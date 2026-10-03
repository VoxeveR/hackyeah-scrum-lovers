"""Decision core. Three surfaces share one evaluation path:

  * LLM proxy (/v1/chat/completions): sees the whole conversation; checks every tool call the model
    asks for before the agent can run it, and masks identifiers before they reach an external model.
  * Hooks (/v1/hooks/claude-code, /v1/hooks/codex): the agent asks before running each tool
    (PreToolUse) and reports results afterwards (PostToolUse) so the session can be labelled.
  * SDK (/v1/decide): the same check for in-house apps that call tools themselves.

Per request:
  1. identify  — virtual key -> identity; model (proxy only) must be on the allowlist
  2. label     — tool results set session labels: untrusted (web, network shell) and data class (PII...)
  3. to_model  — proxy only: mask identifiers the target model may not see
  4. upstream  — proxy only: forward with the gateway's own key
  5. tool_call — evaluate every action; a blocked action never reaches the agent's executor
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
from typing import Any

from .actions import compute_facts, output_is_untrusted
from .audit import AuditLog
from .detectors import (Redactor, find_identifiers, injection_hits, json_strings, mask_residue, redact_json,
                        residue_hints, withhold_json)
from .policy import ACTION_SEVERITY, Control, LoadedPolicy, PolicyStore
from .systemone import SystemOneClient
from .trace import Tracer
from .verify import residue_questions, rule_questions, state_text, stub_residual

RISKY_EFFECTS = {"external_send", "financial", "delete", "exec", "write"}


class SessionStore:
    """Labels for agents that report through hooks or the SDK, where the gateway does not see history."""

    def __init__(self) -> None:
        self._data: dict[tuple[str, str], dict[str, Any]] = {}

    def get(self, agent_id: str, session_id: str | None, default_rank: int) -> dict[str, Any]:
        # No session id -> one session per agent, which is the more restrictive choice.
        key = (agent_id, session_id or "_agent")
        return self._data.setdefault(key, {"integrity": "trusted", "class_rank": default_rank, "user_request": ""})


class Gateway:
    def __init__(self, store: PolicyStore, audit: AuditLog, tracer: Tracer, upstreams: dict[str, Any],
                 systemone: SystemOneClient, protected: list[str] | None = None):
        self.store = store
        self.audit = audit
        self.tracer = tracer
        self.upstreams = upstreams
        self.systemone = systemone
        self.protected = protected or []
        self.sessions = SessionStore()
        self._seen_results: dict[str, list[dict[str, Any]]] = {}  # content hash -> signals already computed
        self._verify_cache: dict[str, tuple[Any, str, list[dict[str, Any]]]] = {}
        self._events_shown = 0
        self._n = 0

    # ================================================================== surface 1: LLM proxy
    async def chat(self, api_key: str | None, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        pol = self._policy()
        t_start = time.perf_counter()
        identity = pol.doc.identities.get(api_key or "")
        if identity is None:
            self.tracer.header(f"żądanie #{self._n} · nieznany klucz")
            self.tracer.verdict("block", "401: klucz nie należy do żadnego agenta")
            self._audit(pol, None, "proxy", "block", [{"control": "IDENTITY", "reason": "unknown key"}], {})
            return 401, _err("SpireGate: nieznany klucz agenta", "invalid_api_key")

        model = pol.model(str(body.get("model")))
        self.tracer.header(f"żądanie #{self._n} · {identity.agent_id} ({identity.desk}) → {body.get('model')} · "
                           f"polityka rev {pol.rev} ({pol.sha}), profil {pol.profile_name}")
        if model is None:
            self.tracer.verdict("block", "model spoza listy dozwolonych w polityce")
            self._audit(pol, identity, "proxy", "block", [{"control": "MODEL-ALLOWLIST", "reason": "model not allowed"}], {},
                        extra={"model": body.get("model")})
            return 403, _err(f"SpireGate: model {body.get('model')!r} nie jest dozwolony", "model_not_allowed")
        if body.get("stream"):
            return 400, _err("SpireGate MVP: streaming jeszcze nieobsługiwany, ustaw stream=false", "unsupported")

        messages: list[dict[str, Any]] = body.get("messages", [])
        signals: list[dict[str, Any]] = []

        # 2. label from history (stateless: the agent resends the full history every turn)
        session = {"integrity": "trusted", "class_rank": pol.class_rank("internal")}
        calls_by_id: dict[str, tuple[str, dict[str, Any]]] = {}
        s1_ms = 0.0
        for m in messages:
            for tc in m.get("tool_calls") or []:
                calls_by_id[tc["id"]] = (tc["function"]["name"], _loads(tc["function"].get("arguments")))
            if m.get("role") == "user" and find_identifiers(_text(m)):
                session["class_rank"] = max(session["class_rank"], pol.class_rank("client_pii"))
            if m.get("role") == "tool":
                name, args = calls_by_id.get(m.get("tool_call_id"), ("?", {}))
                s1_ms += await self._label_result(pol, session, name, args, _text(m), signals)
        self.tracer.info(_session_line(pol, session))

        # 3. masking for the target model
        upstream_body, redacted = await self._apply_to_model(pol, model, session, body, signals)

        # 4. upstream
        t0_ms = round((time.perf_counter() - t_start) * 1000 - s1_ms, 1)
        upstream = self.upstreams[model.upstream]
        status, resp, up_ms = await upstream.complete(upstream_body)
        usage = resp.get("usage", {}) if isinstance(resp, dict) else {}
        self.tracer.info(f"→ {upstream.name}: HTTP {status}, {up_ms} ms, {usage.get('total_tokens', '?')} tokenów")
        if status != 200:
            self._audit(pol, identity, "proxy", "upstream_error", signals, {"t0_ms": t0_ms, "upstream_ms": up_ms},
                        extra={"model": body.get("model")})
            return status, resp

        # 5. tool calls the model asks for
        user_goal = next((_text(m) for m in messages if m.get("role") == "user"), "")
        message = resp["choices"][0]["message"]
        calls, worst, s1b_ms = [], "allow", 0.0
        for tc in message.get("tool_calls") or []:
            decision, sigs, record, ms = await self._evaluate_call(
                pol, identity, session, tc["function"]["name"], _loads(tc["function"].get("arguments")), user_goal, None)
            calls.append(record)
            signals.extend(sigs)
            s1b_ms += ms
            if ACTION_SEVERITY[decision] > ACTION_SEVERITY[worst]:
                worst = decision

        if not calls:
            self.tracer.verdict("allow", "model odpowiedział tekstem; przekazuję agentowi")
        elif worst in ("block", "escalate"):
            reasons = "; ".join(f"{c['tool']}: {', '.join(c['controls'])}" for c in calls if c["decision"] in ("block", "escalate"))
            word = "Zablokowane" if worst == "block" else "Wymaga zatwierdzenia przez człowieka"
            resp["choices"][0]["message"] = {"role": "assistant", "content": f"[SpireGate: {word}] {reasons}. Akcja nie została wykonana."}
            resp["choices"][0]["finish_reason"] = "stop"
            self.tracer.verdict(worst, "agent dostaje tekst zamiast tool_call, więc nie ma czego wykonać")
        else:
            self.tracer.verdict("allow", "tool_call przekazany agentowi do wykonania")

        verdict = "redact" if worst == "allow" and redacted else worst
        latency = {"t0_ms": t0_ms, "systemone_ms": round(s1_ms + s1b_ms, 1), "upstream_ms": up_ms}
        self._audit(pol, identity, "proxy", verdict, signals, latency,
                    extra={"model": body.get("model"), "session": _session_view(pol, session),
                           "redacted": redacted, "tool_calls": calls, "usage": usage})
        return 200, resp

    # ================================================================== surface 2+3: SDK and hooks
    async def decide(self, api_key: str | None, req: dict[str, Any], surface: str = "sdk") -> dict[str, Any]:
        """phase: "prompt" (user request), "pre" (before a tool runs) or "post" (tool result)."""
        pol = self._policy()
        t_start = time.perf_counter()
        phase = req.get("phase", "pre")
        tool = str(req.get("tool") or "")
        identity = pol.doc.identities.get(api_key or "")
        if identity is None:
            self.tracer.header(f"{surface} {phase} · nieznany klucz")
            self.tracer.verdict("block", "klucz nie należy do żadnego agenta")
            self._audit(pol, None, surface, "block", [{"control": "IDENTITY", "reason": "unknown key"}], {})
            return {"decision": "block", "controls": ["IDENTITY"], "reasons": ["SpireGate: nieznany klucz agenta"]}

        session = self.sessions.get(identity.agent_id, req.get("session_id"), pol.class_rank("internal"))
        args = req.get("args") if isinstance(req.get("args"), dict) else {}
        signals: list[dict[str, Any]] = []
        self.tracer.header(f"{surface} · {phase} · {identity.agent_id}" + (f" · {tool}" if tool else "")
                           + f" · polityka rev {pol.rev} ({pol.sha})")

        if phase == "prompt":
            text = str(req.get("user_request") or "")
            session["user_request"] = Redactor().redact(text)[0][:2000]
            if find_identifiers(text):
                session["class_rank"] = max(session["class_rank"], pol.class_rank("client_pii"))
            self.tracer.info("zapamiętuję polecenie użytkownika (zamaskowane) do oceny zgodności akcji z celem")
            self.tracer.info(_session_line(pol, session))
            return {"decision": "allow", "controls": [], "reasons": []}

        if phase == "post":
            raw = req.get("result")
            text = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False)
            await self._label_result(pol, session, tool, args, text, signals)
            redacted_obj, used, withheld = await self._redact_result(pol, session, tool, raw, signals)
            self.tracer.info(_session_line(pol, session))
            decision = "withhold" if withheld else "redact" if used else "label"
            self._audit(pol, identity, surface, decision, signals, {}, extra={"tool": tool, "phase": "post",
                        "session": _session_view(pol, session), "redacted": used})
            return {"decision": "withhold" if withheld else "redact" if used else "allow",
                    "controls": [s["control"] for s in signals if s["enforced"]], "reasons": [],
                    "session": _session_view(pol, session), "result_redacted": redacted_obj if used else None}

        decision, sigs, record, s1_ms = await self._evaluate_call(
            pol, identity, session, tool, args, session.get("user_request", ""), req.get("cwd"))
        enforced = [s for s in sigs if s["enforced"] and s["action"] in ("block", "escalate")]
        if decision == "allow":
            self.tracer.verdict("allow", "akcja zgodna z polityką; dalej decyduje agent (jego własne zgody)")
        else:
            self.tracer.verdict(decision, "akcja nie zostanie wykonana" if decision == "block" else "wymaga zatwierdzenia")
        latency = {"t0_ms": round((time.perf_counter() - t_start) * 1000 - s1_ms, 1), "systemone_ms": s1_ms}
        self._audit(pol, identity, surface, decision, sigs, latency,
                    extra={"tool": tool, "phase": "pre", "session": _session_view(pol, session), "tool_calls": [record]})
        return {"decision": decision, "controls": [s["control"] for s in enforced],
                "reasons": [f"{s['control']}: {s['reason']}" for s in enforced],
                "policy": {"rev": pol.rev, "sha": pol.sha}}

    async def hook(self, api_key: str | None, fmt: str, event: dict[str, Any]) -> dict[str, Any]:
        """Translates a Claude Code / Codex hook event into decide() and back into what that agent expects.

        Never answers "allow": an allowed action falls through to the agent's own permission prompts.
        """
        name = event.get("hook_event_name", "")
        req: dict[str, Any] = {"session_id": event.get("session_id"), "cwd": event.get("cwd")}
        if name == "UserPromptSubmit":
            req.update(phase="prompt", user_request=event.get("prompt", ""))
        elif name == "PostToolUse":
            req.update(phase="post", tool=event.get("tool_name"), args=event.get("tool_input") or {},
                       result=event.get("tool_response", event.get("tool_output", "")))
        elif name == "PreToolUse":
            req.update(phase="pre", tool=event.get("tool_name"), args=event.get("tool_input") or {})
        else:
            return {"stdout": "", "stderr": "", "exit": 0}

        out = await self.decide(api_key, req, surface=f"hook:{fmt}")
        if name == "PostToolUse" and out.get("result_redacted") is not None:
            if fmt == "claude-code":  # replaces the result before the model sees it; same shape as the original
                payload = {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                  "updatedToolOutput": out["result_redacted"]}}
                self.tracer.info("Claude Code dostanie " + ("WSTRZYMANY" if out["decision"] == "withhold" else "zamaskowany")
                                 + " wynik (updatedToolOutput)")
                return {"stdout": json.dumps(payload, ensure_ascii=False), "stderr": "", "exit": 0}
            self.tracer.info("UWAGA: Codex nie pozwala podmienić wyniku narzędzia; maskowanie tylko w logu")
        if name != "PreToolUse" or out["decision"] == "allow":
            return {"stdout": "", "stderr": "", "exit": 0}
        reason = "SpireGate: " + ("; ".join(out["reasons"]) or "zablokowane przez politykę")
        if fmt == "codex":  # exit 2 + stderr is the most robust block signal across Codex versions
            return {"stdout": "", "stderr": reason + "\n", "exit": 2}
        decision = "deny" if out["decision"] == "block" else "ask"
        payload = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                          "permissionDecisionReason": reason}}
        return {"stdout": json.dumps(payload, ensure_ascii=False), "stderr": "", "exit": 0}

    # ================================================================== shared evaluation
    async def _label_result(self, pol: LoadedPolicy, session: dict[str, Any], name: str,
                            args: dict[str, Any], text: str, signals: list[dict[str, Any]]) -> float:
        spec = pol.tool(name)
        untrusted = output_is_untrusted(name, spec.model_dump(), args)
        if untrusted:
            session["integrity"] = "untrusted"
        session["class_rank"] = max(session["class_rank"], pol.class_rank(spec.output_class))
        ids = find_identifiers(text)
        if ids:
            session["class_rank"] = max(session["class_rank"], pol.class_rank("client_pii"))

        key = hashlib.sha256(f"{name}\x00{text}".encode()).hexdigest()
        if key in self._seen_results:  # history is resent every turn; judge each result once
            signals.extend(self._seen_results[key])
            return 0.0
        self.tracer.info(f"nowy wynik narzędzia {name}: {'NIEZAUFANY' if untrusted else 'zaufany'}, klasa {spec.output_class}"
                         + (f", identyfikatory: {', '.join(sorted({i.kind for i in ids}))}" if ids else ""))
        result_signals: list[dict[str, Any]] = []
        s1_ms = await self._tool_result_controls(pol, name, text, result_signals) if untrusted else 0.0
        self._seen_results[key] = result_signals
        signals.extend(result_signals)
        return s1_ms

    async def _tool_result_controls(self, pol: LoadedPolicy, name: str, text: str, out: list) -> float:
        s1_ms = 0.0
        for c in pol.controls_for("tool_result"):
            mode = pol.mode_of(c)
            if mode == "off":
                continue
            if c.detector == "injection_lexicon":
                hits = injection_hits(text)
                if hits:
                    out.append(self._signal(c, mode, f"{name}: podejrzane wzorce {hits}; sesja i tak już niezaufana"))
            elif c.detector == "systemone_directed_at_agent":
                redacted, _ = Redactor().redact(text)
                res = await self.systemone.ask(pol.doc.systemone, "directed_at_agent", redacted[:4000])
                s1_ms += res.latency_ms
                out.append(self._s1_signal(c, mode, res, f"{name}: czy tekst wydaje polecenia agentowi?"))
        return s1_ms

    async def _evaluate_call(self, pol: LoadedPolicy, identity, session: dict[str, Any], name: str,
                             args: dict[str, Any], user_goal: str, cwd: str | None):
        spec = pol.tool(name)
        effective, facts = compute_facts(name, spec.model_dump(), args, allowed_tools=identity.allowed_tools,
                                         internal_domains=pol.doc.org.get("internal_domains", []),
                                         protected_roots=self.protected, cwd=cwd)
        shown = {k: (v if len(str(v)) < 60 else str(v)[:57] + "...") for k, v in args.items()}
        dest = f", cel: {', '.join(facts['destinations'])}" if facts["destinations"] else ""
        self.tracer.info(f"akcja: {name}({shown})  [effect={effective['effect']}{dest}]")
        data = {"identity": identity.model_dump(), "session": _session_view(pol, session),
                "tool": {"name": name, **effective}, "args": args, "facts": facts}

        sigs: list[dict[str, Any]] = []
        s1_ms = 0.0
        for c in pol.controls_for("tool_call"):
            mode = pol.mode_of(c)
            if mode == "off":
                continue
            if c.when:
                matched, err = pol.eval_when(c, data)
                if err:
                    action = pol.profile.on_eval_error
                    sigs.append(self._signal(c, mode, f"błąd warunku CEL ({err}) → fail-closed: {action}", action=action))
                elif matched:
                    sigs.append(self._signal(c, mode, c.title))
                elif c.verify is not None and effective["effect"] in RISKY_EFFECTS:
                    # the rule did not fire; ask System One whether the action still breaks it (escalate only)
                    vmode = _verify_mode(pol, c)
                    state = {"rule": c.title, "user_request": Redactor().redact(user_goal)[0], "tool": name,
                             "args": _loads(Redactor().redact(json.dumps(args, ensure_ascii=False))[0])}
                    res = await self.systemone.ask_questions(pol.doc.systemone, rule_questions(c.verify), state,
                                                             "violates", stub=lambda st: 0.05)
                    s1_ms += res.latency_ms
                    if res.probability is not None and res.probability >= c.verify.threshold:
                        sigs.append(self._vsignal(f"{c.id}/verify", "escalate", vmode,
                                                  f"reguła nie zadziałała, ale System One [{res.backend}] p={res.probability:.2f} "
                                                  f"≥ {c.verify.threshold}: możliwe naruszenie „{c.title}”"))
                    else:
                        self.tracer.info(f"{c.id}/verify: System One [{res.backend}] "
                                         + (f"p={res.probability:.2f}" if res.probability is not None else "bez wyniku")
                                         + ": brak naruszenia")
            elif c.detector == "systemone_matches_goal" and effective["effect"] in RISKY_EFFECTS:
                if not user_goal:
                    self.tracer.info(f"System One {c.id}: brak polecenia użytkownika w sesji, pomijam")
                    continue
                state = {"user_request": Redactor().redact(user_goal)[0], "tool": name,
                         "args": _loads(Redactor().redact(json.dumps(args, ensure_ascii=False))[0])}
                res = await self.systemone.ask(pol.doc.systemone, "off_goal", state)
                s1_ms += res.latency_ms
                sigs.append(self._s1_signal(c, mode, res, f"{name}: czy akcja wykracza poza polecenie?"))
        decision = _combine(sigs)
        record = {"tool": name, "args_sha256": hashlib.sha256(json.dumps(args, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
                  "effect": effective["effect"], "destinations": facts["destinations"], "decision": decision,
                  "controls": [s["control"] for s in sigs if s["enforced"] and s["action"] in ("block", "escalate")]}
        return decision, sigs, record, s1_ms

    async def _apply_to_model(self, pol: LoadedPolicy, model, session, body, signals):
        """Two reasons to mask before the model: the session's data class exceeds what the model may see
        (all identifier kinds), or a per-kind rule such as "the agent never sees PESEL" (any model)."""
        upstream_body = copy.deepcopy(body)
        plans: list[tuple[Control, set[str] | None, str]] = []
        class_ctrl = next((c for c in pol.controls_for("to_model") if c.detector == "fin_identifiers"), None)
        if class_ctrl and session["class_rank"] > pol.class_rank(model.max_class):
            plans.append((class_ctrl, None, f"bo {model.id} ({model.location}) może widzieć najwyżej klasę "
                                            f"{model.max_class}, a sesja ma {_class(pol, session)}"))
        for c in pol.controls_for("tool_result"):
            if c.detector == "identifiers" and c.action == "redact":
                plans.append((c, set(c.kinds or []), c.title))
        if not plans:
            self.tracer.info(f"klasa sesji {_class(pol, session)} ≤ max_class modelu {model.max_class}: bez maskowania")
            return upstream_body, []

        redactor = Redactor()  # shared, so placeholders stay numbered consistently across rules
        applied: list[str] = []
        for control, kinds, why in plans:
            mode = pol.mode_of(control)
            if mode == "off":
                continue
            target = upstream_body if mode == "enforce" else copy.deepcopy(upstream_body)
            used: list[str] = []
            for m in target.get("messages", []):
                if isinstance(m.get("content"), str):
                    m["content"], u = redactor.redact(m["content"], kinds)
                    used += u
                for tc in m.get("tool_calls") or []:
                    tc["function"]["arguments"], u = redactor.redact(tc["function"]["arguments"], kinds)
                    used += u
            unique = sorted(set(used), key=used.index)
            if unique:
                signals.append(self._signal(control, mode, f"{', '.join(unique)} zamaskowane przed modelem: {why}"))
                if mode == "enforce":
                    applied += unique

        # second line: System One confirms nothing of that kind is left in each tool result
        names_by_id = {tc["id"]: tc["function"]["name"]
                       for m in upstream_body.get("messages", []) for tc in (m.get("tool_calls") or [])}
        for c in pol.controls_for("tool_result"):
            if c.detector != "identifiers" or c.verify is None:
                continue
            kinds = set(c.kinds or [])
            for m in upstream_body.get("messages", []):
                if m.get("role") != "tool" or not isinstance(m.get("content"), str):
                    continue
                spec = pol.tool(names_by_id.get(m.get("tool_call_id"), "?"))
                sensitive = (any(f"[{k}#" in m["content"] for k in kinds)
                             or pol.class_rank(spec.output_class) >= pol.class_rank("client_pii"))
                key = hashlib.sha256(f"{c.id}\x00{pol.sha}\x00{m['content']}".encode()).hexdigest()
                if key not in self._verify_cache:  # history is resent every turn: verify each result once
                    local: list[dict[str, Any]] = []
                    new, outcome = await self._verify_residue(pol, c, m["content"], kinds, sensitive, local)
                    self._verify_cache[key] = (new, outcome, local)
                new, outcome, cached = self._verify_cache[key]
                signals.extend(cached)
                if outcome in ("masked", "withheld") and new != m["content"]:
                    m["content"] = new
                    applied.append(outcome)
        return upstream_body, applied

    async def _redact_result(self, pol: LoadedPolicy, session: dict[str, Any], tool: str, raw: Any,
                             signals: list[dict[str, Any]]) -> tuple[Any, list[str], bool]:
        """Hooks and SDK: mask identifier kinds inside a tool result before it reaches the agent,
        then let System One confirm nothing is left. Returns (result, what changed, withheld?)."""
        redactor = session.setdefault("_redactor", Redactor())  # per session: [PESEL#1] stays the same person
        obj, applied, withheld = raw, [], False
        spec = pol.tool(tool)
        for c in pol.controls_for("tool_result"):
            if c.detector != "identifiers" or c.action != "redact":
                continue
            mode = pol.mode_of(c)
            if mode == "off":
                continue
            kinds = set(c.kinds or [])
            candidate, used = redact_json(obj, redactor, kinds)
            unique = sorted(set(used), key=used.index)
            if unique:
                signals.append(self._signal(c, mode, f"{tool}: {', '.join(unique)} zamaskowane, zanim wynik trafi do agenta"))
                if mode == "enforce":
                    obj, applied = candidate, applied + unique
            if c.verify is not None:
                sensitive = bool(unique) or pol.class_rank(spec.output_class) >= pol.class_rank("client_pii")
                obj, outcome = await self._verify_residue(pol, c, obj, kinds, sensitive, signals)
                enforcing = _verify_mode(pol, c) == "enforce"
                if outcome in ("masked", "withheld") and enforcing:
                    applied.append(outcome)
                withheld = withheld or (outcome == "withheld" and enforcing)
        return obj, applied, withheld

    async def _verify_residue(self, pol: LoadedPolicy, c: Control, obj: Any, kinds: set[str], sensitive: bool,
                              signals: list[dict[str, Any]]) -> tuple[Any, str]:
        """precise masking (done) → residue hints? → System One → mask hinted spans → System One → withhold.

        System One alone never withholds: a withhold needs a second "yes" after masking, and a
        deterministic filter that found traces or a source known to carry client data."""
        v = c.verify
        mode = _verify_mode(pol, c)
        if mode == "off":
            return obj, "skip"
        label = sorted(kinds)[0]
        cid = f"{c.id}/verify"
        hinted = any(residue_hints(t, kinds) for t in json_strings(obj))
        if not hinted and not sensitive:
            return obj, "skip"
        why = "filtr znalazł ślady" if hinted else "wynik ze źródła z danymi klientów"

        async def ask(o):
            return await self.systemone.ask_questions(pol.doc.systemone, residue_questions(v), state_text(o), "residual",
                                                      stub=lambda st: stub_residual(st, kinds))

        res = await ask(obj)
        if res.probability is None:
            detail = res.error or res.note or "brak odpowiedzi"
            if not hinted:
                self.tracer.info(f"{cid}: System One bez wyniku ({detail}); brak śladów, wynik bez zmian")
                return obj, "error"
            masked, n = mask_residue(obj, kinds, label)
            signals.append(self._vsignal(cid, "redact", mode, f"System One bez wyniku ({detail}); "
                                                              f"maskuję deterministycznie {n} podejrzanych fragmentów"))
            return (masked if mode == "enforce" else obj), "masked"

        form = res.extra.get("form")
        line = (f"System One [{res.backend}] p={res.probability:.2f}" + (f", forma: {form}" if form else "")
                + f", {res.latency_ms} ms ({why})")
        if res.probability < v.threshold:
            self.tracer.info(f"{cid}: {line} < próg {v.threshold} → potwierdzone: brak {label}")
            signals.append({"control": cid, "action": "allow", "mode": mode, "enforced": False, "authority": "advisory",
                            "reason": line, "probability": res.probability, "backend": res.backend})
            return obj, "pass"

        masked, n = mask_residue(obj, kinds, label)
        if n:
            signals.append(self._vsignal(cid, "redact", mode, f"{line} ≥ próg {v.threshold} → maskuję {n} podejrzanych fragmentów"))
            res2 = await ask(masked)
            if res2.probability is not None and res2.probability < v.threshold:
                self.tracer.info(f"{cid}: po maskowaniu p={res2.probability:.2f} < próg → wynik idzie dalej")
                return (masked if mode == "enforce" else obj), "masked"
            second = "System One bez wyniku" if res2.probability is None else f"po maskowaniu nadal p={res2.probability:.2f}"
        else:
            second = "filtr nie wskazał, co zamaskować"
        what = "wstrzymany" if v.on_fail == "withhold" else "wstrzymany do przeglądu"
        notice = f"[SpireGate: wynik {what} ({c.id}): możliwy {label} w nierozpoznanej formie, zdarzenie #{self._n}]"
        signals.append(self._vsignal(cid, "withhold", mode, f"{line}; {second} → wynik {what}"))
        return (withhold_json(obj, notice) if mode == "enforce" else obj), "withheld"

    def _vsignal(self, cid: str, action: str, mode: str, reason: str) -> dict[str, Any]:
        enforced = mode == "enforce"
        self.tracer.decision(action, cid, reason, enforced=enforced)
        return {"control": cid, "action": action, "mode": mode, "enforced": enforced,
                "authority": "corroborated", "reason": reason}

    # ================================================================== helpers
    def _policy(self) -> LoadedPolicy:
        pol = self.store.get()
        for ev in self.store.events[self._events_shown:]:
            self.tracer.policy(ev)
        self._events_shown = len(self.store.events)
        self._n += 1
        return pol

    def _signal(self, c: Control, mode: str, reason: str, *, action: str | None = None) -> dict[str, Any]:
        action = action or c.action
        if c.authority == "corroborating" and action == "block":
            action = "taint"  # heuristics never block alone
        enforced = mode == "enforce"
        self.tracer.decision(action, c.id, reason, enforced=enforced)
        return {"control": c.id, "action": action, "mode": mode, "enforced": enforced,
                "authority": c.authority, "reason": reason}

    def _s1_signal(self, c: Control, mode: str, res, question: str) -> dict[str, Any]:
        if res.probability is None:
            detail = res.error or res.note or "brak odpowiedzi"
            self.tracer.info(f"System One [{res.backend}] {question} → brak wyniku ({detail}); bez wpływu (advisory)")
            return {"control": c.id, "action": "allow", "mode": mode, "enforced": False,
                    "authority": "advisory", "reason": detail, "backend": res.backend}
        note = f" ({res.note})" if res.note else ""
        text = f"System One [{res.backend}{note}] {question} p={res.probability:.2f}, {res.latency_ms} ms"
        if c.escalate_at is None or res.probability < c.escalate_at:
            self.tracer.info(text + f" < próg {c.escalate_at}: bez sygnału")
            return {"control": c.id, "action": "allow", "mode": mode, "enforced": False, "authority": "advisory",
                    "reason": text, "probability": res.probability, "backend": res.backend}
        sig = self._signal(c, mode, text + f" ≥ próg {c.escalate_at}")
        sig.update(probability=res.probability, backend=res.backend)
        return sig

    def _audit(self, pol, identity, surface, decision, signals, latency, extra=None) -> None:
        self.audit.append({
            "request": self._n, "surface": surface,
            "agent": identity.agent_id if identity else None,
            "desk": identity.desk if identity else None,
            "decision": decision, "signals": signals, "latency": latency,
            "policy": {"rev": pol.rev, "sha": pol.sha, "profile": pol.profile_name},
            **(extra or {}),
        })


_MODE_ORDER = {"off": 0, "monitor": 1, "enforce": 2}


def _verify_mode(pol: LoadedPolicy, c: Control) -> str:
    """verify.mode can only make a rule more lenient, never stricter than the rule's own mode."""
    rule = pol.mode_of(c)
    own = c.verify.mode if c.verify and c.verify.mode else rule
    return min(rule, own, key=_MODE_ORDER.__getitem__)


def _combine(signals: list[dict[str, Any]]) -> str:
    worst = "allow"
    for s in signals:
        if s["enforced"] and s["action"] in ("block", "escalate") and ACTION_SEVERITY[s["action"]] > ACTION_SEVERITY[worst]:
            worst = s["action"]
    return worst


def _class(pol: LoadedPolicy, session: dict[str, Any]) -> str:
    return pol.doc.classification[session["class_rank"]]


def _session_view(pol: LoadedPolicy, session: dict[str, Any]) -> dict[str, Any]:
    return {"integrity": session["integrity"], "class": _class(pol, session), "class_rank": session["class_rank"]}


def _session_line(pol: LoadedPolicy, session: dict[str, Any]) -> str:
    return f"etykiety sesji: integrity={session['integrity']}, class={_class(pol, session)}"


def _loads(arguments: Any) -> dict[str, Any]:
    if isinstance(arguments, dict):
        return arguments
    try:
        value = json.loads(arguments or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _text(m: dict[str, Any]) -> str:
    c = m.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return " ".join(p.get("text", "") for p in c if isinstance(p, dict))
    return ""


def _err(message: str, code: str) -> dict[str, Any]:
    return {"error": {"message": message, "type": code, "code": code}}
