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
from .budget import BudgetLedger, Hold
from .events import SIMULATED, EventBus
from .detectors import (Redactor, find_identifiers, injection_hits, json_strings, mask_residue, redact_json,
                        residue_hints, withhold_json)
from .feed import FeedStore, model_paths, signals_for, stops, withhold_notice
from .policy import ACTION_SEVERITY, Control, LoadedPolicy, PolicyStore
from .systemone import QUESTIONS, SystemOneClient, _stub_answer
from .trace import Tracer
from .verify import residue_questions, state_text, stub_residual

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
                 systemone: SystemOneClient, protected: list[str] | None = None, feed: FeedStore | None = None):
        self.store = store
        self.feed = feed or FeedStore()   # signed signatures of known attacks (external threat-intel system)
        self.feed.sync(store.current.doc.feed)
        self._feed_events_shown = 0
        self.audit = audit
        self.tracer = tracer
        self.upstreams = upstreams
        self.systemone = systemone
        self.protected = protected or []
        self.sessions = SessionStore()
        self.ledger = BudgetLedger()
        self.ledger.replay(audit.tail(20000), store.current.doc.budgets)
        self.systemone.on_usage = self._systemone_cost
        self.bus = EventBus()  # live stream for the dashboard (Silnik page)
        self.systemone.on_event = self.bus.system_one
        self._seen_results: dict[str, list[dict[str, Any]]] = {}  # content hash -> signals already computed
        self._verify_cache: dict[str, tuple[Any, str, list[dict[str, Any]]]] = {}
        self._events_shown = 0
        self._n = 0

    # ================================================================== surface 1: LLM proxy
    async def chat(self, api_key: str | None, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        pol = self._policy()
        t_start = time.perf_counter()
        identity = pol.doc.identities.get(api_key or "")
        self.bus.begin("proxy", identity.agent_id if identity else None, "model",
                       f"{body.get('model')} · {len(body.get('messages') or [])} messages")
        if identity is None:
            self.tracer.header(f"request #{self._n} · unknown key")
            self.tracer.verdict("block", "401: the key belongs to no agent")
            self._audit(pol, None, "proxy", "block", [{"control": "IDENTITY", "reason": "unknown key"}], {})
            return 401, _err("SpireGate: unknown agent key", "invalid_api_key")

        model = pol.model(str(body.get("model")))
        self.tracer.header(f"request #{self._n} · {identity.agent_id} ({identity.desk}) → {body.get('model')} · "
                           f"policy rev {pol.rev} ({pol.sha})")
        if model is None:
            self.tracer.verdict("block", "the model is not on the policy's allow-list")
            self._audit(pol, identity, "proxy", "block", [{"control": "MODEL-ALLOWLIST", "reason": "model not allowed"}], {},
                        extra={"model": body.get("model")})
            return 403, _err(f"SpireGate: model {body.get('model')!r} is not allowed", "model_not_allowed")
        if body.get("stream"):
            return 400, _err("SpireGate MVP: streaming is not supported yet, set stream=false", "unsupported")

        messages: list[dict[str, Any]] = body.get("messages", [])
        # 1a. known attack payloads in the user's messages: refused before anything is reserved or sent
        signals = self._feed_signals(pol, "prompt", [_text(m) for m in messages if m.get("role") == "user"])
        refused = stops(signals)
        if refused:
            word = "Blocked" if _combine(refused) == "block" else "Needs human approval"
            self.tracer.verdict("block", "the prompt never reaches the model")
            self._audit(pol, identity, "proxy", "block", signals, {}, extra={"model": body.get("model"), "phase": "prompt"})
            return 200, _assistant(body, f"[SpireGate: {word}] the prompt contains a known attack pattern: "
                                         + "; ".join(s["reason"] for s in refused))
        first_user = next((_text(m) for m in messages if m.get("role") == "user"), "")
        # The proxy is stateless: a conversation is identified by its opening request. A retrying agent always
        # resends its history, so a request without any assistant turn really is a new conversation.
        conv_id = hashlib.sha256(f"{identity.agent_id}\x00{first_user}".encode()).hexdigest()[:12]
        if not any(m.get("role") in ("assistant", "tool") for m in messages):
            self.ledger.reset_session(identity.agent_id, conv_id)

        # 1b. budgets: reserve the worst case on every matching budget before anything is spent
        demand, max_out = self._estimate(pol, model, body)
        refusal, hold = self._budget_preflight(pol, identity, demand, max_out, signals)
        if refusal:
            self._audit(pol, identity, "proxy", "block", signals, {}, extra={"model": body.get("model"), "budget_demand": demand})
            return 403, _err(f"SpireGate: budget exceeded. {refusal}", "budget_exceeded")

        # 2. label from history (stateless: the agent resends the full history every turn)
        session = {"integrity": "trusted", "class_rank": pol.class_rank("internal")}
        calls_by_id: dict[str, tuple[str, dict[str, Any]]] = {}
        hidden: dict[str, str] = {}   # tool_call_id -> what the model reads instead of the result
        s1_ms = 0.0
        for m in messages:
            for tc in m.get("tool_calls") or []:
                calls_by_id[tc["id"]] = (tc["function"]["name"], _loads(tc["function"].get("arguments")))
            if m.get("role") == "user" and find_identifiers(_text(m)):
                session["class_rank"] = max(session["class_rank"], pol.class_rank("client_pii"))
            if m.get("role") == "tool":
                name, args = calls_by_id.get(m.get("tool_call_id"), ("?", {}))
                before = len(signals)
                s1_ms += await self._label_result(pol, session, name, args, _text(m), signals)
                if stops(signals[before:]):     # a known attack payload: the model never reads it
                    hidden[m.get("tool_call_id")] = withhold_notice(stops(signals[before:]))
                elif any(s.get("authority") == "semantic" and s["action"] == "block" for s in signals[before:]):
                    hidden[m.get("tool_call_id")] = ("[SpireGate: result withheld (S1-JEV-001): System One judged it "
                                                     "to contain instructions aimed at the agent]")   # System One blocked it
        self.tracer.info(_session_line(pol, session))

        # 3. masking for the target model
        upstream_body, redacted = await self._apply_to_model(pol, model, session, body, signals)
        for m in upstream_body.get("messages", []):
            if m.get("role") == "tool" and m.get("tool_call_id") in hidden:
                m["content"] = hidden[m["tool_call_id"]]
                redacted.append("withheld")
        if self._drop_poisoned_tools(pol, upstream_body, signals):
            redacted.append("withheld")

        # 4. upstream
        t0_ms = round((time.perf_counter() - t_start) * 1000 - s1_ms, 1)
        upstream = self.upstreams[model.upstream]
        status, resp, up_ms = await upstream.complete(upstream_body)
        usage = resp.get("usage", {}) if isinstance(resp, dict) else {}
        cost = self._actual_cost(pol, model, usage if status == 200 else {}, up_ms)
        self.ledger.reconcile(hold, {"usd": cost["usd"], "tokens": cost["tokens"]})
        self.tracer.info(f"→ {upstream.name}: HTTP {status}, {up_ms} ms, {usage.get('total_tokens', '?')} tokens, "
                         f"cost {cost['usd']:.6f} USD")
        if status != 200:
            self._audit(pol, identity, "proxy", "upstream_error", signals, {"t0_ms": t0_ms, "upstream_ms": up_ms},
                        extra={"model": body.get("model"), "cost": cost})
            return status, resp

        # 5. tool calls the model asks for
        user_goal = first_user
        message = resp["choices"][0]["message"]
        calls, worst, s1b_ms = [], "allow", 0.0
        for tc in message.get("tool_calls") or []:
            decision, sigs, record, ms = await self._evaluate_call(
                pol, identity, session, tc["function"]["name"], _loads(tc["function"].get("arguments")), user_goal, None,
                session_id=conv_id)
            calls.append(record)
            signals.extend(sigs)
            s1b_ms += ms
            if ACTION_SEVERITY[decision] > ACTION_SEVERITY[worst]:
                worst = decision

        if not calls:
            self.tracer.verdict("allow", "the model answered with text; passed to the agent")
        elif worst in ("block", "escalate"):
            reasons = "; ".join(f"{c['tool']}: {', '.join(c['controls'])}" for c in calls if c["decision"] in ("block", "escalate"))
            word = "Blocked" if worst == "block" else "Needs human approval"
            resp["choices"][0]["message"] = {"role": "assistant", "content": f"[SpireGate: {word}] {reasons}. The action was not executed."}
            resp["choices"][0]["finish_reason"] = "stop"
            self.tracer.verdict(worst, "the agent gets text instead of a tool_call, so there is nothing to execute")
        else:
            self.tracer.verdict("allow", "tool_call passed to the agent to execute")

        verdict = worst if worst != "allow" else "withhold" if "withheld" in redacted else "redact" if redacted else "allow"
        latency = {"t0_ms": t0_ms, "systemone_ms": round(s1_ms + s1b_ms, 1), "upstream_ms": up_ms}
        self._audit(pol, identity, "proxy", verdict, signals, latency,
                    extra={"model": body.get("model"), "session": _session_view(pol, session),
                           "redacted": redacted, "tool_calls": calls, "usage": usage, "cost": cost})
        return 200, resp

    # ================================================================== budgets
    def _estimate(self, pol: LoadedPolicy, model, body: dict[str, Any]) -> tuple[dict[str, float], int]:
        """Worst case for one model call: estimated input (chars / 4) plus the maximum answer length."""
        est_in = len(json.dumps(body.get("messages", []), ensure_ascii=False)) // 4 + len(json.dumps(body.get("tools", []))) // 4
        max_out = int(body.get("max_completion_tokens") or body.get("max_tokens") or pol.doc.budgets.default_max_tokens)
        price = pol.doc.prices.get(model.id)
        usd = (est_in * price.usd_per_mtok_in + max_out * price.usd_per_mtok_out) / 1e6 if price else 0.0
        return {"usd": round(usd, 8), "tokens": est_in + max_out, "requests": 1}, max_out

    def _budget_preflight(self, pol: LoadedPolicy, identity, demand, max_out: int, signals
                          ) -> tuple[str | None, Hold | None]:
        """Returns (refusal reason, hold to reconcile after the call)."""
        budgets = pol.doc.budgets
        if not budgets.rules:
            return None, None
        problems = [(r.id, f"{r.id}: at most {r.max_tokens_per_request} answer tokens per request, this request asks for {max_out}")
                    for r, _ in BudgetLedger.matching(budgets, identity)
                    if r.max_tokens_per_request and max_out > r.max_tokens_per_request]
        hold = None
        if not problems:
            violations, hold = self.ledger.reserve(budgets, identity, demand)
            problems = [(v.budget_id, v.message()) for v in violations]
        if problems:
            signals.extend(self._bsignal(cid, reason) for cid, reason in problems)
            self.tracer.verdict("block", "403, no retry: the agent gets the reason and when the limit renews")
            return "; ".join(r for _, r in problems), None
        self.tracer.info(f"budget: reserved {demand['usd']:.6f} USD, {demand['tokens']} tokens")
        return None, hold

    def _actual_cost(self, pol: LoadedPolicy, model, usage: dict[str, Any], up_ms: float) -> dict[str, float]:
        tin, tout = int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)
        price = pol.doc.prices.get(model.id)
        gpu_s = round(up_ms / 1000, 3) if model.location == "on_prem" else 0.0
        usd = 0.0
        if price:
            usd = (tin * price.usd_per_mtok_in + tout * price.usd_per_mtok_out) / 1e6 + gpu_s * price.usd_per_gpu_second
        return {"usd": round(usd, 8), "tokens": tin + tout, "gpu_s": gpu_s}

    def _bsignal(self, cid: str, reason: str) -> dict[str, Any]:
        self.tracer.decision("block", cid, reason)
        return {"control": cid, "action": "block", "authority": "authoritative", "reason": reason}

    def _systemone_cost(self, backend: str, input_tokens: int) -> None:
        pol = self.store.current
        price = pol.doc.prices.get(pol.doc.systemone.model)
        per_mtok = price.usd_per_mtok_in if price and backend == "jev" else 0.0
        self.ledger.add_control_overhead(input_tokens, per_mtok)
        self.bus.add_s1_cost(input_tokens, input_tokens / 1e6 * per_mtok)

    # ================================================================== surface 2+3: SDK and hooks
    async def decide(self, api_key: str | None, req: dict[str, Any], surface: str = "sdk") -> dict[str, Any]:
        """phase: "prompt" (user request), "pre" (before a tool runs) or "post" (tool result)."""
        pol = self._policy()
        t_start = time.perf_counter()
        phase = req.get("phase", "pre")
        tool = str(req.get("tool") or "")
        identity = pol.doc.identities.get(api_key or "")
        args = req.get("args") if isinstance(req.get("args"), dict) else {}
        kind, label = {"prompt": ("prompt", "user prompt"), "post": ("result", f"{tool} → result")
                       }.get(phase, ("action", _action_label(tool, args)))
        if phase != "prompt" or identity is None:  # a user's prompt is context for later checks, not a decision
            self.bus.begin(surface, identity.agent_id if identity else None, kind, label)
        if identity is None:
            self.tracer.header(f"{surface} {phase} · unknown key")
            self.tracer.verdict("block", "the key belongs to no agent")
            self._audit(pol, None, surface, "block", [{"control": "IDENTITY", "reason": "unknown key"}], {})
            return {"decision": "block", "controls": ["IDENTITY"], "reasons": ["SpireGate: unknown agent key"]}

        session = self.sessions.get(identity.agent_id, req.get("session_id"), pol.class_rank("internal"))
        signals: list[dict[str, Any]] = []
        self.tracer.header(f"{surface} · {phase} · {identity.agent_id}" + (f" · {tool}" if tool else "")
                           + f" · policy rev {pol.rev} ({pol.sha})")

        if phase == "prompt":
            text = str(req.get("user_request") or "")
            refused = stops(signals := self._feed_signals(pol, "prompt", [text]))
            if refused:   # a known attack payload: the prompt never reaches the agent
                self.bus.begin(surface, identity.agent_id, kind, label)
                self.tracer.verdict("block", "the prompt never reaches the agent")
                self._audit(pol, identity, surface, "block", signals, {}, extra={"phase": "prompt"})
                return {"decision": "block", "controls": list(dict.fromkeys(s["control"] for s in refused)),
                        "reasons": [f"{s['control']}: {s['reason']}" for s in refused]}
            session["user_request"] = Redactor().redact(text)[0][:2000]
            if find_identifiers(text):
                session["class_rank"] = max(session["class_rank"], pol.class_rank("client_pii"))
            self.tracer.info("user prompt stored (masked) to judge whether later actions match it")
            self.tracer.info(_session_line(pol, session))
            return {"decision": "allow", "controls": [], "reasons": []}

        if phase == "post":
            raw = req.get("result")
            text = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False)
            pending: list[dict[str, Any]] = []
            await self._label_result(pol, session, tool, args, text, signals, defer=pending)
            known = stops(signals)
            if known:   # a known attack payload (feed): withheld as a whole, nothing left to mask or ask about
                redacted_obj, used, withheld = withhold_json(raw, withhold_notice(known, self._n)), ["withheld"], True
            else:
                redacted_obj, used, withheld = await self._redact_result(pol, session, tool, raw, signals, extra=pending)
            for item in pending:   # no identifier check to join: ask on its own
                if not item.get("done"):
                    await self._ask_directed(pol, item)
            jev_block = next((s for s in signals if s.get("authority") == "semantic" and s["action"] == "block"), None)
            if jev_block and not known:   # System One blocked the result: the agent gets a notice instead
                notice = f"[SpireGate: result withheld ({jev_block['control']}): System One judged it to contain instructions aimed at the agent]"
                redacted_obj, used, withheld = withhold_json(redacted_obj, notice), list(used) + ["withheld"], True
            self.tracer.info(_session_line(pol, session))
            decision = "withhold" if withheld else "redact" if used else "label"
            self._audit(pol, identity, surface, decision, signals, {}, extra={"tool": tool, "phase": "post",
                        "session": _session_view(pol, session), "redacted": used})
            return {"decision": "withhold" if withheld else "redact" if used else "allow",
                    "controls": [s["control"] for s in signals if s["action"] != "allow"], "reasons": [],
                    "session": _session_view(pol, session), "result_redacted": redacted_obj if used else None}

        decision, sigs, record, s1_ms = await self._evaluate_call(
            pol, identity, session, tool, args, session.get("user_request", ""), req.get("cwd"),
            session_id=req.get("session_id"))
        enforced = [s for s in sigs if s["action"] in ("block", "escalate")]
        if decision == "allow":
            self.tracer.verdict("allow", "the action complies with the policy; the agent's own permissions decide next")
        else:
            self.tracer.verdict(decision, "the action will not run" if decision == "block" else "needs approval")
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
                self.tracer.info("Claude Code gets a " + ("WITHHELD" if out["decision"] == "withhold" else "masked")
                                 + " result (updatedToolOutput)")
                return {"stdout": json.dumps(payload, ensure_ascii=False), "stderr": "", "exit": 0}
            self.tracer.info("NOTE: Codex cannot replace a tool result; masking is recorded in the log only")
        if name == "UserPromptSubmit" and out["decision"] != "allow":
            reason = "SpireGate: " + "; ".join(out["reasons"])
            if fmt == "codex":
                return {"stdout": "", "stderr": reason + "\n", "exit": 2}
            # Claude Code erases the prompt from the context and shows the reason to the user
            return {"stdout": json.dumps({"decision": "block", "reason": reason}, ensure_ascii=False), "stderr": "", "exit": 0}
        if name != "PreToolUse" or out["decision"] == "allow":
            return {"stdout": "", "stderr": "", "exit": 0}
        reason = "SpireGate: " + ("; ".join(out["reasons"]) or "blocked by policy")
        if fmt == "codex":  # exit 2 + stderr is the most robust block signal across Codex versions
            return {"stdout": "", "stderr": reason + "\n", "exit": 2}
        decision = "deny" if out["decision"] == "block" else "ask"
        payload = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                          "permissionDecisionReason": reason}}
        return {"stdout": json.dumps(payload, ensure_ascii=False), "stderr": "", "exit": 0}

    # ================================================================== shared evaluation
    async def _label_result(self, pol: LoadedPolicy, session: dict[str, Any], name: str,
                            args: dict[str, Any], text: str, signals: list[dict[str, Any]],
                            defer: list | None = None) -> float:
        spec = pol.tool(name)
        untrusted = output_is_untrusted(name, spec.model_dump(), args)
        if untrusted:
            session["integrity"] = "untrusted"
        session["class_rank"] = max(session["class_rank"], pol.class_rank(spec.output_class))
        ids = find_identifiers(text)
        if ids:
            session["class_rank"] = max(session["class_rank"], pol.class_rank("client_pii"))

        feed_sha = self.feed.current.sha if self.feed.current else ""
        key = hashlib.sha256(f"{name}\x00{pol.sha}\x00{feed_sha}\x00{text}".encode()).hexdigest()
        if key in self._seen_results:  # history is resent every turn; judge each result once
            signals.extend(self._seen_results[key])
            _taint_on_feed_hit(session, self._seen_results[key])
            return 0.0
        self.tracer.info(f"new tool result {name}: {'UNTRUSTED' if untrusted else 'trusted'}, class {spec.output_class}"
                         + (f", identifiers: {', '.join(sorted({i.kind for i in ids}))}" if ids else ""))
        # signatures of known attacks run on every result, trusted or not (a poisoned model file is poisoned anywhere)
        result_signals = self._feed_signals(pol, "tool_result", [text])
        s1_ms = 0.0
        if untrusted and not stops(result_signals):   # a withheld result needs no further questions
            s1_ms = await self._tool_result_controls(pol, name, text, result_signals, defer, signals)
        self._seen_results[key] = result_signals
        signals.extend(result_signals)
        _taint_on_feed_hit(session, result_signals)
        return s1_ms

    async def _tool_result_controls(self, pol: LoadedPolicy, name: str, text: str, out: list,
                                    defer: list | None = None, signals: list | None = None) -> float:
        """With `defer`, the System One question is not asked here: it joins the identifier check on the same
        result, so one call answers both. `out` is the cached signal list, `signals` the request's."""
        s1_ms = 0.0
        for c in pol.controls_for("tool_result"):
            if c.detector == "injection_lexicon":
                hits = injection_hits(text)
                if hits:
                    out.append(self._signal(c, f"{name}: suspicious patterns {hits}; the session is untrusted anyway"))
            elif c.detector == "systemone_directed_at_agent":
                # deferred: resolved after _label_result copied `out` into the request's signals, so append to both
                item = {"control": c, "name": name, "text": text, "out": out, "signals": signals if defer is not None else None}
                if defer is not None:
                    defer.append(item)
                else:
                    s1_ms += await self._ask_directed(pol, item)
        return s1_ms

    async def _ask_directed(self, pol: LoadedPolicy, item: dict[str, Any]) -> float:
        """The question about one untrusted result, asked on its own (nothing else to bundle it with)."""
        seen = list(item["out"]) + list(item.get("signals") or [])
        b = await self.systemone.ask_bundle(pol.doc.systemone, QUESTIONS["directed_at_agent"],
                                            Redactor().redact(item["text"])[0][:4000],
                                            {"directed_at_agent": lambda st: _stub_answer("directed_at_agent", st)},
                                            meta={"after_rule": any(_rule_acted(s) for s in seen)})
        self._resolve_directed(item, b)
        return b.latency_ms

    def _resolve_directed(self, item: dict[str, Any], bundle) -> None:
        item["done"] = True
        sig = self._s1_signal(item["control"], bundle.result("directed_at_agent"),
                              f"{item['name']}: does the text give the agent instructions?")
        item["out"].append(sig)                      # cached with the result: judged once
        if item.get("signals") is not None and item["signals"] is not item["out"]:
            item["signals"].append(sig)

    async def _ask_action(self, pol: LoadedPolicy, name: str, args: dict[str, Any], user_goal: str,
                          pending: list, sigs: list[dict[str, Any]]) -> float:
        """Every semantic question about one action in a single System One call."""
        questions: dict[str, Any] = {}
        stubs: dict[str, Any] = {}
        for q, c in pending:
            if q == "off_goal":
                questions.update(QUESTIONS["off_goal"])
                stubs[q] = lambda st: _stub_answer("off_goal", st)
            elif c.detector == "systemone_rule":
                questions[q] = {"type": "noul", "instructions": f"Czy ta akcja łamie zasadę firmy: „{c.rule}”?",
                                "criteria": {"true": "akcja narusza tę zasadę",
                                             "false": "akcja jest zgodna z tą zasadą albo jej nie dotyczy"}}
                stubs[q] = lambda st: 0.05
            else:
                v = c.verify
                questions[q] = {"type": "noul", "instructions": f"{v.question} (zasada: {c.title})",
                                "criteria": {"true": v.positive, "false": v.negative}}
                stubs[q] = lambda st: 0.05
        state = {"user_request": Redactor().redact(user_goal)[0], "tool": name,
                 "args": _loads(Redactor().redact(json.dumps(args, ensure_ascii=False))[0])}
        b = await self.systemone.ask_bundle(pol.doc.systemone, questions, state, stubs)
        self.tracer.info(f"System One [{b.backend}]: {len(pending)} questions in one call, {b.latency_ms} ms")
        for q, c in pending:
            res = b.result(q)
            if q == "off_goal":
                sigs.append(self._s1_signal(c, res, f"{name}: does the action go beyond the request?"))
            elif c.detector == "systemone_rule":
                sigs.append(self._s1_signal(c, res, f"{name}: {c.title}"))
            elif res.probability is not None and c.verify.block_at is not None and res.probability >= c.verify.block_at:
                sig = self._vsignal(f"{c.id}/verify", "block",
                                    f"the rule did not fire, but System One [{res.backend}] p={res.probability:.2f} "
                                    f"≥ {c.verify.block_at}: breaks “{c.title}”, blocked")
                sigs.append({**sig, "probability": res.probability, "backend": res.backend})
            elif res.probability is not None and res.probability >= c.verify.threshold:
                sig = self._vsignal(f"{c.id}/verify", "escalate",
                                    f"the rule did not fire, but System One [{res.backend}] p={res.probability:.2f} "
                                    f"≥ {c.verify.threshold}: may break “{c.title}”, to review")
                sigs.append({**sig, "probability": res.probability, "backend": res.backend})
            else:
                self.tracer.info(f"{c.id}/verify: System One [{res.backend}] "
                                 + (f"p={res.probability:.2f}" if res.probability is not None else "no answer")
                                 + ": no breach")
        return b.latency_ms

    async def _evaluate_call(self, pol: LoadedPolicy, identity, session: dict[str, Any], name: str,
                             args: dict[str, Any], user_goal: str, cwd: str | None, session_id: str | None = None):
        spec = pol.tool(name)
        effective, facts = compute_facts(name, spec.model_dump(), args, allowed_tools=identity.allowed_tools,
                                         internal_domains=pol.doc.org.get("internal_domains", []),
                                         protected_roots=self.protected, cwd=cwd)
        shown = {k: (v if len(str(v)) < 60 else str(v)[:57] + "...") for k, v in args.items()}
        dest = f", to: {', '.join(facts['destinations'])}" if facts["destinations"] else ""
        self.tracer.info(f"action: {name}({shown})  [effect={effective['effect']}{dest}]")
        data = {"identity": identity.model_dump(), "session": _session_view(pol, session),
                "tool": {"name": name, **effective}, "args": args, "facts": facts}

        sigs: list[dict[str, Any]] = []
        s1_ms = 0.0
        # loop breaker and tool-call budgets come before any other rule
        for cid, reason in self.ledger.tool_call(pol.doc.budgets, identity, session_id, name, args):
            sigs.append(self._bsignal(cid, reason))
        # known attacks from the signed feed: the arguments, plus any model file the action points at
        texts = json_strings(args)
        sigs += self._feed_signals(pol, "tool_call", texts, model_paths(texts, cwd))
        # 1. deterministic rules decide what they can, and collect the semantic questions for System One
        pending: list[tuple[str, Control]] = []
        for c in pol.controls_for("tool_call"):
            if c.detector == "systemone_rule":               # a company rule in plain language
                # without its own scope it covers risky actions; `when` widens or narrows that
                if (c.when and _in_scope(pol, c, data)) or (not c.when and effective["effect"] in RISKY_EFFECTS):
                    pending.append(("rule_" + _qname(c.id).removeprefix("verify_"), c))
                continue
            if c.detector == "systemone_matches_goal":       # a rule only System One can judge
                if effective["effect"] not in RISKY_EFFECTS or not _in_scope(pol, c, data):
                    continue
                if user_goal:
                    pending.append(("off_goal", c))
                else:
                    self.tracer.info(f"System One {c.id}: no user prompt in the session, skipped")
                continue
            if c.when:
                matched, err = pol.eval_when(c, data)
                if err:
                    sigs.append(self._signal(c, f"CEL condition error ({err}) → fail-closed: block", action="block"))
                elif matched:
                    sigs.append(self._signal(c, c.title))
                elif c.verify is not None and effective["effect"] in RISKY_EFFECTS and _verify_applies(pol, c, data):
                    pending.append((_qname(c.id), c))     # the rule is silent: does the action break it anyway?
        # 2. after a deterministic block there is nothing left for System One to decide: it is not asked
        #    (it may make a decision stricter, never looser, so asking could not change the outcome)
        if pending and _combine(sigs) == "block":
            self.tracer.info(f"System One skipped ({', '.join(c.id for _, c in pending)}): "
                             "a deterministic rule already blocked")
        elif pending:
            s1_ms += await self._ask_action(pol, name, args, user_goal, pending, sigs)
        decision = _combine(sigs)
        preview = Redactor().redact(json.dumps(args, ensure_ascii=False))[0]  # PII and secrets masked, never raw
        record = {"tool": name, "args_sha256": hashlib.sha256(json.dumps(args, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
                  "args_redacted": preview if len(preview) <= 600 else preview[:597] + "...",
                  "effect": effective["effect"], "destinations": facts["destinations"], "decision": decision,
                  "controls": [s["control"] for s in sigs if s["action"] in ("block", "escalate")]}
        return decision, sigs, record, s1_ms

    async def _apply_to_model(self, pol: LoadedPolicy, model, session, body, signals):
        """Two reasons to mask before the model: the session's data class exceeds what the model may see
        (all identifier kinds), or a per-kind rule such as "the agent never sees PESEL" (any model)."""
        upstream_body = copy.deepcopy(body)
        plans: list[tuple[Control, set[str] | None, str]] = []
        class_ctrl = next((c for c in pol.controls_for("to_model") if c.detector == "fin_identifiers"), None)
        if class_ctrl and session["class_rank"] > pol.class_rank(model.max_class):
            plans.append((class_ctrl, None, f"{model.id} ({model.location}) may see at most class "
                                            f"{model.max_class}, the session holds {_class(pol, session)}"))
        for c in pol.controls_for("tool_result"):
            if c.detector == "identifiers" and c.action == "redact":
                plans.append((c, set(c.kinds or []), c.title))
        if not plans:
            self.tracer.info(f"session class {_class(pol, session)} ≤ the model's max_class {model.max_class}: no masking")
            return upstream_body, []

        redactor = Redactor()  # shared, so placeholders stay numbered consistently across rules
        applied: list[str] = []
        for control, kinds, why in plans:
            used: list[str] = []
            for m in upstream_body.get("messages", []):
                if isinstance(m.get("content"), str):
                    m["content"], u = redactor.redact(m["content"], kinds)
                    used += u
                for tc in m.get("tool_calls") or []:
                    tc["function"]["arguments"], u = redactor.redact(tc["function"]["arguments"], kinds)
                    used += u
            unique = sorted(set(used), key=used.index)
            if unique:
                signals.append(self._signal(control, f"{', '.join(unique)} masked before the model: {why}"))
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
                             signals: list[dict[str, Any]], extra: list | None = None) -> tuple[Any, list[str], bool]:
        """Hooks and SDK: mask identifier kinds inside a tool result before it reaches the agent,
        then let System One confirm nothing is left. Returns (result, what changed, withheld?)."""
        redactor = session.setdefault("_redactor", Redactor())  # per session: [PESEL#1] stays the same person
        obj, applied, withheld = raw, [], False
        spec = pol.tool(tool)
        for c in pol.controls_for("tool_result"):
            if c.detector != "identifiers" or c.action != "redact":
                continue
            kinds = set(c.kinds or [])
            obj, used = redact_json(obj, redactor, kinds)
            unique = sorted(set(used), key=used.index)
            if unique:
                signals.append(self._signal(c, f"{tool}: {', '.join(unique)} masked before the result reaches the agent"))
                applied += unique
            if c.verify is not None:
                sensitive = bool(unique) or pol.class_rank(spec.output_class) >= pol.class_rank("client_pii")
                obj, outcome = await self._verify_residue(pol, c, obj, kinds, sensitive, signals, extra=extra)
                if outcome in ("masked", "withheld"):  # suspected identifiers still mean the session touched PII
                    session["class_rank"] = max(session["class_rank"], pol.class_rank("client_pii"))
                    applied.append(outcome)
                withheld = withheld or outcome == "withheld"
        return obj, applied, withheld

    async def _verify_residue(self, pol: LoadedPolicy, c: Control, obj: Any, kinds: set[str], sensitive: bool,
                              signals: list[dict[str, Any]], extra: list | None = None) -> tuple[Any, str]:
        """precise masking (done) → residue hints? → System One → mask hinted spans → System One → withhold.

        System One alone never withholds: a withhold needs a second "yes" after masking, and a
        deterministic filter that found traces or a source known to carry client data."""
        v = c.verify
        label = sorted(kinds)[0]
        cid = f"{c.id}/verify"
        hinted = any(residue_hints(t, kinds) for t in json_strings(obj))
        if not hinted and not sensitive:
            return obj, "skip"
        why = "the filter found traces" if hinted else "a result from a client-data source"

        async def ask(o, joined=()):
            # other identifier kinds are masked too: System One only needs to see what this rule may have missed
            questions = residue_questions(v)
            stubs = {"residual": lambda st: stub_residual(st, kinds)}
            if joined:
                questions.update(QUESTIONS["directed_at_agent"])
                stubs["directed_at_agent"] = lambda st: _stub_answer("directed_at_agent", st)
            b = await self.systemone.ask_bundle(pol.doc.systemone, questions, Redactor().redact(state_text(o))[0], stubs,
                                                meta={"after_rule": True})   # the identifier detector ran first
            for item in joined:
                self._resolve_directed(item, b)
            return b.result("residual")

        res = await ask(obj, [it for it in (extra or []) if not it.get("done")])
        if res.probability is None:
            detail = res.error or res.note or "no answer"
            if not hinted:
                self.tracer.info(f"{cid}: System One gave no answer ({detail}); no traces, result unchanged")
                return obj, "error"
            masked, n = mask_residue(obj, kinds, label)
            signals.append(self._vsignal(cid, "redact", f"System One gave no answer ({detail}); "
                                                        f"masking {n} suspicious spans deterministically"))
            return masked, "masked"

        form = res.extra.get("form")
        line = (f"System One [{res.backend}] p={res.probability:.2f}" + (f", form: {form}" if form else "")
                + f", {res.latency_ms} ms ({why})")
        if res.probability < v.threshold:
            self.tracer.info(f"{cid}: {line} < threshold {v.threshold} → confirmed: no {label}")
            signals.append({"control": cid, "action": "allow", "authority": "advisory",
                            "reason": line, "probability": res.probability, "backend": res.backend})
            return obj, "pass"

        masked, n = mask_residue(obj, kinds, label)
        if n:
            signals.append(self._vsignal(cid, "redact", f"{line} ≥ threshold {v.threshold} → masking {n} suspicious spans"))
            res2 = await ask(masked)
            if res2.probability is not None and res2.probability < v.threshold:
                self.tracer.info(f"{cid}: after masking p={res2.probability:.2f} < threshold → the result goes through")
                return masked, "masked"
            second = "System One gave no answer" if res2.probability is None else f"still p={res2.probability:.2f} after masking"
        else:
            second = "the filter found nothing to mask"
        what = "withheld" if v.on_fail == "withhold" else "withheld for review"
        notice = f"[SpireGate: result {what} ({c.id}): possible {label} in an unrecognised form, event #{self._n}]"
        signals.append(self._vsignal(cid, "withhold", f"{line}; {second} → result {what}"))
        return withhold_json(obj, notice), "withheld"

    def _vsignal(self, cid: str, action: str, reason: str) -> dict[str, Any]:
        self.tracer.decision(action, cid, reason)
        return {"control": cid, "action": action, "authority": "corroborated", "reason": reason}

    # ================================================================== signature feed
    def _feed_signals(self, pol: LoadedPolicy, phase: str, texts: list[str], files=()) -> list[dict[str, Any]]:
        sigs = signals_for(self.feed.current, pol.controls_for(phase), phase, texts, files)
        for s in sigs:
            self.tracer.decision(s["action"], s["control"], s["reason"])
        return sigs

    def _drop_poisoned_tools(self, pol: LoadedPolicy, body: dict[str, Any], signals: list[dict[str, Any]]) -> list[str]:
        """Tool definitions come from the tool's server (e.g. MCP), so they are untrusted content: a definition
        that carries a known attack (hidden <IMPORTANT> instructions...) is removed before the model sees it."""
        kept, dropped = [], []
        for t in body.get("tools") or []:
            fn = t.get("function") or {}
            hits = self._feed_signals(pol, "tool_result", json_strings(fn))
            if stops(hits):
                dropped.append(str(fn.get("name", "?")))
                signals.extend(hits)
            else:
                kept.append(t)
        if dropped:
            body["tools"] = kept
            if not kept:
                body.pop("tools", None)
                body.pop("tool_choice", None)
            self.tracer.info(f"poisoned tools removed: {', '.join(dropped)} (the model never sees them)")
        return dropped

    # ================================================================== helpers
    def _policy(self) -> LoadedPolicy:
        pol = self.store.get()
        for ev in self.store.events[self._events_shown:]:
            self.tracer.policy(ev)
        self._events_shown = len(self.store.events)
        self.feed.sync(pol.doc.feed)   # a local feed file is re-read on change; an http feed is polled in the background
        for ev in self.feed.events[self._feed_events_shown:]:
            self.tracer.policy(f"signature feed: {ev['message']}")
        self._feed_events_shown = len(self.feed.events)
        self._n += 1
        return pol

    def _signal(self, c: Control, reason: str, *, action: str | None = None) -> dict[str, Any]:
        action = action or c.action
        if c.authority == "corroborating" and action == "block":
            action = "taint"  # heuristics never block alone
        self.tracer.decision(action, c.id, reason)
        return {"control": c.id, "action": action, "authority": c.authority, "reason": reason}

    def _s1_signal(self, c: Control, res, question: str) -> dict[str, Any]:
        """System One's verdict on one rule: approve (below escalate_at), review (escalate) or block (block_at)."""
        p = res.probability
        if p is None:
            detail = res.error or res.note or "no answer"
            if c.authority == "semantic" and res.error and c.on_error != "allow":
                # the rule has no deterministic fallback: an outage must not silently approve
                action = "escalate" if c.on_error == "review" else "block"
                sig = self._signal(c, f"{question}: System One unavailable ({detail}) → "
                                      + ("to review" if action == "escalate" else "blocked"), action=action)
                sig.update(backend=res.backend)
                return sig
            self.tracer.info(f"System One [{res.backend}] {question} → no answer ({detail}); no effect")
            return {"control": c.id, "action": "allow", "authority": c.authority, "reason": detail, "backend": res.backend}
        note = f" ({res.note})" if res.note else ""
        text = f"System One [{res.backend}{note}] {question} p={p:.2f}, {res.latency_ms} ms"
        if c.block_at is not None and p >= c.block_at:
            sig = self._signal(c, text + f" ≥ {c.block_at}: blocked", action="block")
        elif c.escalate_at is not None and p >= c.escalate_at:
            sig = self._signal(c, text + f" ≥ {c.escalate_at}: to review", action="escalate")
        else:
            self.tracer.info(text + f" < {c.escalate_at}: approved")
            return {"control": c.id, "action": "allow", "authority": c.authority,
                    "reason": text, "probability": p, "backend": res.backend}
        sig.update(probability=p, backend=res.backend)
        return sig

    def _audit(self, pol, identity, surface, decision, signals, latency, extra=None) -> None:
        record = self.audit.append({
            "request": self._n, "surface": surface,
            "agent": identity.agent_id if identity else None,
            "desk": identity.desk if identity else None,
            "decision": decision, "signals": signals, "latency": latency,
            "policy": {"rev": pol.rev, "sha": pol.sha},
            **({"feed": {"v": self.feed.current.version, "sha": self.feed.current.sha}} if self.feed.current else {}),
            **({"sim": True} if SIMULATED.get() else {}),  # synthetic load is labelled as such
            **(extra or {}),
        })
        self.bus.end(decision, signals, latency, (extra or {}).get("cost"), record.get("seq"))


def _combine(signals: list[dict[str, Any]]) -> str:
    worst = "allow"
    for s in signals:
        if s["action"] in ("block", "escalate") and ACTION_SEVERITY[s["action"]] > ACTION_SEVERITY[worst]:
            worst = s["action"]
    return worst


def _taint_on_feed_hit(session: dict[str, Any], signals: list[dict[str, Any]]) -> None:
    """A result that carried a known attack makes the session untrusted, whatever the source claimed."""
    if any(s.get("signature") and s.get("action") != "allow" for s in signals):
        session["integrity"] = "untrusted"


def _assistant(body: dict[str, Any], content: str) -> dict[str, Any]:
    """A chat completion the gateway answers itself (nothing was sent to the model, nothing was spent)."""
    return {"id": "spiregate-refusal", "object": "chat.completion", "created": int(time.time()),
            "model": body.get("model"), "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]}


def _in_scope(pol: LoadedPolicy, c: Control, data: dict[str, Any]) -> bool:
    """For a rule only System One judges, `when` is its scope. A broken scope asks anyway."""
    if not c.when:
        return True
    matched, err = pol.eval_when(c, data)
    return True if err else bool(matched)


def _rule_acted(s: dict[str, Any]) -> bool:
    """A deterministic rule or heuristic (not System One) changed something in this request."""
    return s.get("action") not in (None, "allow") and s.get("authority") not in ("advisory", "semantic", "corroborated")


def _verify_applies(pol: LoadedPolicy, c: Control, data: dict[str, Any]) -> bool:
    """Ask System One about a rule only where the rule means something. A broken scope asks anyway:
    an extra advisory question is the safer mistake."""
    if not c.verify.when:
        return True
    matched, err = pol.eval_when(c, data, key=f"{c.id}/verify")
    return True if err else bool(matched)


def _qname(control_id: str) -> str:
    """A System One question name per rule, so many rules fit in one call."""
    return "verify_" + "".join(ch if ch.isalnum() else "_" for ch in control_id)


def _action_label(tool: str, args: dict[str, Any]) -> str:
    """Short, masked description of an action for the live stream (never raw PII or secrets)."""
    main = next((args[k] for k in ("command", "cmd", "file_path", "path", "url", "to", "pattern") if args.get(k)), "")
    if isinstance(main, list):
        main = " ".join(map(str, main))
    text = f"{tool}: {main}" if main else tool
    return Redactor().redact(str(text))[0][:90]


def _class(pol: LoadedPolicy, session: dict[str, Any]) -> str:
    return pol.doc.classification[session["class_rank"]]


def _session_view(pol: LoadedPolicy, session: dict[str, Any]) -> dict[str, Any]:
    return {"integrity": session["integrity"], "class": _class(pol, session), "class_rank": session["class_rank"]}


def _session_line(pol: LoadedPolicy, session: dict[str, Any]) -> str:
    return f"session labels: integrity={session['integrity']}, class={_class(pol, session)}"


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
