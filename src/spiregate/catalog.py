"""Rule templates: what a bank can switch on without writing CEL.

One source of truth for the dashboard's forms, the free-text importer and editing: a control made from a
template remembers `template` and `params`, so the dashboard reopens it as the same simple form. Every
template builds a plain control; the policy file stays the only thing the gate reads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .detectors import KIND_LABELS, KNOWN_KINDS

ACTION_LABELS = {"block": "Blocks", "escalate": "To review", "redact": "Redacts", "taint": "Flags", "allow": "Allows"}
LANES = {"d": "Deterministic", "dj": "Deterministic + Jev", "j": "Jev"}
# what a rule looks at, in one short line (for rules whose parameters do not say it)
WHAT = {"block_credentials": "~/.aws, ~/.ssh, ~/.kube, .netrc, *.pem", "block_download_exec": "curl | sh, base64 -d | sh",
        "block_destructive": "rm -rf, force push, DROP TABLE, terraform destroy", "block_privilege": "sudo, su, chmod 777",
        "block_package_install": "pip, npm, brew, apt", "fin_identifiers": "IBAN, LEI, ISIN, card, PESEL",
        "injection_lexicon": "EN/PL phrase list, hidden text", "systemone_directed_at_agent": "web pages, emails and files from outside",
        "systemone_matches_goal": "risky actions outside the shell",
        "signatures": "signed feed of known attacks: pickle, model supply chain, RCE on AI infrastructure"}

# calibrated on Jev 1.13.0 (2026-10-03): "no" ≤ 0.17, "yes" ≥ 0.83 → threshold 0.7. Kept in Polish: the threshold
# was calibrated on this exact wording.
_PESEL_VERIFY = {
    "question": "Czy ten tekst nadal zawiera numer PESEL albo jego część?",
    "positive": "11-cyfrowy numer identyfikacyjny osoby w dowolnej formie, np. z odstępami, zapisany słownie, "
                "częściowo podany albo zakodowany",
    "negative": "brak takiego numeru; znaczniki w nawiasach typu [PESEL#1] lub [PESEL?#1] są już zamaskowane i się nie "
                "liczą; numery zamówień, faktur i telefonów to nie PESEL",
    "threshold": 0.7, "on_fail": "withhold",
}

_DOMAIN = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
_TOOL = re.compile(r"^[A-Za-z0-9_.:-]+$")


@dataclass
class Param:
    name: str
    label: str
    type: str                       # kinds | list | number | text | choice | bool
    default: Any = None
    options: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Template:
    key: str
    group: str
    title: str                      # also the default title of a rule made from it
    summary: str
    lane: str                       # d | dj | j (dj is decided by params for mask_identifiers)
    prefix: str
    params: list[Param]
    build: Callable[[dict[str, Any], str, str | None], dict[str, Any]]
    
    def view(self) -> dict[str, Any]:
        return {"key": self.key, "group": self.group, "title": self.title, "summary": self.summary, "lane": self.lane,
                "target": "control",
                "params": [{"name": p.name, "label": p.label, "type": p.type, "default": p.default,
                            "options": [{"value": v, "label": lbl} for v, lbl in p.options]} for p in self.params]}


# ---------------------------------------------------------------- param cleaning (never trust a form)
def _kinds(v: Any) -> list[str]:
    out = [str(k).upper() for k in (v or []) if str(k).upper() in KNOWN_KINDS]
    if not out:
        raise ValueError("choose at least one kind of data")
    return sorted(set(out), key=out.index)


def _domains(v: Any) -> list[str]:
    items = v if isinstance(v, list) else re.split(r"[\s,;]+", str(v or ""))
    out = []
    for d in items:
        d = str(d).strip().lower().lstrip("@").rstrip(".")
        if not d:
            continue
        if not _DOMAIN.match(d):
            raise ValueError(f"“{d}” does not look like a domain (e.g. gs.com)")
        out.append(d)
    if not out:
        raise ValueError("enter at least one domain")
    return sorted(set(out), key=out.index)


def _tools(v: Any) -> list[str]:
    items = v if isinstance(v, list) else re.split(r"[\s,;]+", str(v or ""))
    out = [t.strip() for t in items if str(t).strip()]
    bad = [t for t in out if not _TOOL.match(t)]
    if bad or not out:
        raise ValueError("enter tool names, e.g. Bash, send_email" + (f" (invalid: {', '.join(bad)})" if bad else ""))
    return out


def _number(v: Any, name: str, lo: float = 0, hi: float = 1e12) -> float:
    try:
        x = float(str(v).replace(" ", "").replace(",", "."))
    except (TypeError, ValueError):
        raise ValueError(f"{name}: enter a number") from None
    if not lo <= x <= hi:
        raise ValueError(f"{name}: must be between {lo:g} and {hi:g}")
    return x


def _choice(v: Any, allowed: tuple[str, ...], default: str) -> str:
    return v if v in allowed else default


def _num_lit(x: float) -> str:
    return repr(float(x))


def _finish(ctrl: dict[str, Any], template: str, params: dict[str, Any]) -> dict[str, Any]:
    ctrl["template"] = template
    ctrl["params"] = params
    return ctrl


# ---------------------------------------------------------------- builders
def _mask(p: dict[str, Any], cid: str, title: str | None) -> dict[str, Any]:
    kinds, verify = _kinds(p.get("kinds")), bool(p.get("verify"))
    labels = ", ".join(KIND_LABELS.get(k, k) for k in kinds)
    c = {"id": cid, "title": title or f"The agent never sees: {labels}", "phase": "tool_result", "detector": "identifiers",
         "kinds": kinds, "action": "redact"}
    if verify:
        c["verify"] = dict(_PESEL_VERIFY) if kinds == ["PESEL"] else {
            "question": f"Does this text still contain a {labels} or part of one?",
            "positive": f"a {labels} in any form, e.g. with spaces, spelled out in words, partial or encoded",
            "negative": "no such data; tokens in square brackets are already masked and do not count; "
                        "order, invoice and phone numbers do not count",
            "threshold": 0.7, "on_fail": "withhold"}
    return _finish(c, "mask_identifiers", {"kinds": kinds, "verify": verify})


def _fact_rule(key: str, fact: str, default_title: str, default_action: str = "block"):
    def build(p: dict[str, Any], cid: str, title: str | None) -> dict[str, Any]:
        action = _choice(p.get("action"), ("block", "escalate"), default_action)
        c = {"id": cid, "title": title or default_title, "phase": "tool_call", "when": f"facts.{fact}", "action": action}
        return _finish(c, key, {"action": action})
    return build


def _egress(p: dict[str, Any], cid: str, title: str | None) -> dict[str, Any]:
    domains = _domains(p.get("domains"))
    ok = " || ".join(f'd.endsWith("@{d}") || d.endsWith(".{d}") || d == "{d}"' for d in domains)
    c = {"id": cid, "title": title or f"Send only to: {', '.join(domains)}", "phase": "tool_call",
         "when": f'tool.effect == "external_send" && !facts.destinations.all(d, {ok})', "action": "block"}
    return _finish(c, "egress_domains", {"domains": domains})


def _amount(p: dict[str, Any], cid: str, title: str | None) -> dict[str, Any]:
    amount = _number(p.get("amount", 10000), "amount", 0)
    action = _choice(p.get("action"), ("escalate", "block"), "escalate")
    shown = f"{amount:,.0f}"
    c = {"id": cid, "title": title or f"Payments over {shown}: " + ("review" if action == "escalate" else "block"),
         "phase": "tool_call", "when": f'tool.effect == "financial" && facts.amount > {_num_lit(amount)}', "action": action}
    return _finish(c, "amount_review", {"amount": amount, "action": action})


def _hours(p: dict[str, Any], cid: str, title: str | None) -> dict[str, Any]:
    start, end = int(_number(p.get("start", 8), "from", 0, 23)), int(_number(p.get("end", 18), "to", 1, 24))
    if start >= end:
        raise ValueError("“from” must be earlier than “to”")
    action = _choice(p.get("action"), ("escalate", "block"), "escalate")
    c = {"id": cid, "title": title or f"Sends, payments and deletes outside {start}:00–{end}:00 and at weekends",
         "phase": "tool_call",
         "when": f'tool.effect in ["external_send", "financial", "delete"] && '
                 f"(facts.hour < {start} || facts.hour >= {end} || facts.weekday >= 5)",
         "action": action}
    return _finish(c, "business_hours", {"start": start, "end": end, "action": action})


def _deny_tools(p: dict[str, Any], cid: str, title: str | None) -> dict[str, Any]:
    tools = _tools(p.get("tools"))
    listed = ", ".join(f'"{t}"' for t in tools)
    c = {"id": cid, "title": title or f"Banned tools: {', '.join(tools)}", "phase": "tool_call",
         "when": f"tool.name in [{listed}]", "action": "block"}
    return _finish(c, "deny_tools", {"tools": tools})


def _prose(p: dict[str, Any], cid: str, title: str | None) -> dict[str, Any]:
    text = " ".join(str(p.get("text") or "").split())
    if len(text) < 8:
        raise ValueError("describe the rule in one sentence")
    if len(text) > 600:
        raise ValueError("the rule is too long (max 600 characters); split it into several")
    action = _choice(p.get("action"), ("escalate", "block"), "escalate")
    c = {"id": cid, "title": title or (text if len(text) <= 90 else text[:87] + "…"), "phase": "tool_call",
         "detector": "systemone_rule", "rule": text, "action": action, "authority": "semantic", "escalate_at": 0.75}
    if action == "block":
        c["block_at"] = 0.92
    return _finish(c, "prose_rule", {"text": text, "action": action})



ACTION_PARAM = Param("action", "When the rule fires", "choice", "block", [("block", "Block"), ("escalate", "Send to review")])
REVIEW_FIRST = Param("action", "When the rule fires", "choice", "escalate", [("escalate", "Send to review"), ("block", "Block")])

TEMPLATES: dict[str, Template] = {t.key: t for t in [
    Template("mask_identifiers", "Data", "The agent never sees…", "Masks the chosen data in tool results before the agent sees them.",
             "d", "MASK", [Param("kinds", "Data", "kinds", ["PESEL"]),
                           Param("verify", "Jev checks that nothing slipped through (e.g. spelled out in words)", "bool", False)], _mask),
    Template("egress_domains", "Actions", "Send only to domains", "Blocks emails and uploads to anything outside the listed domains.",
             "d", "EGRESS", [Param("domains", "Allowed domains", "list", ["gs.com"])], _egress),
    Template("block_credentials", "Actions", "Credentials", "Blocks access to ~/.aws, ~/.ssh, keys and password files.",
             "d", "CRED", [ACTION_PARAM], _fact_rule("block_credentials", "touches_credentials",
                                                     "No access to credentials")),
    Template("block_download_exec", "Actions", "Download and run", "Blocks curl | sh and similar ways of running code from the internet.",
             "d", "EXEC", [ACTION_PARAM], _fact_rule("block_download_exec", "pipe_to_shell",
                                                     "No running code straight from the internet")),
    Template("block_destructive", "Actions", "Destructive commands", "rm -rf, force push, DROP TABLE, terraform destroy, deletes.",
             "d", "DESTR", [ACTION_PARAM], _fact_rule("block_destructive", "destructive", "No destructive commands")),
    Template("block_privilege", "Actions", "Admin privileges", "sudo, su, setuid, chmod 777.",
             "d", "PRIV", [ACTION_PARAM], _fact_rule("block_privilege", "privilege_escalation", "No privilege escalation")),
    Template("block_package_install", "Actions", "Package installs", "pip, npm, brew, apt: dependencies from outside.",
             "d", "PKG", [REVIEW_FIRST], _fact_rule("block_package_install", "package_install",
                                                    "Package installs from outside", "escalate")),
    Template("amount_review", "Actions", "Payments over an amount", "A transfer above the threshold goes to approval or is blocked.",
             "d", "AMT", [Param("amount", "Threshold", "number", 10000), REVIEW_FIRST], _amount),
    Template("business_hours", "Actions", "Business hours", "Sends, payments and deletes outside business hours and at weekends.",
             "d", "HOURS", [Param("start", "From hour", "number", 8), Param("end", "To hour", "number", 18), REVIEW_FIRST],
             _hours),
    Template("deny_tools", "Actions", "Banned tools", "The agent may not use the listed tools.",
             "d", "TOOLS", [Param("tools", "Tools", "list", [])], _deny_tools),
    Template("prose_rule", "Plain-language rules", "Plain-language rule", "A rule written as a sentence; Jev judges every risky action against it.",
             "j", "RULE", [Param("text", "Rule", "text", ""), REVIEW_FIRST], _prose),
]}


def build(key: str, params: dict[str, Any], cid: str, title: str | None = None) -> dict[str, Any]:
    t = TEMPLATES.get(key)
    if t is None:
        raise ValueError(f"unknown template {key!r}")
    return t.build(params or {}, cid, (title or "").strip() or None)


def next_id(prefix: str, taken: set[str]) -> str:
    n = 1
    while f"{prefix}-{n:03d}" in taken:
        n += 1
    return f"{prefix}-{n:03d}"


def lane_of(c: Any) -> str:
    """Which lane of the Engine page a control belongs to."""
    if (c.detector or "").startswith("systemone_"):
        return "j"
    return "dj" if c.verify is not None else "d"


def catalog_view() -> dict[str, Any]:
    return {"templates": [t.view() for t in TEMPLATES.values()],
            "kinds": [{"value": k, "label": KIND_LABELS.get(k, k)} for k in KIND_LABELS],
            "lanes": LANES}
