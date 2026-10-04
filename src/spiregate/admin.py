"""Admin plane for the dashboard: analytics over the audit log, guarded policy edits, playground, exports.

Everything here reads the same hash-chained audit log, so management and SecOps never see different numbers.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .audit import verify
from .catalog import ACTION_LABELS, TEMPLATES, WHAT, catalog_view, lane_of
from .catalog import build as catalog_build
from .detectors import KIND_LABELS
from .feed import posture_check
from .policy import INVARIANTS, LoadedPolicy, PolicyStore
from .systemone import SystemOneClient

DECISIONS = ("allow", "redact", "escalate", "block")
_ACTIONS_THAT_COUNT = {"block", "redact", "withhold", "escalate", "taint"}


def _acted(s: dict[str, Any]) -> bool:
    """A signal that changed the outcome. Entries written before modes were removed may carry
    enforced=false (monitor mode): those only observed and are not counted."""
    return s.get("action") in _ACTIONS_THAT_COUNT and s.get("enforced", True) is not False


def _raw_decision(entry: dict[str, Any]) -> str:
    """Decision as recorded, for exports: keeps withhold apart from block."""
    d = entry.get("decision", "allow")
    return "allow" if d in ("label", "upstream_error") else d


def _decision(entry: dict[str, Any]) -> str:
    """Dashboard view of a decision. `withhold` (the action ran, its result was hidden from the model) stays
    distinct in the audit log for investigators, but for an operator it is simply a blocked output."""
    d = entry.get("decision", "allow")
    return "allow" if d in ("label", "upstream_error") else "block" if d == "withhold" else d


def _pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, round(p / 100 * (len(s) - 1))))
    return round(s[k], 1)


class AuditVerifyCache:
    """Verifying the whole chain on every 2 s poll is wasteful; re-verify only when the file changes."""

    def __init__(self, path: Path):
        self.path = path
        self._key: tuple[int, int] | None = None
        self._result: tuple[bool, str] = (True, "no log yet")

    def get(self) -> tuple[bool, str]:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return True, "no log yet"
        key = (st.st_size, st.st_mtime_ns)
        if key != self._key:
            self._key, self._result = key, verify(self.path)
        return self._result


def _control_titles(pol: LoadedPolicy) -> dict[str, str]:
    titles = {c.id: c.title for c in pol.doc.controls}
    titles["LOOP-001"] = "Loop breaker: the same call over and over"
    titles["BUDGET-SESSION"] = "Tool-call limit per session"
    for r in pol.doc.budgets.rules:
        titles[r.id] = f"Budget {r.scope} per {r.window}"
    return titles


def budgets_view(entries: list[dict[str, Any]], pol: LoadedPolicy, ledger) -> dict[str, Any]:
    spend: dict[str, dict[str, float]] = defaultdict(lambda: {"usd": 0.0, "tokens": 0, "calls": 0})
    for e in entries:
        c = e.get("cost")
        if c:
            row = spend[e.get("model") or "?"]
            row["usd"] += c.get("usd", 0.0)
            row["tokens"] += c.get("tokens", 0)
            row["calls"] += 1
    refused = sum(1 for e in entries for s in e.get("signals", []) if _acted(s)
                  and str(s.get("control", "")).startswith(("BUD", "LOOP-", "BUDGET-")))
    rows, tripped = ledger.snapshot(pol.doc.budgets) if ledger else ([], [])
    overhead = dict(ledger.control_overhead) if ledger else {"calls": 0, "input_tokens": 0, "usd": 0.0}
    model_usd = sum(r["usd"] for r in spend.values())
    return {
        "rules": rows,
        "loops": {"tripped": tripped, **pol.doc.budgets.loops.model_dump()},
        "spend": {m: {**v, "usd": round(v["usd"], 6)} for m, v in sorted(spend.items(), key=lambda kv: -kv[1]["usd"])},
        "spend_usd": round(model_usd, 6),
        "control_overhead": {**overhead, "usd": round(overhead["usd"], 6),
                             "share_pct": round(100 * overhead["usd"] / model_usd, 2) if model_usd else None},
        "refused": refused,
    }


def summarize(entries: list[dict[str, Any]], pol: LoadedPolicy, store: PolicyStore,
              audit_state: tuple[bool, str], now: datetime | None = None, ledger=None,
              feed: dict[str, Any] | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    kpis = Counter(_decision(e) for e in entries)

    # timeline: last 30 minutes, one bucket per minute
    start = (now - timedelta(minutes=29)).replace(second=0, microsecond=0)
    buckets = {start + timedelta(minutes=i): Counter() for i in range(30)}
    for e in entries:
        try:
            ts = datetime.fromisoformat(e["ts"]).replace(second=0, microsecond=0)
        except (KeyError, ValueError):
            continue
        if ts in buckets:
            buckets[ts][_decision(e)] += 1
    timeline = [{"t": t.astimezone().strftime("%H:%M"), **{d: c.get(d, 0) for d in DECISIONS}}
                for t, c in buckets.items()]

    titles = _control_titles(pol)
    by_control: dict[str, dict[str, Any]] = {}
    for e in entries:
        for sig in e.get("signals", []):
            if not _acted(sig):
                continue
            cid = sig.get("control", "?")
            row = by_control.setdefault(cid, {"id": cid, "title": titles.get(cid.split("/")[0], ""), "count": 0,
                                              "actions": Counter()})
            row["count"] += 1
            row["actions"][sig["action"]] += 1
    controls = sorted(({**r, "actions": dict(r["actions"])} for r in by_control.values()), key=lambda r: -r["count"])

    agents: dict[str, Counter] = defaultdict(Counter)
    desks: dict[str, str] = {}
    for e in entries:
        a = e.get("agent") or "unknown key"
        agents[a][_decision(e)] += 1
        agents[a]["total"] += 1
        desks[a] = e.get("desk") or "—"
    by_agent = sorted(({"agent": a, "desk": desks[a], **dict(c)} for a, c in agents.items()), key=lambda r: -r["total"])

    lat: dict[str, list[float]] = defaultdict(list)
    for e in entries:
        for k, v in (e.get("latency") or {}).items():
            if isinstance(v, (int, float)) and (k != "systemone_ms" or v > 0):
                lat[k.removesuffix("_ms")].append(float(v))
    latency = {k: {"p50": _pct(v, 50), "p95": _pct(v, 95), "n": len(v)} for k, v in lat.items()}

    s1_backends = Counter(s.get("backend") for e in entries for s in e.get("signals", []) if s.get("backend"))
    tokens = Counter()
    for e in entries:
        u = e.get("usage") or {}
        if u.get("total_tokens"):
            tokens[e.get("model") or "?"] += u["total_tokens"]

    backend, note = SystemOneClient.resolve_backend(pol.doc.systemone)
    checks = [
        {"name": "Invariants", "ok": True, "detail": f"{len(INVARIANTS)} rules, cannot be removed"},
        {"name": "Policy", "ok": store.last_error is None,
         "detail": "edit rejected" if store.last_error else f"rev {pol.rev} · loaded"},
        {"name": "Audit chain", "ok": audit_state[0], "detail": "intact" if audit_state[0] else "broken"},
        {"name": "System One", "ok": backend == "jev", "detail": note or f"{backend} · online"},
        {"name": "Budgets", "ok": bool(pol.doc.budgets.rules), "detail": f"{len(pol.doc.budgets.rules)} rules"},
    ]
    if feed is not None:
        checks.append(posture_check(feed))
    weights = {"Invariants": 30, "Policy": 20, "Audit chain": 20, "System One": 15, "Budgets": 15, "Signature feed": 15}
    score = round(100 * sum(weights[c["name"]] for c in checks if c["ok"]) / sum(weights[c["name"]] for c in checks))

    return {
        "generated_at": now.isoformat(),
        "policy": {"rev": pol.rev, "sha": pol.sha, "error": store.last_error, "events": store.events[-8:],
                   "rules": len(pol.doc.controls)},
        "kpis": {"total": len(entries), **{d: kpis.get(d, 0) for d in DECISIONS}},
        "timeline": timeline,
        "controls": controls[:8],
        "agents": by_agent[:8],
        "latency": latency,
        "systemone": {"backend": backend, "note": note, "model": pol.doc.systemone.model,
                      "calls": sum(s1_backends.values()), "by_backend": dict(s1_backends)},
        "tokens": dict(tokens),
        "audit": {"ok": audit_state[0], "message": audit_state[1]},
        "posture": {"score": score, "checks": checks},
        "budgets": budgets_view(entries, pol, ledger),
    }


def _rule_label(c) -> str:
    if c.authority == "semantic":
        return "Jev: review or block" if c.block_at is not None else "Jev: review"
    if c.detector == "identifiers" and c.verify is not None:
        return "Redacts, Jev verifies"
    return ACTION_LABELS.get(c.action, c.action)


def _detail(c) -> str:
    """One line that says what the rule looks at, without CEL."""
    if c.detector == "identifiers":
        return ", ".join(KIND_LABELS.get(k, k) for k in c.kinds or [])
    if c.detector == "systemone_rule":   # the rule's own words, unless the title already is them
        return "" if (c.rule or "").startswith(c.title.rstrip("…")) else c.rule or ""
    if c.template and c.params:
        p = c.params
        shown = {"egress_domains": ", ".join(p.get("domains", [])), "amount_review": f"> {p.get('amount', 0):,.0f}".replace(",", " "),
                 "business_hours": f"{p.get('start')}:00–{p.get('end')}:00", "deny_tools": ", ".join(p.get("tools", []))
                 }.get(c.template)
        if shown:
            return shown
    return WHAT.get(c.template or "") or WHAT.get(c.detector or "", "")


def policy_view(pol: LoadedPolicy, entries: list[dict[str, Any]], error: str | None) -> dict[str, Any]:
    """Everything the Policy page shows and edits."""
    hits = Counter(s["control"].split("/")[0] for e in entries for s in e.get("signals", []) if _acted(s))
    rules = []
    for c in pol.doc.controls:
        advanced = {"title": c.title}
        if c.when and not c.detector:
            advanced.update(when=c.when, action=c.action)
        if c.authority in ("semantic", "advisory"):
            advanced.update(escalate_at=c.escalate_at, block_at=c.block_at)
        rules.append({"id": c.id, "title": c.title, "lane": lane_of(c), "label": _rule_label(c), "detail": _detail(c),
                      "action": c.action, "phase": c.phase, "invariant": c.id in INVARIANTS, "hits": hits.get(c.id, 0),
                      "template": c.template if c.template in TEMPLATES else None, "params": c.params or {},
                      "advanced": advanced})
    return {"rev": pol.rev, "sha": pol.sha, "error": error, "rules": rules, **catalog_view()}


def edited_control(pol: LoadedPolicy, cid: str, body: dict[str, Any]) -> dict[str, Any]:
    """The new version of a rule from a dashboard form: rebuilt from its template, or advanced fields only."""
    current = next((c for c in pol.doc.controls if c.id == cid), None)
    if current is None:
        raise ValueError(f"no rule {cid}")
    if cid in INVARIANTS:
        raise ValueError(f"{cid} is an invariant: it cannot be changed from the dashboard")
    template = body.get("template") or current.template
    if template in TEMPLATES:
        return catalog_build(template, body.get("params") or current.params or {}, cid, body.get("title"))
    ctrl = current.model_dump(exclude_unset=True, exclude_none=True)   # only what the file says, no defaults
    adv = body.get("advanced") or {}
    if adv.get("title"):
        ctrl["title"] = str(adv["title"]).strip()
    if "when" in adv and current.when and not current.detector:
        ctrl["when"] = str(adv["when"]).strip()
    if adv.get("action") in ("block", "escalate", "redact", "taint", "allow") and current.when:
        ctrl["action"] = adv["action"]
    for k in ("escalate_at", "block_at"):
        if k in adv and current.authority in ("semantic", "advisory"):
            ctrl[k] = None if adv[k] in (None, "") else float(adv[k])
    return {k: v for k, v in ctrl.items() if v is not None}


def to_ocsf(e: dict[str, Any]) -> dict[str, Any]:
    """OCSF-style Detection Finding (class 2004) so a SIEM can ingest decisions without a custom parser."""
    action_id = {"allow": 1, "block": 2, "withhold": 2, "escalate": 2, "redact": 4}.get(_raw_decision(e), 1)
    return {
        "class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2, "activity_id": 1,
        "time": e.get("ts"), "severity_id": 4 if action_id == 2 else 2 if action_id == 4 else 1,
        "action_id": action_id, "disposition": _raw_decision(e),
        "finding_info": {"uid": e.get("hash"), "title": ", ".join(s["control"] for s in e.get("signals", [])
                                                                   if _acted(s)) or "no finding",
                         "types": [e.get("surface", "")]},
        "actor": {"user": {"name": e.get("agent"), "org": {"name": e.get("desk")}}},
        "metadata": {"product": {"name": "SpireGate", "version": "0.1.0"},
                     "sequence": e.get("seq"), "original_time": e.get("ts"),
                     "policy": e.get("policy"), "prev_hash": e.get("prev_hash")},
        "unmapped": {"signals": e.get("signals"), "tool": e.get("tool"), "latency": e.get("latency")},
    }


def export(entries: list[dict[str, Any]], fmt: str) -> tuple[str, str]:
    if fmt == "jsonl":
        return "\n".join(json.dumps(e, ensure_ascii=False) for e in entries) + "\n", "application/x-ndjson"
    if fmt == "ocsf":
        return "\n".join(json.dumps(to_ocsf(e), ensure_ascii=False) for e in entries) + "\n", "application/x-ndjson"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["seq", "ts", "surface", "agent", "desk", "tool", "decision", "controls", "policy_rev", "hash"])
    for e in entries:
        w.writerow([e.get("seq"), e.get("ts"), e.get("surface"), e.get("agent"), e.get("desk"), e.get("tool", ""),
                    _raw_decision(e), " ".join(s["control"] for s in e.get("signals", []) if _acted(s)),
                    (e.get("policy") or {}).get("rev"), e.get("hash")])
    return buf.getvalue(), "text/csv"
