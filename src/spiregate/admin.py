"""Admin plane for the dashboard: analytics over the audit log, guarded policy edits, playground, exports.

Everything here reads the same hash-chained audit log, so management and SecOps never see different numbers.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .audit import verify
from .policy import INVARIANTS, LoadedPolicy, PolicyStore, load_policy
from .systemone import SystemOneClient

DECISIONS = ("allow", "redact", "withhold", "escalate", "block")
_ACTIONS_THAT_COUNT = {"block", "redact", "withhold", "escalate", "taint"}


def _decision(entry: dict[str, Any]) -> str:
    d = entry.get("decision", "allow")
    return "allow" if d in ("label", "upstream_error") else d


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
        self._result: tuple[bool, str] = (True, "brak logu")

    def get(self) -> tuple[bool, str]:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return True, "brak logu"
        key = (st.st_size, st.st_mtime_ns)
        if key != self._key:
            self._key, self._result = key, verify(self.path)
        return self._result


def summarize(entries: list[dict[str, Any]], pol: LoadedPolicy, store: PolicyStore,
              audit_state: tuple[bool, str], now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    kpis = Counter(_decision(e) for e in entries)
    would = sum(1 for e in entries for s in e.get("signals", []) if not s.get("enforced")
                and s.get("action") in _ACTIONS_THAT_COUNT)

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

    titles = {c.id: c.title for c in pol.doc.controls}
    by_control: dict[str, dict[str, Any]] = {}
    for e in entries:
        for s in e.get("signals", []):
            if s.get("action") not in _ACTIONS_THAT_COUNT:
                continue
            cid = s.get("control", "?")
            row = by_control.setdefault(cid, {"id": cid, "title": titles.get(cid.split("/")[0], ""),
                                              "enforced": 0, "would": 0, "actions": Counter()})
            row["enforced" if s.get("enforced") else "would"] += 1
            row["actions"][s["action"]] += 1
    controls = sorted(({**r, "actions": dict(r["actions"]), "count": r["enforced"] + r["would"]}
                       for r in by_control.values()), key=lambda r: -r["count"])

    agents: dict[str, Counter] = defaultdict(Counter)
    desks: dict[str, str] = {}
    for e in entries:
        a = e.get("agent") or "nieznany klucz"
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
    enforce = [c for c in pol.doc.controls if pol.mode_of(c) == "enforce"]
    checks = [
        {"name": "Inwarianty", "ok": True, "detail": f"{len(INVARIANTS)} reguły, zawsze enforce"},
        {"name": "Tryb enforce", "ok": len(enforce) >= len(pol.doc.controls) - 2,
         "detail": f"{len(enforce)} z {len(pol.doc.controls)} kontrolek"},
        {"name": "Polityka", "ok": store.last_error is None,
         "detail": "odrzucona edycja" if store.last_error else f"rev {pol.rev} · wczytana"},
        {"name": "Łańcuch audytu", "ok": audit_state[0], "detail": "nienaruszony" if audit_state[0] else "naruszony"},
        {"name": "System One", "ok": backend == "jev", "detail": note or f"{backend} · online"},
        {"name": "Profil", "ok": pol.profile_name != "dev", "detail": pol.profile_name},
    ]
    weights = [25, 20, 15, 20, 10, 10]
    score = sum(w for w, c in zip(weights, checks) if c["ok"])

    return {
        "generated_at": now.isoformat(),
        "policy": {"rev": pol.rev, "sha": pol.sha, "profile": pol.profile_name, "profiles": list(pol.doc.profiles),
                   "error": store.last_error, "events": store.events[-8:]},
        "kpis": {"total": len(entries), **{d: kpis.get(d, 0) for d in DECISIONS}, "would": would},
        "timeline": timeline,
        "controls": controls[:8],
        "agents": by_agent[:8],
        "latency": latency,
        "systemone": {"backend": backend, "note": note, "model": pol.doc.systemone.model,
                      "calls": sum(s1_backends.values()), "by_backend": dict(s1_backends)},
        "tokens": dict(tokens),
        "audit": {"ok": audit_state[0], "message": audit_state[1]},
        "posture": {"score": score, "checks": checks},
    }


def controls_view(pol: LoadedPolicy, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hits = Counter(s["control"].split("/")[0] for e in entries for s in e.get("signals", [])
                   if s.get("action") in _ACTIONS_THAT_COUNT)
    out = []
    for c in pol.doc.controls:
        out.append({
            "id": c.id, "title": c.title, "phase": c.phase, "action": c.action, "authority": c.authority,
            "mode": c.mode, "effective_mode": pol.mode_of(c), "invariant": c.id in INVARIANTS,
            "detector": c.detector, "when": c.when, "kinds": c.kinds,
            "verify": c.verify.model_dump() if c.verify else None, "hits": hits.get(c.id, 0),
        })
    return out


def edit_policy(path: Path, *, control_id: str | None = None, mode: str | None = None,
                profile: str | None = None) -> None:
    """Line-level edit: only the changed lines differ, comments and alignment stay exactly as written.
    The result is validated BEFORE it is written; an invalid edit never reaches the file."""
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if control_id is not None:
        if control_id in INVARIANTS:
            raise ValueError(f"{control_id} jest inwariantem i zawsze działa w trybie enforce")
        if mode not in ("enforce", "monitor", "off"):
            raise ValueError("mode musi być enforce, monitor albo off")
        lines = _set_control_mode(lines, control_id, mode)
    if profile is not None:
        lines = _replace_scalar(lines, "active_profile", profile)
    rev_line = next((ln for ln in lines if re.match(r"\s*policy_rev:\s*\d+", ln)), None)
    current = int(re.search(r"\d+", rev_line).group(0)) if rev_line else 0
    lines = _replace_scalar(lines, "policy_rev", str(current + 1))
    text = "".join(lines)
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
        tmp.write(text)
    try:
        load_policy(Path(tmp.name))  # raises with a readable message if the edit would break the policy
    finally:
        os.unlink(tmp.name)
    path.write_text(text, encoding="utf-8")


def _replace_scalar(lines: list[str], key: str, value: str) -> list[str]:
    rx = re.compile(rf"^(\s*{key}:\s*)([^\s#]+)(.*)$", re.S)
    for i, ln in enumerate(lines):
        m = rx.match(ln)
        if m:
            lines[i] = f"{m.group(1)}{value}{m.group(3)}"
            return lines
    raise ValueError(f"w polityce brakuje klucza {key}")


def _set_control_mode(lines: list[str], control_id: str, mode: str) -> list[str]:
    head = re.compile(rf"^(\s*)- id:\s*{re.escape(control_id)}\s*(#.*)?$")
    start = next((i for i, ln in enumerate(lines) if head.match(ln.rstrip("\n"))), None)
    if start is None:
        raise ValueError(f"nie ma kontrolki {control_id}")
    field_indent = len(head.match(lines[start].rstrip("\n")).group(1)) + 2
    end = start + 1
    while end < len(lines):  # the block ends at the next item or at anything indented less than its fields
        ln = lines[end]
        if ln.strip() and not ln.lstrip().startswith("#") and (len(ln) - len(ln.lstrip())) < field_indent:
            break
        end += 1
    own = re.compile(rf"^ {{{field_indent}}}mode:\s*\S+")  # the control's own mode, not verify.mode
    for i in range(start + 1, end):
        if own.match(lines[i]):
            lines[i] = re.sub(r"(mode:\s*)\S+", rf"\g<1>{mode}", lines[i], count=1)
            return lines
    insert_at = next((i + 1 for i in range(start + 1, end) if re.match(rf"^ {{{field_indent}}}action:", lines[i])), start + 1)
    lines.insert(insert_at, " " * field_indent + f"mode: {mode}\n")
    return lines


def to_ocsf(e: dict[str, Any]) -> dict[str, Any]:
    """OCSF-style Detection Finding (class 2004) so a SIEM can ingest decisions without a custom parser."""
    action_id = {"allow": 1, "block": 2, "withhold": 2, "escalate": 2, "redact": 4}.get(_decision(e), 1)
    return {
        "class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2, "activity_id": 1,
        "time": e.get("ts"), "severity_id": 4 if action_id == 2 else 2 if action_id == 4 else 1,
        "action_id": action_id, "disposition": _decision(e),
        "finding_info": {"uid": e.get("hash"), "title": ", ".join(s["control"] for s in e.get("signals", [])
                                                                   if s.get("enforced")) or "no finding",
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
                    _decision(e), " ".join(s["control"] for s in e.get("signals", []) if s.get("enforced")),
                    (e.get("policy") or {}).get("rev"), e.get("hash")])
    return buf.getvalue(), "text/csv"
