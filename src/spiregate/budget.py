"""Budget and resource governance: tokens, USD, GPU-seconds, requests and tool calls per scope, plus a
loop breaker. Sliding windows in memory (a shared store such as Redis would replace this in production).

Reserve-then-reconcile: before a model call the worst case (estimated input + max output) is reserved on
every matching budget, like a card authorisation hold; after the response the hold is replaced by the
actual usage. Concurrent agents therefore cannot overspend a budget between check and use.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from types import SimpleNamespace
from typing import Any

WINDOWS = {"minute": 60, "hour": 3600, "day": 86400}
METRICS = ("usd", "tokens", "requests", "tool_calls")


@dataclass
class Violation:
    budget_id: str
    scope: str
    metric: str
    used: float
    requested: float
    limit: float
    window: str
    reset_s: int

    def message(self) -> str:
        unit = {"usd": "USD", "tokens": "tokens", "requests": "requests", "tool_calls": "tool calls"}.get(self.metric, self.metric)
        used = f"{self.used:.4f}" if self.metric == "usd" else f"{self.used:.0f}"
        limit = f"{self.limit:.4f}" if self.metric == "usd" else f"{self.limit:.0f}"
        return (f"{self.budget_id}: limit {limit} {unit} per {self.window} for {self.scope} "
                f"(used {used}, this request +{self.requested:g}); renews in about {self.reset_s} s")


@dataclass
class Hold:
    entries: list[tuple[list, str]] = field(default_factory=list)  # ([ts, value], metric)


class BudgetLedger:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._meters: dict[tuple[str, str, str], deque] = defaultdict(deque)  # (budget_id, scope, metric) -> [ts, value]
        self._session_calls: dict[tuple[str, str], int] = defaultdict(int)
        self._recent_calls: dict[tuple[str, str], deque] = defaultdict(deque)  # (agent, session) -> [ts, fingerprint]
        self._tripped: dict[tuple[str, str, str], tuple[float, str]] = {}     # (agent, session, fingerprint) -> (until, tool)
        self.control_overhead = {"calls": 0, "input_tokens": 0, "usd": 0.0}

    # ------------------------------------------------------------------ scopes
    @staticmethod
    def scopes(identity) -> list[str]:
        return ["org", f"desk:{identity.desk}", f"agent:{identity.agent_id}"]

    @staticmethod
    def matching(budgets, identity) -> list[tuple[Any, str]]:
        """(rule, concrete scope) for every budget rule that applies to this identity."""
        out = []
        for rule in budgets.rules:
            for scope in BudgetLedger.scopes(identity):
                kind = scope.split(":", 1)[0]
                if rule.scope == scope or (rule.scope.startswith(kind) and fnmatch.fnmatchcase(scope, rule.scope)):
                    out.append((rule, scope))
        return out

    def _used(self, key, window_s: int, now: float) -> float:
        q = self._meters[key]
        while q and q[0][0] <= now - window_s:
            q.popleft()
        return sum(v for _, v in q)

    def _reset_in(self, key, window_s: int, now: float) -> int:
        q = self._meters[key]
        return max(1, int(q[0][0] + window_s - now)) if q else window_s

    # ------------------------------------------------------------------ model calls
    def reserve(self, budgets, identity, demand: dict[str, float], now: float | None = None
                ) -> tuple[list[Violation], Hold | None]:
        """Checks every matching rule; reserves the demand only if none would be exceeded."""
        now = now or time.time()
        with self._lock:
            violations = []
            for rule, scope in self.matching(budgets, identity):
                window_s = WINDOWS[rule.window]
                for metric in METRICS:
                    limit = getattr(rule, metric, None)
                    want = demand.get(metric, 0.0)
                    if limit is None or not want:
                        continue
                    key = (rule.id, scope, metric)
                    used = self._used(key, window_s, now)
                    if used + want > limit + 1e-12:
                        violations.append(Violation(rule.id, scope, metric, used, round(want, 6), limit, rule.window,
                                                    self._reset_in(key, window_s, now)))
            if violations:
                return violations, None
            hold = Hold()
            for rule, scope in self.matching(budgets, identity):
                for metric in METRICS:
                    if getattr(rule, metric, None) is not None and demand.get(metric):
                        entry = [now, demand[metric]]
                        self._meters[(rule.id, scope, metric)].append(entry)
                        hold.entries.append((entry, metric))
            return [], hold

    def reconcile(self, hold: Hold | None, actual: dict[str, float]) -> None:
        """Replaces each reserved amount with the actual one (or releases it if the call failed)."""
        if hold is None:
            return
        with self._lock:
            for entry, metric in hold.entries:
                if metric in actual:  # e.g. requests stay counted even when the call failed
                    entry[1] = actual[metric]

    # ------------------------------------------------------------------ tool calls
    @staticmethod
    def fingerprint(tool: str, args: dict[str, Any]) -> str:
        return hashlib.sha256(f"{tool}\x00{json.dumps(args, sort_keys=True, ensure_ascii=False)}".encode()).hexdigest()[:16]

    def tool_call(self, budgets, identity, session_id: str | None, tool: str, args: dict[str, Any],
                  now: float | None = None) -> list[tuple[str, str]]:
        """Counts a tool call; returns [(control_id, reason)] for every limit it breaks (loop, per-session cap).

        The loop breaker stops only the repeated call (same tool, same arguments): the agent can still do
        something different, which is what a stuck agent needs, while a legitimate session keeps working."""
        now = now or time.time()
        key = (identity.agent_id, session_id or "_agent")
        fp = self.fingerprint(tool, args)
        out: list[tuple[str, str]] = []
        loops = budgets.loops
        with self._lock:
            until = self._tripped.get((*key, fp))
            if until and until[0] > now:
                out.append(("LOOP-001", f"loop breaker: the same {tool} call is blocked for another "
                                        f"{int(until[0] - now)} s; try a different approach"))
                return out
            q = self._recent_calls[key]
            q.append((now, fp))
            while q and q[0][0] <= now - loops.window_s:
                q.popleft()
            same = sum(1 for _, f in q if f == fp)
            if same >= loops.same_call_repeats:
                self._tripped[(*key, fp)] = (now + loops.cooldown_s, tool)
                out.append(("LOOP-001", f"{tool} with the same arguments {same}× in {loops.window_s} s: "
                                        f"this call is blocked for {loops.cooldown_s} s"))
            self._session_calls[key] += 1
        caps = [r.tool_calls_per_session for r, _ in self.matching(budgets, identity) if r.tool_calls_per_session]
        if caps and self._session_calls[key] > min(caps):
            out.append(("BUDGET-SESSION", f"limit of {min(caps)} tool calls per session exceeded"))
        violations, _ = self.reserve(budgets, identity, {"tool_calls": 1}, now)
        out += [(v.budget_id, v.message()) for v in violations]
        return out

    def replay(self, entries: list[dict[str, Any]], budgets, now: float | None = None) -> int:
        """Rebuilds the model-spend meters from the audit log, so restarting the gateway never hands out a
        fresh allowance. Tool-call windows are short (minutes) and are not replayed."""
        now = now or time.time()
        horizon = now - max(WINDOWS[r.window] for r in budgets.rules) if budgets.rules else now
        n = 0
        with self._lock:
            for e in entries:
                cost, agent = e.get("cost"), e.get("agent")
                if not cost or not agent or e.get("surface") != "proxy":
                    continue
                try:
                    ts = datetime.fromisoformat(e["ts"]).timestamp()
                except (KeyError, ValueError):
                    continue
                if ts <= horizon:
                    continue
                who = SimpleNamespace(agent_id=agent, desk=e.get("desk") or "")
                spent = {"usd": cost.get("usd", 0.0), "tokens": cost.get("tokens", 0), "requests": 1}
                for rule, scope in self.matching(budgets, who):
                    for metric in ("usd", "tokens", "requests"):
                        if getattr(rule, metric, None) is not None and spent[metric]:
                            self._meters[(rule.id, scope, metric)].append([ts, spent[metric]])
                n += 1
            for q in self._meters.values():  # audit order is time order, but keep the invariant explicit
                q_sorted = sorted(q, key=lambda x: x[0])
                q.clear()
                q.extend(q_sorted)
        return n

    def reset_session(self, agent_id: str, session_id: str) -> None:
        """A new conversation starts with clean loop and per-session counters (spend budgets are untouched)."""
        key = (agent_id, session_id)
        with self._lock:
            self._recent_calls.pop(key, None)
            self._session_calls.pop(key, None)
            for k in [k for k in self._tripped if k[:2] == key]:
                del self._tripped[k]

    def add_control_overhead(self, input_tokens: int, usd_per_mtok: float) -> None:
        with self._lock:
            self.control_overhead["calls"] += 1
            self.control_overhead["input_tokens"] += input_tokens
            self.control_overhead["usd"] += input_tokens / 1e6 * usd_per_mtok

    # ------------------------------------------------------------------ reporting
    def snapshot(self, budgets, now: float | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        now = now or time.time()
        rows = []
        with self._lock:
            scopes_seen = {(bid, scope) for bid, scope, _ in self._meters}
            for rule in budgets.rules:
                window_s = WINDOWS[rule.window]
                for bid, scope in sorted(scopes_seen):
                    if bid != rule.id:
                        continue
                    metrics = {}
                    for metric in METRICS:
                        limit = getattr(rule, metric, None)
                        if limit is not None:
                            used = self._used((rule.id, scope, metric), window_s, now)
                            metrics[metric] = {"used": round(used, 6), "limit": limit,
                                               "pct": round(100 * used / limit, 1) if limit else 0}
                    rows.append({"id": rule.id, "scope": scope, "window": rule.window, "metrics": metrics})
                if not any(r["id"] == rule.id for r in rows):  # rule exists but nothing spent yet
                    rows.append({"id": rule.id, "scope": rule.scope, "window": rule.window,
                                 "metrics": {m: {"used": 0, "limit": getattr(rule, m), "pct": 0}
                                             for m in METRICS if getattr(rule, m, None) is not None}})
            tripped = [{"agent": a, "session": s, "tool": t, "until_s": int(u - now)}
                       for (a, s, _), (u, t) in self._tripped.items() if u > now]
        return rows, tripped
