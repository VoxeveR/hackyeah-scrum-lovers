"""Live event stream of the decision engine, for the dashboard's Silnik page.

Every request emits `start`, one `s1` pair (start/end) per System One call, and `end` with the decision,
latency split and cost. Subscribers (Server-Sent Events) get bounded queues: a slow or closed browser tab
drops events instead of slowing the engine down.
"""

from __future__ import annotations

import asyncio
import itertools
import time
from contextvars import ContextVar
from typing import Any

_REQUEST: ContextVar[dict[str, Any] | None] = ContextVar("spire_request", default=None)
# Set for synthetic traffic (load generator): marked in the audit log, kept off the console trace.
SIMULATED: ContextVar[bool] = ContextVar("spire_simulated", default=False)


class EventBus:
    def __init__(self, maxsize: int = 5000) -> None:
        self._subs: set[asyncio.Queue] = set()
        self._ids = itertools.count(1)
        self._maxsize = maxsize

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(self._maxsize)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def emit(self, event: dict[str, Any]) -> None:
        for q in list(self._subs):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    # ------------------------------------------------------------------ per-request context
    def begin(self, surface: str, agent: str | None, kind: str, label: str) -> dict[str, Any]:
        ctx = {"id": next(self._ids), "t": time.perf_counter(), "s1_calls": 0, "s1_ms": 0.0,
               "s1_tokens": 0, "s1_usd": 0.0, "s1_kinds": set(), "s1_p": None, "after_rule": False}
        _REQUEST.set(ctx)
        self.emit({"type": "start", "id": ctx["id"], "surface": surface, "agent": agent or "nieznany klucz",
                   "kind": kind, "label": label[:90], "sim": SIMULATED.get()})
        return ctx

    @staticmethod
    def current() -> dict[str, Any] | None:
        return _REQUEST.get()

    def end(self, decision: str, signals: list[dict[str, Any]], latency: dict[str, Any],
            cost: dict[str, Any] | None = None, seq: int | None = None) -> None:
        ctx = _REQUEST.get()
        if ctx is None or ctx.get("done"):
            return
        ctx["done"] = True
        total = round((time.perf_counter() - ctx["t"]) * 1000, 2)
        upstream = float(latency.get("upstream_ms") or 0.0)
        acted = [s for s in signals if s.get("action") not in (None, "allow")]
        model_usd = float((cost or {}).get("usd") or 0.0)
        self.emit({
            "type": "end", "id": ctx["id"], "seq": seq,
            "decision": "allow" if decision in ("label", "upstream_error") else decision,
            "controls": [s.get("control") for s in acted][:6],
            "reason": (acted[0].get("reason") or "")[:160] if acted else "",
            "ms": total, "s1_ms": round(ctx["s1_ms"], 1), "upstream_ms": upstream,
            "model_called": "upstream_ms" in latency,  # a fast (stub) model can answer in 0.0 ms
            "t0_ms": round(max(0.0, total - ctx["s1_ms"] - upstream), 2),
            "s1_calls": ctx["s1_calls"], "s1_tokens": ctx["s1_tokens"], "s1_usd": ctx["s1_usd"],
            # verify: System One checked what a deterministic rule may have missed; jev: a judgement only it makes
            "s1_kinds": sorted(ctx["s1_kinds"]), "s1_p": ctx["s1_p"], "s1_after_rule": ctx["after_rule"],
            "model_usd": model_usd, "usd": ctx["s1_usd"] + model_usd,
        })

    def system_one(self, event: dict[str, Any]) -> None:
        """Called by the System One client at the start and end of every question."""
        ctx = _REQUEST.get()
        if ctx is None:
            return
        ctx["s1_kinds"].update(event.get("kinds") or [])
        ctx["after_rule"] = ctx["after_rule"] or bool(event.get("after_rule"))
        probs = [p for p in (event.get("p") or {}).values() if isinstance(p, (int, float))]
        if probs:  # the highest risk System One saw in this request
            ctx["s1_p"] = max(probs + ([ctx["s1_p"]] if ctx["s1_p"] is not None else []))
        if event.get("state") == "end":
            ctx["s1_calls"] += 1
            ctx["s1_ms"] += float(event.get("ms") or 0.0)
        self.emit({"type": "s1", "id": ctx["id"], **event})

    @staticmethod
    def add_s1_cost(input_tokens: int, usd: float) -> None:
        ctx = _REQUEST.get()
        if ctx is not None:
            ctx["s1_tokens"] += input_tokens
            ctx["s1_usd"] += usd
