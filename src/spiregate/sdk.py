"""Tiny client for in-house apps that run their own tools:

    guard = Guard(key="spire-demo-sdk", session_id="payments-42")
    guard.prompt("Zapłać fakturę INV-7 dla ACME")

    @guard.tool("send_email")
    def send_email(to, subject, body): ...

Every call is checked before it runs; its result is reported afterwards and returned masked
(e.g. no PESEL) if the policy says so. Fail-closed: if the gateway cannot be reached, the tool does not run.
"""

from __future__ import annotations

import functools
import json
import uuid
from typing import Any, Callable

import httpx


class Blocked(RuntimeError):
    def __init__(self, decision: str, reasons: list[str]):
        super().__init__(f"SpireGate: {decision}: {'; '.join(reasons) or 'gateway niedostępny'}")
        self.decision = decision
        self.reasons = reasons


class Guard:
    def __init__(self, key: str, url: str = "http://127.0.0.1:8787", session_id: str | None = None,
                 client: httpx.Client | None = None, timeout: float = 4.0):
        self.key = key
        self.url = url.rstrip("/")
        self.session_id = session_id or uuid.uuid4().hex
        self._http = client or httpx.Client(timeout=timeout)

    def _decide(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            r = self._http.post(f"{self.url}/v1/decide", json={"session_id": self.session_id, **payload},
                                headers={"Authorization": f"Bearer {self.key}"})
            r.raise_for_status()
            return r.json()
        except httpx.HTTPError as e:
            raise Blocked("block", [f"gateway niedostępny ({type(e).__name__})"]) from e

    def prompt(self, user_request: str) -> None:
        self._decide({"phase": "prompt", "user_request": user_request})

    def check(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        out = self._decide({"phase": "pre", "tool": tool, "args": args})
        if out["decision"] != "allow":
            raise Blocked(out["decision"], out.get("reasons", []))
        return out

    def report(self, tool: str, args: dict[str, Any], result: Any) -> Any:
        """Reports a result and returns what the caller may see (PII masked per policy)."""
        out = self._decide({"phase": "post", "tool": tool, "args": args,
                            "result": json.loads(json.dumps(result, ensure_ascii=False, default=str))})
        masked = out.get("result_redacted")
        return result if masked is None else masked

    def tool(self, name: str | None = None) -> Callable:
        def wrap(fn: Callable) -> Callable:
            tool_name = name or fn.__name__

            @functools.wraps(fn)
            def inner(**kwargs: Any) -> Any:
                self.check(tool_name, kwargs)
                return self.report(tool_name, kwargs, fn(**kwargs))
            return inner
        return wrap
