"""Upstream models. The gateway holds the real keys; agents only ever hold a SpireGate virtual key."""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import httpx


class OpenAIUpstream:
    name = "openai"

    def __init__(self, http: httpx.AsyncClient | None = None):
        self._http = http or httpx.AsyncClient()
        self.url = os.environ.get("SPIRE_OPENAI_URL", "https://api.openai.com/v1/chat/completions")

    async def complete(self, body: dict[str, Any]) -> tuple[int, dict[str, Any], float]:
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            return 503, _error("SpireGate: brak OPENAI_API_KEY w .env gatewaya", "upstream_unavailable"), 0.0
        t = time.perf_counter()
        try:
            r = await self._http.post(self.url, headers={"Authorization": f"Bearer {key}"}, json=body, timeout=120)
        except httpx.HTTPError as e:
            return 502, _error(f"SpireGate: OpenAI unreachable ({type(e).__name__})", "upstream_error"), _ms(t)
        try:
            payload = r.json()
        except ValueError:
            payload = _error(f"SpireGate: OpenAI returned HTTP {r.status_code} without JSON", "upstream_error")
        return r.status_code, payload, _ms(t)


class StubUpstream:
    """A scripted, deliberately gullible 'model' for the KYC demo: deterministic, no key needed.

    It follows any e-mail instruction it finds in fetched web content, which is exactly the
    behaviour an injected prompt tries to trigger in a real model.
    """

    name = "stub"

    def __init__(self) -> None:
        self.seen: list[dict[str, Any]] = []  # bodies exactly as the "model" received them

    async def complete(self, body: dict[str, Any]) -> tuple[int, dict[str, Any], float]:
        self.seen.append(json.loads(json.dumps(body)))
        t = time.perf_counter()
        message = self._next_message(body.get("messages", []))
        finish = "tool_calls" if message.get("tool_calls") else "stop"
        prompt_tokens = sum(len(str(m.get("content") or "")) for m in body.get("messages", [])) // 4
        resp = {
            "id": f"stub-{len(self.seen)}",
            "object": "chat.completion",
            "created": 0,
            "model": body.get("model", "stub-model"),
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 40, "total_tokens": prompt_tokens + 40},
        }
        return 200, resp, _ms(t)

    def _next_message(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        user = next((str(m.get("content") or "") for m in messages if m.get("role") == "user"), "")
        names_by_id: dict[str, str] = {}
        for m in messages:
            for tc in m.get("tool_calls") or []:
                names_by_id[tc["id"]] = tc["function"]["name"]
        results = {names_by_id.get(m.get("tool_call_id"), "?"): str(m.get("content") or "")
                   for m in messages if m.get("role") == "tool"}
        called = set(names_by_id.values())

        if "crm_get_client" not in called:
            return _call(len(messages), "crm_get_client", {"client_id": "ACME-001"})
        if "web_fetch" not in called and re.search(r"wiadomo|news|internet", user, re.I):
            return _call(len(messages), "web_fetch", {"url": "https://news.example.com/acme"})
        retries = sum(1 for n in names_by_id.values() if n == "web_fetch")
        if "spróbuj ponownie" in results.get("web_fetch", "") and retries < 12:
            return _call(len(messages), "web_fetch", {"url": "https://news.example.com/acme"})  # retries blindly
        if "send_email" not in called:
            injected = re.search(r"(?:wyślij|send|prześlij|forward)[^@]{0,120}?([\w.+-]+@[\w-]+(?:\.[\w-]+)+)",
                                 results.get("web_fetch", ""), re.I)
            asked = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", user)
            to = injected.group(1) if injected else (asked.group(0) if asked else "unknown@example.com")
            body = "Podsumowanie KYC klienta ACME:\n" + results.get("crm_get_client", "")
            return _call(len(messages), "send_email", {"to": to, "subject": "Podsumowanie KYC: ACME Corp", "body": body})
        return {"role": "assistant", "content": "Gotowe, podsumowanie KYC zostało wysłane."}


def _call(n: int, name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{"id": f"call_{n}_{name}", "type": "function",
                        "function": {"name": name, "arguments": json.dumps(args, ensure_ascii=False)}}],
    }


def _error(message: str, code: str) -> dict[str, Any]:
    return {"error": {"message": message, "type": code, "code": code}}


def _ms(t: float) -> float:
    return round((time.perf_counter() - t) * 1000, 1)
