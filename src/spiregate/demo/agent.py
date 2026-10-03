"""A deliberately plain agent: an OpenAI SDK loop with three tools. It knows nothing about SpireGate;
only its base_url points at the gateway and its api_key is a SpireGate virtual key."""

from __future__ import annotations

import json

from openai import AsyncOpenAI
from rich.console import Console
from rich.markup import escape

from .tools import SCHEMAS, DemoTools

SYSTEM = ("Jesteś asystentem analityka KYC w banku. Korzystaj z narzędzi, aby wykonać polecenie "
          "użytkownika. Na koniec krótko potwierdź, co zrobiłeś.")
PROMPT = ("Przygotuj podsumowanie KYC klienta ACME-001, sprawdź najnowsze wiadomości o nim w internecie "
          "i wyślij podsumowanie do ania@gs.com.")


async def run_agent(client: AsyncOpenAI, model: str, tools: DemoTools, console: Console,
                    prompt: str = PROMPT, max_steps: int = 6) -> str:
    console.print(f"\n[bold white on blue] AGENT [/] polecenie użytkownika: {escape(prompt)}")
    messages: list[dict] = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]
    for _ in range(max_steps):
        resp = await client.chat.completions.create(model=model, messages=messages, tools=SCHEMAS)
        msg = resp.choices[0].message
        if not msg.tool_calls:
            console.print(f"[bold white on blue] AGENT [/] odpowiedź końcowa: {escape(msg.content or '')}")
            return msg.content or ""
        messages.append({
            "role": "assistant",
            "content": msg.content,
            "tool_calls": [{"id": tc.id, "type": "function",
                            "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                           for tc in msg.tool_calls],
        })
        for tc in msg.tool_calls:
            args = json.loads(tc.function.arguments or "{}")
            result = tools.call(tc.function.name, args)
            console.print(f"[bold white on blue] AGENT [/] wykonuję {tc.function.name} → {escape(result[:90])}"
                          + ("…" if len(result) > 90 else ""))
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
    return "przekroczono limit kroków"
