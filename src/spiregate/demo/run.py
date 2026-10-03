"""Runs the KYC scenario end to end and prints both sides: what the agent does, what the gateway decides."""

from __future__ import annotations

from pathlib import Path

import httpx
from openai import AsyncOpenAI
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from ..app import build_gateway, create_app
from ..trace import Tracer
from .agent import PROMPT, run_agent
from .tools import DemoTools

AGENT_KEY = "spire-demo-kyc"  # SpireGate virtual key from policy.identities, not an OpenAI key


async def run_demo(scenario: str, model: str, policy: Path, gateway_url: str | None = None,
                   prompt: str | None = None) -> DemoTools:
    console = Console()
    console.print(Panel.fit(
        f"Scenariusz: [bold]{scenario}[/]   model: [bold]{model}[/]\n"
        + ("Strona z wiadomościami zawiera UKRYTĄ instrukcję dla AI." if scenario == "attack"
           else "Strona z wiadomościami jest zwykłym artykułem."),
        title="SpireGate · demo KYC"))
    tools = DemoTools(scenario=scenario)
    if gateway_url:
        client = AsyncOpenAI(base_url=gateway_url.rstrip("/") + "/v1", api_key=AGENT_KEY)
    else:
        gateway = build_gateway(policy, tracer=Tracer(console))
        http = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(gateway)), base_url="http://spiregate")
        client = AsyncOpenAI(base_url="http://spiregate/v1", api_key=AGENT_KEY, http_client=http)

    await run_agent(client, model, tools, console, prompt=prompt or PROMPT)

    console.print()
    if tools.outbox:
        for mail in tools.outbox:
            console.print(Panel(escape(mail["body"]), title=f"wysłany e-mail → {escape(mail['to'])}", border_style="green"))
    else:
        console.print(Panel("Żaden e-mail nie wyszedł.", title="skrzynka nadawcza", border_style="red"))
    console.print("[dim]Log audytowy: uv run spiregate audit show  ·  weryfikacja łańcucha: uv run spiregate audit verify[/]")
    return tools
