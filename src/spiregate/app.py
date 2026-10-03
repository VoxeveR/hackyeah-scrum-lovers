"""HTTP surface: an OpenAI-compatible /v1/chat/completions that any agent can point its base_url at."""

from __future__ import annotations

import os
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .actions import protected_roots
from .audit import AuditLog
from .core import Gateway
from .policy import PolicyStore
from .systemone import SystemOneClient
from .trace import Tracer
from .upstream import OpenAIUpstream, StubUpstream

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY = ROOT / "policy" / "spiregate.policy.yaml"
DEFAULT_AUDIT = ROOT / "var" / "audit.jsonl"


def load_dotenv(path: Path = ROOT / ".env") -> None:
    """Minimal .env loader; never overrides variables already set in the environment."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def build_gateway(policy_path: Path = DEFAULT_POLICY, audit_path: Path = DEFAULT_AUDIT,
                  tracer: Tracer | None = None, stub: StubUpstream | None = None) -> Gateway:
    http = httpx.AsyncClient()
    store = PolicyStore(policy_path)
    return Gateway(
        store=store,
        audit=AuditLog(audit_path),
        tracer=tracer or Tracer(),
        upstreams={"openai": OpenAIUpstream(http), "stub": stub or StubUpstream()},
        systemone=SystemOneClient(http),
        protected=protected_roots(ROOT, store.current.doc.org.get("protected_paths", [])),
    )


def create_app(gateway: Gateway) -> FastAPI:
    app = FastAPI(title="SpireGate", version="0.1.0")

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        body = await request.json()
        status, payload = await gateway.chat(_key(request), body)
        return JSONResponse(payload, status_code=status)

    @app.post("/v1/decide")
    async def decide(request: Request) -> JSONResponse:
        """SDK surface: {phase: prompt|pre|post, session_id, tool, args, result, user_request, cwd}."""
        return JSONResponse(await gateway.decide(_key(request), await request.json(), surface="sdk"))

    @app.post("/v1/hooks/{fmt}")
    async def hook(fmt: str, request: Request) -> JSONResponse:
        """Hook surface: body is the raw hook event; reply tells spire_hook.py what to print and how to exit."""
        if fmt not in ("claude-code", "codex"):
            return JSONResponse({"stdout": "", "stderr": f"SpireGate: nieznany format hooka {fmt}\n", "exit": 2})
        try:
            event = await request.json()
        except ValueError:
            return JSONResponse({"stdout": "", "stderr": "SpireGate: niepoprawny JSON z hooka\n", "exit": 2})
        return JSONResponse(await gateway.hook(_key(request), fmt, event))

    @app.get("/v1/models")
    async def models() -> dict:
        pol = gateway.store.get()
        return {"object": "list", "data": [{"id": m.id, "object": "model", "owned_by": m.upstream} for m in pol.doc.models]}

    @app.get("/v1/audit")
    async def audit(n: int = 50) -> dict:
        return {"entries": gateway.audit.tail(n)}

    @app.get("/healthz")
    async def healthz() -> dict:
        pol = gateway.store.get()
        return {"ok": True, "policy_rev": pol.rev, "policy_sha": pol.sha, "profile": pol.profile_name,
                "policy_error": gateway.store.last_error}

    return app


def _key(request: Request) -> str | None:
    return request.headers.get("authorization", "").removeprefix("Bearer ").strip() or None
