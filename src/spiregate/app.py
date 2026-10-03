"""HTTP surface: an OpenAI-compatible /v1/chat/completions that any agent can point its base_url at."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from . import admin as adm

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
DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard"


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


def create_app(gateway: Gateway, admin_token: str | None = None) -> FastAPI:
    app = FastAPI(title="SpireGate", version="0.1.0")
    # The admin plane has its own token; an agent's virtual key never opens it.
    app.state.admin_token = admin_token or os.environ.get("SPIRE_ADMIN_TOKEN") or secrets.token_urlsafe(12)
    verify_cache = adm.AuditVerifyCache(gateway.audit.path)

    @app.middleware("http")
    async def no_stale_dashboard(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/ui"):
            response.headers["Cache-Control"] = "no-cache"  # always revalidate, so a redeploy shows up at once
        return response

    def require_admin(request: Request) -> None:
        given = request.headers.get("authorization", "").removeprefix("Bearer ").strip() or request.query_params.get("token", "")
        if not secrets.compare_digest(given, app.state.admin_token):
            raise HTTPException(status_code=401, detail="SpireGate: wymagany token administratora")

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

    # ------------------------------------------------------------------ admin plane (dashboard)
    @app.get("/v1/admin/summary", dependencies=[Depends(require_admin)])
    async def admin_summary() -> dict:
        pol = gateway.store.get()
        return adm.summarize(gateway.audit.tail(2000), pol, gateway.store, verify_cache.get())

    @app.get("/v1/admin/events", dependencies=[Depends(require_admin)])
    async def admin_events(after: int = 0, limit: int = 200) -> dict:
        entries = [e for e in gateway.audit.tail(2000) if e["seq"] > after]
        return {"entries": entries[-limit:]}

    @app.get("/v1/admin/controls", dependencies=[Depends(require_admin)])
    async def admin_controls() -> dict:
        pol = gateway.store.get()
        return {"controls": adm.controls_view(pol, gateway.audit.tail(2000)), "profile": pol.profile_name,
                "profiles": list(pol.doc.profiles), "rev": pol.rev, "sha": pol.sha, "error": gateway.store.last_error}

    @app.post("/v1/admin/controls/{control_id}", dependencies=[Depends(require_admin)])
    async def admin_set_mode(control_id: str, request: Request) -> JSONResponse:
        body = await request.json()
        try:
            adm.edit_policy(gateway.store.path, control_id=control_id, mode=body.get("mode"))
        except ValueError as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        pol = gateway.store.get()
        return JSONResponse({"ok": gateway.store.last_error is None, "rev": pol.rev, "sha": pol.sha,
                             "error": gateway.store.last_error})

    @app.post("/v1/admin/profile", dependencies=[Depends(require_admin)])
    async def admin_set_profile(request: Request) -> JSONResponse:
        body = await request.json()
        try:
            adm.edit_policy(gateway.store.path, profile=body.get("profile"))
        except ValueError as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        pol = gateway.store.get()
        return JSONResponse({"ok": gateway.store.last_error is None, "rev": pol.rev, "profile": pol.profile_name})

    @app.get("/v1/admin/identities", dependencies=[Depends(require_admin)])
    async def admin_identities() -> dict:
        pol = gateway.store.get()
        return {"identities": [{"key": k, **v.model_dump()} for k, v in pol.doc.identities.items()],
                "tools": sorted(k for k in pol.doc.tools if k != "*")}

    @app.post("/v1/admin/playground", dependencies=[Depends(require_admin)])
    async def admin_playground(request: Request) -> dict:
        """Judges' ad-hoc checks: the real decision path, with the trace it produced."""
        body = await request.json()
        start = len(gateway.tracer.lines)
        req = {"phase": body.get("phase", "pre"), "session_id": body.get("session_id") or "playground",
               "tool": body.get("tool"), "args": body.get("args") or {}, "result": body.get("result"),
               "user_request": body.get("user_request"), "cwd": str(ROOT / "demo" / "claude-code")}
        out = await gateway.decide(body.get("agent_key"), req, surface="playground")
        return {**out, "trace": gateway.tracer.lines[start:]}

    @app.get("/v1/admin/audit/verify", dependencies=[Depends(require_admin)])
    async def admin_verify() -> dict:
        ok, msg = verify_cache.get()
        return {"ok": ok, "message": msg}

    @app.get("/v1/admin/audit/export", dependencies=[Depends(require_admin)])
    async def admin_export(fmt: str = "jsonl") -> Response:
        if fmt not in ("jsonl", "csv", "ocsf"):
            raise HTTPException(status_code=400, detail="fmt: jsonl | csv | ocsf")
        body, media = adm.export(gateway.audit.tail(100000), fmt)
        ext = {"jsonl": "jsonl", "csv": "csv", "ocsf": "ocsf.jsonl"}[fmt]
        return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="spiregate-audit.{ext}"'})

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse("/ui/")

    if DASHBOARD_DIR.exists():
        app.mount("/ui", StaticFiles(directory=DASHBOARD_DIR, html=True), name="ui")

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
