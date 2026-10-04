"""HTTP surface: an OpenAI-compatible /v1/chat/completions that any agent can point its base_url at."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from contextlib import contextmanager
from datetime import date
from pathlib import Path
from typing import Iterator

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import admin as adm
from . import catalog, importer, loadgen
from . import policy_edit as policy_editor

from .actions import protected_roots
from .analyst import Analyst
from .audit import AuditLog
from .core import Gateway
from .events import SIMULATED
from .feed import FeedStore
from .feed import view as feed_view
from .policy import PolicyStore
from .systemone import SystemOneClient
from .trace import Tracer
from .upstream import OpenAIUpstream, StubUpstream

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY = ROOT / "policy" / "spiregate.policy.yaml"
DEFAULT_AUDIT = ROOT / "var" / "audit.jsonl"
DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard"
MAX_RUN_S = 15.0   # the dashboard's Start button: simulated traffic stops by itself after this long


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
        # last good signed bundle next to the audit log: a restart without the feed server keeps the signatures
        feed=FeedStore(ROOT, cache_path=audit_path.parent / "feed-cache.json"),
    )


def create_app(gateway: Gateway, admin_token: str | None = None) -> FastAPI:
    app = FastAPI(title="SpireGate", version="0.1.0")
    # The admin plane has its own token; an agent's virtual key never opens it.
    app.state.admin_token = admin_token or os.environ.get("SPIRE_ADMIN_TOKEN") or secrets.token_urlsafe(12)
    app.state.loadgen = None
    app.state.loadgen_stop = None
    verify_cache = adm.AuditVerifyCache(gateway.audit.path)
    analyst = app.state.analyst = Analyst(gateway)   # background LLM analyst: off the request path, advisory only

    @app.middleware("http")
    async def analyst_tick(request: Request, call_next):
        response = await call_next(request)
        analyst.tick()   # every N decisions an assessment starts in the background; this response never waits for it
        return response

    @app.middleware("http")
    async def no_stale_dashboard(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/ui"):
            response.headers["Cache-Control"] = "no-cache"  # always revalidate, so a redeploy shows up at once
        return response

    def require_admin(request: Request) -> None:
        given = request.headers.get("authorization", "").removeprefix("Bearer ").strip() or request.query_params.get("token", "")
        if not secrets.compare_digest(given, app.state.admin_token):
            raise HTTPException(status_code=401, detail="SpireGate: admin token required")

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        body = await request.json()
        with _simulated(request):
            status, payload = await gateway.chat(_key(request), body)
        return JSONResponse(payload, status_code=status)

    @app.post("/v1/decide")
    async def decide(request: Request) -> JSONResponse:
        """SDK surface: {phase: prompt|pre|post, session_id, tool, args, result, user_request, cwd}."""
        body = await request.json()
        with _simulated(request):
            return JSONResponse(await gateway.decide(_key(request), body, surface="sdk"))

    @app.post("/v1/hooks/{fmt}")
    async def hook(fmt: str, request: Request) -> JSONResponse:
        """Hook surface: body is the raw hook event; reply tells spire_hook.py what to print and how to exit."""
        if fmt not in ("claude-code", "codex"):
            return JSONResponse({"stdout": "", "stderr": f"SpireGate: unknown hook format {fmt}\n", "exit": 2})
        try:
            event = await request.json()
        except ValueError:
            return JSONResponse({"stdout": "", "stderr": "SpireGate: invalid JSON from the hook\n", "exit": 2})
        with _simulated(request):
            return JSONResponse(await gateway.hook(_key(request), fmt, event))

    # ------------------------------------------------------------------ admin plane (dashboard)
    @app.get("/v1/admin/summary", dependencies=[Depends(require_admin)])
    async def admin_summary() -> dict:
        pol = gateway.store.get()
        return adm.summarize(gateway.audit.tail(2000), pol, gateway.store, verify_cache.get(), ledger=gateway.ledger,
                             feed=gateway.feed.status(pol.doc.feed))

    @app.get("/v1/admin/events", dependencies=[Depends(require_admin)])
    async def admin_events(after: int = 0, limit: int = 200) -> dict:
        entries = [e for e in gateway.audit.tail(2000) if e["seq"] > after]
        return {"entries": entries[-limit:]}

    # ------------------------------------------------------------------ policy editor (Polityka page)
    def policy_response(extra: dict | None = None) -> JSONResponse:
        pol = gateway.store.get()   # re-reads the file the edit just wrote
        return JSONResponse({**adm.policy_view(pol, gateway.audit.tail(2000), gateway.store.last_error), **(extra or {})})

    def policy_edit(fn) -> JSONResponse:
        try:
            fn()
        except ValueError as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        return policy_response({"ok": True})

    def taken_ids() -> set[str]:
        return policy_editor.ids(gateway.store.path)

    @app.get("/v1/admin/policy", dependencies=[Depends(require_admin)])
    async def admin_policy() -> JSONResponse:
        return policy_response()

    @app.post("/v1/admin/policy/rules", dependencies=[Depends(require_admin)])
    async def admin_rule_add(request: Request) -> JSONResponse:
        body = await request.json()

        def add():
            t = catalog.TEMPLATES.get(body.get("template"))
            if t is None:
                raise ValueError("choose a rule template")
            item = catalog.build(t.key, body.get("params") or {}, catalog.next_id(t.prefix, taken_ids()), body.get("title"))
            policy_editor.apply(gateway.store.path, add=[item])
        return policy_edit(add)

    @app.put("/v1/admin/policy/rules/{rule_id}", dependencies=[Depends(require_admin)])
    async def admin_rule_edit(rule_id: str, request: Request) -> JSONResponse:
        body = await request.json()
        return policy_edit(lambda: policy_editor.apply(
            gateway.store.path, replace={rule_id: adm.edited_control(gateway.store.get(), rule_id, body)}))

    @app.delete("/v1/admin/policy/rules/{rule_id}", dependencies=[Depends(require_admin)])
    async def admin_rule_delete(rule_id: str) -> JSONResponse:
        return policy_edit(lambda: policy_editor.apply(gateway.store.path, remove=[rule_id]))

    @app.post("/v1/admin/policy/import", dependencies=[Depends(require_admin)])
    async def admin_import(request: Request) -> JSONResponse:
        """Free-text company policy → proposals. Nothing is written until /import/apply."""
        body = await request.json()
        text = str(body.get("text") or "")[:20000]
        pol = gateway.store.get()
        props = importer.propose(text, taken_ids(), tools=list(pol.doc.tools), controls=pol.doc.controls)
        return JSONResponse({"proposals": [p.view() for p in props]})

    @app.post("/v1/admin/policy/import/apply", dependencies=[Depends(require_admin)])
    async def admin_import_apply(request: Request) -> JSONResponse:
        """Adds the reviewed proposals in one validated write. Rules are rebuilt here from template + params:
        the browser never sends a rule that is written as-is."""
        body = await request.json()

        def apply():
            taken, controls = taken_ids(), []
            for p in body.get("proposals") or []:
                t = catalog.TEMPLATES.get(p.get("template"))
                if t is None:
                    raise ValueError(f"unknown template {p.get('template')!r}")
                cid = catalog.next_id(t.prefix, taken)
                taken.add(cid)
                controls.append(catalog.build(t.key, p.get("params") or {}, cid, p.get("title")))
            if not controls:
                raise ValueError("no rule selected")
            policy_editor.apply(gateway.store.path, add=controls)
        return policy_edit(apply)

    @app.get("/v1/admin/policy/sample", dependencies=[Depends(require_admin)])
    async def admin_import_sample() -> dict:
        return {"text": importer.SAMPLE}

    @app.get("/v1/admin/stream", dependencies=[Depends(require_admin)])
    async def admin_stream(request: Request) -> StreamingResponse:
        """Server-Sent Events: every request's start, System One calls and decision, as they happen."""
        queue = gateway.bus.subscribe()

        async def events():
            try:
                yield "retry: 2000\n\n"
                while not await request.is_disconnected():
                    try:
                        first = await asyncio.wait_for(queue.get(), timeout=10)
                    except asyncio.TimeoutError:
                        yield ": ping\n\n"
                        continue
                    batch = [first]
                    while not queue.empty() and len(batch) < 250:
                        batch.append(queue.get_nowait())
                    yield f"data: {json.dumps(batch, ensure_ascii=False)}\n\n"
            finally:
                gateway.bus.unsubscribe(queue)

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.post("/v1/admin/loadgen", dependencies=[Depends(require_admin)])
    async def admin_loadgen(request: Request) -> JSONResponse:
        """Simulated-agent traffic through this gateway's own HTTP surface.
        {"action": "start"}: runs until {"action": "stop"} or MAX_RUN_S, whichever comes first. The cap is
        enforced here, so a closed browser tab can never leave it running (and spending System One calls).
        {"n": 100}: a fixed batch, as used by tests."""
        body = await request.json()
        action = body.get("action") or "batch"
        running = app.state.loadgen is not None and not app.state.loadgen.done()
        if action == "stop":
            if running and app.state.loadgen_stop is not None:
                app.state.loadgen_stop.set()
            return JSONResponse({"ok": True, "running": running})
        if running:
            return JSONResponse({"ok": False, "running": True, "error": "a run is already in progress"}, status_code=409)
        stop = asyncio.Event()
        if action == "start":
            n, seconds, rate = None, min(float(body.get("seconds") or MAX_RUN_S), MAX_RUN_S), float(body.get("rate") or 6.0)
        else:
            n, seconds, rate = max(1, min(int(body.get("n") or 100), 1000)), MAX_RUN_S * 4, float(body.get("rate") or 12.0)

        async def go() -> dict:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://spiregate",
                                         timeout=30) as client:
                return await loadgen.run(client, n=n, seconds=seconds, rate=rate, stop=stop,
                                         cwd=str(ROOT / "demo" / "claude-code"), bus=gateway.bus)

        app.state.loadgen, app.state.loadgen_stop = asyncio.create_task(go()), stop
        backend, note = SystemOneClient.resolve_backend(gateway.store.get().doc.systemone)
        return JSONResponse({"ok": True, "action": action, "n": n, "seconds": seconds, "systemone": backend, "note": note})

    @app.get("/v1/admin/identities", dependencies=[Depends(require_admin)])
    async def admin_identities() -> dict:
        pol = gateway.store.get()
        return {"identities": [{"key": k, **v.model_dump()} for k, v in pol.doc.identities.items()],
                "tools": sorted(k for k in pol.doc.tools if k != "*")}

    @app.post("/v1/admin/playground", dependencies=[Depends(require_admin)])
    async def admin_playground(request: Request) -> dict:
        """Judges' ad-hoc checks: the real decision path, with the trace it produced."""
        body = await request.json()
        req = {"phase": body.get("phase", "pre"), "session_id": body.get("session_id") or "playground",
               "tool": body.get("tool"), "args": body.get("args") or {}, "result": body.get("result"),
               "user_request": body.get("user_request"), "cwd": str(ROOT / "demo" / "claude-code")}
        with gateway.tracer.capture() as trace:
            out = await gateway.decide(body.get("agent_key"), req, surface="playground")
        return {**out, "trace": list(trace)}

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

    # ------------------------------------------------------------------ signature feed
    def feed_payload() -> dict:
        pol = gateway.store.get()
        gateway.feed.sync(pol.doc.feed)
        return feed_view(gateway.feed.status(pol.doc.feed), pol.doc.controls, gateway.audit.tail(2000))

    @app.get("/v1/admin/feed", dependencies=[Depends(require_admin)])
    async def admin_feed() -> dict:
        return feed_payload()

    @app.post("/v1/admin/feed/refresh", dependencies=[Depends(require_admin)])
    async def admin_feed_refresh() -> dict:
        """Fetch the feed now instead of waiting for the next poll (or re-read a local bundle)."""
        spec = gateway.store.get().doc.feed
        if spec is None:
            raise HTTPException(status_code=400, detail="the policy has no feed section")
        gateway.feed.sync(spec)
        await gateway.feed.pull(spec, force=True)
        return feed_payload()

    # ------------------------------------------------------------------ background analyst and daily report
    @app.get("/v1/admin/analyst", dependencies=[Depends(require_admin)])
    async def admin_analyst() -> dict:
        return analyst.status()

    @app.post("/v1/admin/analyst/run", dependencies=[Depends(require_admin)])
    async def admin_analyst_run() -> dict:
        """Assess the decisions since the previous assessment now, without waiting for the next N requests."""
        entry = await analyst.assess()
        return {"ok": entry is not None, "assessment": entry, "status": analyst.status(),
                **({} if entry else {"error": "no new decisions since the last assessment"})}

    @app.get("/v1/admin/reports", dependencies=[Depends(require_admin)])
    async def admin_reports() -> dict:
        return {"reports": analyst.reports()}

    @app.post("/v1/admin/reports/daily", dependencies=[Depends(require_admin)])
    async def admin_report_daily(day: str | None = None) -> dict:
        """Write the daily report now (today by default); it is also written automatically at analyst.daily_report_at."""
        try:
            d = date.fromisoformat(day) if day else None
        except ValueError:
            raise HTTPException(status_code=400, detail="day: YYYY-MM-DD")
        report = await analyst.daily(d)
        return {"ok": True, "date": report["date"], "posture_score": report["posture_score"],
                "risk_level": report["risk_level"], "backend": report["backend"], "note": report["note"],
                "headline": report["narrative"]["headline"], "url": f"/v1/admin/reports/daily/{report['date']}.html"}

    @app.get("/v1/admin/reports/daily/{day}.html", dependencies=[Depends(require_admin)])
    async def admin_report_html(day: str) -> Response:
        page = analyst.report_html(day)
        if page is None:
            raise HTTPException(status_code=404, detail=f"no report for {day}")
        # the page holds model-written text (escaped): no scripts, no external loads
        return Response(page, media_type="text/html; charset=utf-8",
                        headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})

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
        cur = gateway.feed.current
        return {"ok": True, "policy_rev": pol.rev, "policy_sha": pol.sha,
                "policy_error": gateway.store.last_error,
                "feed_version": cur.version if cur else None, "feed_error": gateway.feed.last_error}

    return app


@contextmanager
def _simulated(request: Request) -> Iterator[None]:
    """Load-generator traffic (X-Spire-Sim) is labelled in the audit log and kept off the console."""
    token = SIMULATED.set(bool(request.headers.get("x-spire-sim")))
    try:
        yield
    finally:
        SIMULATED.reset(token)


def _key(request: Request) -> str | None:
    return request.headers.get("authorization", "").removeprefix("Bearer ").strip() or None
