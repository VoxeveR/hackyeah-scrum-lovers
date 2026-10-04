"""Synthetic fleet and the live event stream behind the Silnik dashboard page."""

import asyncio
import json
import shutil

import httpx
import pytest
from rich.console import Console

from spiregate import loadgen
from spiregate.app import DEFAULT_POLICY, ROOT, build_gateway, create_app
from spiregate.trace import Tracer

TOKEN = "t"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(autouse=True)
def no_keys(monkeypatch):
    for var in ("OPENAI_API_KEY", "TYPESAFE_API_KEY", "SPIRE_SYSTEMONE_BACKEND"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def env(tmp_path):
    policy = tmp_path / "policy.yaml"
    shutil.copy(DEFAULT_POLICY, policy)
    gw = build_gateway(policy, tmp_path / "audit.jsonl", tracer=Tracer(Console(quiet=True), enabled=False))
    app = create_app(gw, admin_token=TOKEN)
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw")
    return gw, app, http


async def _run(app, gw, n, seed=1):
    q = gw.bus.subscribe()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw", timeout=30) as c:
        summary = await loadgen.run(c, n=n, rate=200, cwd=str(ROOT / "demo" / "claude-code"), seed=seed, bus=gw.bus)
    events = []
    while not q.empty():
        events.append(q.get_nowait())
    gw.bus.unsubscribe(q)
    return summary, events


def test_every_simulated_request_is_answered_and_labelled_sim(env):
    gw, app, _ = env
    summary, events = asyncio.run(_run(app, gw, 60))
    assert summary["n"] == 60 and sum(summary["outcomes"].values()) >= 60
    ends = [e for e in events if e["type"] == "end"]
    starts = [e for e in events if e["type"] == "start"]
    assert len(ends) == len(starts) >= 40                  # user prompts are context, not decisions: not streamed
    assert all(e["kind"] != "prompt" for e in starts)
    audit = gw.audit.tail(10000)
    assert audit and all(a.get("sim") for a in audit)  # nothing from the fleet is left unlabelled


def test_the_fleet_produces_a_realistic_mix_of_decisions(env):
    gw, app, _ = env
    _, events = asyncio.run(_run(app, gw, 120, seed=7))
    decisions = {}
    for e in events:
        if e["type"] == "end":
            decisions[e["decision"]] = decisions.get(e["decision"], 0) + 1
    assert decisions.get("allow", 0) > decisions.get("block", 0) > 0   # mostly allowed, with real blocks
    assert decisions.get("redact", 0) > 0 and sum(decisions.values()) >= 80  # user prompts are not decisions


def test_each_end_event_has_a_latency_split_and_cost(env):
    gw, app, _ = env
    _, events = asyncio.run(_run(app, gw, 60))
    ends = [e for e in events if e["type"] == "end"]
    for e in ends:
        assert e["ms"] >= 0 and e["t0_ms"] >= 0 and e["s1_ms"] >= 0
        assert e["ms"] + 0.5 >= e["t0_ms"] + e["s1_ms"] + e["upstream_ms"]
        assert e["usd"] >= 0
    assert any(e["s1_calls"] > 0 for e in ends)  # some requests really asked System One


def test_bus_delivers_each_request_lifecycle_to_subscribers(env):
    # The SSE endpoint is a thin wrapper over this bus (its HTTP streaming needs a real server, not ASGITransport).
    gw, app, _ = env
    _, events = asyncio.run(_run(app, gw, 30))
    by_id = {}
    for e in events:
        if e["type"] in ("start", "end"):
            by_id.setdefault(e["id"], set()).add(e["type"])
    assert by_id and all(kinds == {"start", "end"} for kinds in by_id.values())  # every request: one start, one end
    assert any(e["type"] == "s1" for e in events) and any(e["type"] == "run" for e in events)


def test_a_slow_subscriber_drops_events_instead_of_blocking_the_engine(env):
    gw, _, _ = env
    small = gw.bus.subscribe()
    small._maxsize = 0  # never used again; simulate a full queue below
    tiny = asyncio.Queue(1)
    gw.bus._subs.add(tiny)
    for _ in range(50):
        gw.bus.emit({"type": "start", "id": 1})  # would raise QueueFull if it blocked the engine
    assert tiny.qsize() == 1  # the slow tab stops receiving; the engine is never slowed
    gw.bus.unsubscribe(tiny)
    gw.bus.unsubscribe(small)


def test_stream_requires_the_admin_token(env):
    _, _, http = env
    r = asyncio.run(http.get("/v1/admin/stream"))
    assert r.status_code == 401


def test_loadgen_endpoint_starts_a_run_and_reports_progress(env):
    gw, app, http = env

    async def scenario():
        r = await http.post("/v1/admin/loadgen", json={"n": 15, "rate": 200}, headers=AUTH)
        assert r.status_code == 200 and r.json()["n"] == 15
        busy = await http.post("/v1/admin/loadgen", json={"n": 5}, headers=AUTH)  # one run at a time
        assert busy.status_code in (200, 409)
        summary = await app.state.loadgen  # the task was created on this same loop
        total = (await http.get("/v1/admin/summary", headers=AUTH)).json()["kpis"]["total"]
        return summary, total

    summary, total = asyncio.run(scenario())
    assert summary["n"] == 15 and sum(summary["outcomes"].values()) >= 15
    assert total > 0  # some steps (user prompts) carry no decision, so audited ≤ scheduled


def test_end_event_says_whether_the_model_was_called(env):
    # the stub model answers in ~0 ms, so the latency alone cannot tell a model call from a refusal
    gw, app, _ = env
    q = gw.bus.subscribe()

    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as c:
            ok = {"model": "stub-model", "messages": [{"role": "user", "content": "hej"}]}
            await c.post("/v1/chat/completions", json=ok, headers={"Authorization": "Bearer spire-sim-onboarding"})
            await c.post("/v1/chat/completions", json={**ok, "model": "gpt-4o"}, headers={"Authorization": "Bearer spire-sim-onboarding"})

    asyncio.run(go())
    ends = []
    while not q.empty():
        e = q.get_nowait()
        if e["type"] == "end":
            ends.append(e)
    assert [e["model_called"] for e in ends] == [True, False]


def test_start_sends_traffic_until_stop_is_pressed(env):
    gw, app, http = env

    async def scenario():
        r = await http.post("/v1/admin/loadgen", json={"action": "start", "seconds": 15, "rate": 40}, headers=AUTH)
        assert r.json()["ok"] and r.json()["n"] is None
        await asyncio.sleep(0.4)
        stopped = await http.post("/v1/admin/loadgen", json={"action": "stop"}, headers=AUTH)
        assert stopped.json()["running"] is True
        return await app.state.loadgen

    summary = asyncio.run(scenario())
    assert summary["stopped"] and summary["n"] > 0 and summary["seconds"] < 5   # stopped long before 15 s


def test_start_is_capped_by_the_server_whatever_the_client_asks(env):
    _, app, http = env

    async def scenario():
        r = await http.post("/v1/admin/loadgen", json={"action": "start", "seconds": 600}, headers=AUTH)
        await http.post("/v1/admin/loadgen", json={"action": "stop"}, headers=AUTH)
        await app.state.loadgen
        return r.json()

    assert asyncio.run(scenario())["seconds"] == 15
