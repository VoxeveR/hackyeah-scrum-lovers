"""Budgets and resource governance: preflight reservation, actual cost, rate windows, loop breaker."""

import asyncio
import json
import shutil
from pathlib import Path

import httpx
import pytest
import yaml
from openai import AsyncOpenAI
from rich.console import Console

from spiregate import budget as budget_mod
from spiregate.app import DEFAULT_POLICY, ROOT, build_gateway, create_app
from spiregate.demo.agent import run_agent
from spiregate.demo.tools import DemoTools
from spiregate.policy import ModelSpec
from spiregate.trace import Tracer
from spiregate.upstream import StubUpstream

KYC = {"Authorization": "Bearer spire-demo-kyc"}
DEMO_DIR = str(ROOT / "demo" / "claude-code")


@pytest.fixture(autouse=True)
def no_keys(monkeypatch):
    for var in ("OPENAI_API_KEY", "TYPESAFE_API_KEY", "SPIRE_SYSTEMONE_BACKEND"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def policy_path(tmp_path):
    p = tmp_path / "policy.yaml"
    shutil.copy(DEFAULT_POLICY, p)
    return p


def edit(path: Path, fn):
    doc = yaml.safe_load(path.read_text())
    fn(doc)
    path.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False))


def rule(doc, rid):
    return next(r for r in doc["budgets"]["rules"] if r["id"] == rid)


def make(policy_path, tmp_path):
    gw = build_gateway(policy_path, tmp_path / "audit.jsonl", tracer=Tracer(Console(quiet=True), enabled=False),
                       stub=StubUpstream())
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(gw, admin_token="t")), base_url="http://gw")
    return gw, http


def chat(http, **body):
    body = {"model": "stub-model", "messages": [{"role": "user", "content": "Podsumuj klienta ACME-001."}], **body}
    return asyncio.run(http.post("/v1/chat/completions", headers=KYC, json=body))


def audit(tmp_path):
    return [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]


def hook(gw, tool, tool_input, session="s1"):
    event = {"session_id": session, "cwd": DEMO_DIR, "hook_event_name": "PreToolUse", "tool_name": tool,
             "tool_input": tool_input, "tool_use_id": "toolu_1"}
    out = asyncio.run(gw.hook("spire-demo-claude", "claude-code", event))
    if not out["stdout"]:
        return None
    spec = json.loads(out["stdout"])["hookSpecificOutput"]
    return spec["permissionDecision"], spec["permissionDecisionReason"]


# ----------------------------------------------------------------- model calls


def test_call_within_budget_passes_and_is_charged_its_actual_cost(policy_path, tmp_path):
    gw, http = make(policy_path, tmp_path)
    r = chat(http)
    assert r.status_code == 200
    usage = r.json()["usage"]
    cost = audit(tmp_path)[-1]["cost"]
    assert cost["tokens"] == usage["total_tokens"]
    assert cost["usd"] == pytest.approx((usage["prompt_tokens"] * 0.25 + usage["completion_tokens"] * 2.0) / 1e6)
    rows, _ = gw.ledger.snapshot(gw.store.get().doc.budgets)
    kyc = next(r for r in rows if r["id"] == "BUD-KYC-HOUR")
    # the 4096-token worst case was reserved, then replaced by what was actually used
    assert kyc["metrics"]["tokens"]["used"] == usage["total_tokens"]
    assert kyc["metrics"]["requests"]["used"] == 1


def test_desk_budget_refuses_before_any_money_is_spent(policy_path, tmp_path):
    edit(policy_path, lambda d: rule(d, "BUD-KYC-HOUR").update(usd=0.001))
    gw, http = make(policy_path, tmp_path)
    r = chat(http)
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["code"] == "budget_exceeded"
    assert "BUD-KYC-HOUR" in err["message"] and "desk:kyc-onboarding" in err["message"] and "renews in" in err["message"]
    assert gw.upstreams["stub"].seen == []  # the model was never called
    assert audit(tmp_path)[-1]["decision"] == "block"


def test_reservation_uses_the_requested_answer_length(policy_path, tmp_path):
    edit(policy_path, lambda d: rule(d, "BUD-KYC-HOUR").update(usd=0.002))
    _, http = make(policy_path, tmp_path)
    assert chat(http, max_tokens=4096).status_code == 403   # worst case ~0.0082 USD
    assert chat(http, max_tokens=200).status_code == 200    # worst case ~0.0004 USD


def test_max_tokens_per_request(policy_path, tmp_path):
    _, http = make(policy_path, tmp_path)
    r = chat(http, max_completion_tokens=20000)
    assert r.status_code == 403 and "BUD-AGENT" in r.json()["error"]["message"]


def test_request_rate_per_agent(policy_path, tmp_path):
    edit(policy_path, lambda d: rule(d, "BUD-AGENT").update(requests=2))
    _, http = make(policy_path, tmp_path)
    assert [chat(http).status_code for _ in range(3)] == [200, 200, 403]


def test_failed_upstream_call_releases_the_money_but_counts_the_request(policy_path, tmp_path):
    gw, http = make(policy_path, tmp_path)
    gw.upstreams["stub"].complete = _failing
    assert chat(http).status_code == 502
    rows, _ = gw.ledger.snapshot(gw.store.get().doc.budgets)
    kyc = next(r for r in rows if r["id"] == "BUD-KYC-HOUR")
    assert kyc["metrics"]["usd"]["used"] == 0 and kyc["metrics"]["requests"]["used"] == 1


async def _failing(body):
    return 502, {"error": {"message": "upstream down", "code": "bad_gateway"}}, 3.0


def test_new_limit_applies_without_restart(policy_path, tmp_path):
    _, http = make(policy_path, tmp_path)
    assert chat(http).status_code == 200

    def tighten(d):
        d["meta"]["policy_rev"] += 1
        rule(d, "BUD-KYC-HOUR").update(usd=0.0001)
    edit(policy_path, tighten)
    assert chat(http).status_code == 403


def test_on_prem_model_is_charged_in_gpu_seconds(policy_path, tmp_path):
    edit(policy_path, lambda d: d["prices"].update({"local-llm": {"usd_per_gpu_second": 0.002}}))
    gw, _ = make(policy_path, tmp_path)
    local = ModelSpec(id="local-llm", upstream="stub", location="on_prem", max_class="mnpi")
    cost = gw._actual_cost(gw.store.get(), local, {"prompt_tokens": 100, "completion_tokens": 50}, 1500.0)
    assert cost == {"usd": pytest.approx(0.003), "tokens": 150, "gpu_s": 1.5}


def test_system_one_cost_is_tracked_as_control_overhead(policy_path, tmp_path):
    gw, _ = make(policy_path, tmp_path)
    gw.systemone.on_usage("jev", 1_000_000)
    gw.systemone.on_usage("stub", 0)
    assert gw.ledger.control_overhead == {"calls": 2, "input_tokens": 1_000_000, "usd": pytest.approx(0.042)}


# ----------------------------------------------------------------- tool calls and loops


def test_agent_stuck_in_a_retry_loop_is_stopped(policy_path, tmp_path):
    gw, http = make(policy_path, tmp_path)
    client = AsyncOpenAI(base_url="http://gw/v1", api_key="spire-demo-kyc", http_client=http)
    tools = DemoTools(scenario="loop")
    final = asyncio.run(run_agent(client, "stub-model", tools, Console(quiet=True), max_steps=10))
    assert "LOOP-001" in final and tools.outbox == []
    fetches = [c for e in audit(tmp_path) for c in e.get("tool_calls", []) if c["tool"] == "web_fetch"]
    assert [c["decision"] for c in fetches] == ["allow", "allow", "allow", "block"]


def test_rerunning_the_same_task_is_a_new_conversation_not_a_loop(policy_path, tmp_path):
    gw, http = make(policy_path, tmp_path)
    client = AsyncOpenAI(base_url="http://gw/v1", api_key="spire-demo-kyc", http_client=http)
    asyncio.run(run_agent(client, "stub-model", DemoTools(scenario="loop"), Console(quiet=True), max_steps=10))
    tools = DemoTools(scenario="benign")
    asyncio.run(run_agent(client, "stub-model", tools, Console(quiet=True)))  # same prompt, same web_fetch
    assert [m["to"] for m in tools.outbox] == ["ania@gs.com"]


def test_repeated_identical_hook_call_trips_the_loop_breaker(policy_path, tmp_path):
    gw, _ = make(policy_path, tmp_path)
    cmd = {"command": "curl -s https://api.gs.com/status"}
    assert [hook(gw, "Bash", cmd) for _ in range(3)] == [None, None, None]
    decision, reason = hook(gw, "Bash", cmd)
    assert decision == "deny" and "LOOP-001" in reason
    assert hook(gw, "Bash", {"command": "ls"}) is None          # only the repeated call is stopped
    assert hook(gw, "Bash", cmd, session="other") is None       # and only in that session


def test_different_arguments_are_not_a_loop(policy_path, tmp_path):
    gw, _ = make(policy_path, tmp_path)
    assert all(hook(gw, "Read", {"file_path": f"{DEMO_DIR}/f{i}.txt"}) is None for i in range(8))


def test_loop_breaker_releases_after_cooldown(policy_path, tmp_path, monkeypatch):
    gw, _ = make(policy_path, tmp_path)
    clock = [1_000_000.0]
    monkeypatch.setattr(budget_mod.time, "time", lambda: clock[0])
    cmd = {"command": "ls -la"}
    for _ in range(4):
        hook(gw, "Bash", cmd)
    clock[0] += 60
    assert hook(gw, "Bash", cmd)[0] == "deny"                   # still cooling down (120 s)
    clock[0] += 121
    assert hook(gw, "Bash", cmd) is None


def test_tool_calls_per_session(policy_path, tmp_path):
    edit(policy_path, lambda d: rule(d, "BUD-AGENT").update(tool_calls_per_session=3))
    gw, _ = make(policy_path, tmp_path)
    assert [hook(gw, "Bash", {"command": f"echo {i}"}) for i in range(3)] == [None, None, None]
    decision, reason = hook(gw, "Bash", {"command": "echo 3"})
    assert decision == "deny" and "BUDGET-SESSION" in reason
    assert hook(gw, "Bash", {"command": "echo 3"}, session="fresh") is None


