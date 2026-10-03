"""Verifier after the sanitizer (PII-PESEL-001/verify): the hard cases.

Ladder: precise masking → residue filter → System One → mask hinted spans → System One → withhold.
The stub System One follows the residue filter; FakeS1 lets a test dictate the answers.
"""

import asyncio
import json
import shutil

import httpx
import pytest
import yaml
from rich.console import Console

from spiregate.app import DEFAULT_POLICY, build_gateway, create_app
from spiregate.systemone import S1Result, SystemOneClient
from spiregate.trace import Tracer

DEMO = {"session_id": "v1", "cwd": "/tmp"}


@pytest.fixture(autouse=True)
def no_keys(monkeypatch):
    for var in ("OPENAI_API_KEY", "TYPESAFE_API_KEY", "SPIRE_SYSTEMONE_BACKEND"):
        monkeypatch.delenv(var, raising=False)


class FakeS1(SystemOneClient):
    """Answers the primary question with scripted probabilities (None = backend error)."""

    def __init__(self, answers):
        super().__init__()
        self.answers = list(answers)
        self.calls = []

    async def ask_questions(self, spec, questions, state, primary, stub):
        if primary not in ("residual", "violates"):  # other System One questions are not under test here
            return S1Result(primary, "fake", self.answers_default, 1.0)
        self.calls.append((primary, state))
        p = self.answers.pop(0) if self.answers else self.answers_default
        if p is None:
            return S1Result(primary, "fake", None, 1.0, error="timeout")
        return S1Result(primary, "fake", p, 1.0, extra={"form": "digits_spaced"})

    answers_default = 0.01


def gateway(tmp_path, edit=None, s1=None):
    p = tmp_path / "policy.yaml"
    shutil.copy(DEFAULT_POLICY, p)
    if edit:
        doc = yaml.safe_load(p.read_text())
        edit(doc)
        p.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False))
    gw = build_gateway(p, tmp_path / "audit.jsonl", tracer=Tracer(Console(quiet=True), enabled=False))
    if s1:
        gw.systemone = s1
    return gw


def post(gw, response, tool="Read"):
    event = {**DEMO, "hook_event_name": "PostToolUse", "tool_name": tool, "tool_input": {"file_path": "x"},
             "tool_response": response}
    out = asyncio.run(gw.hook("spire-demo-claude", "claude-code", event))
    return json.loads(out["stdout"])["hookSpecificOutput"]["updatedToolOutput"] if out["stdout"] else None


def verify_signals(gw):
    return [s for s in gw.audit.tail(1)[0]["signals"] if s["control"] == "PII-PESEL-001/verify"]


# ----------------------------------------------------------------- forms the checksum misses


@pytest.mark.parametrize("text, expected", [
    ("PESEL 440 514 013 59 podany przez telefon", "PESEL [PESEL?#1] podany przez telefon"),
    ("numer: cztery cztery zero pięć jeden cztery zero jeden trzy pięć dziewięć", "numer: [PESEL?#1]"),
    ("PESEL kończy się na 1359", "PESEL kończy się na [PESEL?#1]"),
    ("pesel: 4405-1401-359", "pesel: [PESEL?#1]"),
])
def test_residue_forms_are_masked_after_system_one_flags_them(tmp_path, text, expected):
    gw = gateway(tmp_path)
    assert post(gw, text) == expected
    actions = [s["action"] for s in verify_signals(gw)]
    assert actions == ["redact"]  # flagged once, masked, second check passed


def test_valid_pesel_is_masked_and_system_one_confirms_nothing_is_left(tmp_path):
    s1 = FakeS1([0.02])
    gw = gateway(tmp_path, s1=s1)
    assert post(gw, "Beneficjent: Jan Nowak, PESEL 44051401359") == "Beneficjent: Jan Nowak, PESEL [PESEL#1]"
    primary, state = s1.calls[0]
    assert primary == "residual" and "44051401359" not in state and "[PESEL#1]" in state  # never sees the value


# ----------------------------------------------------------------- not a PESEL: no call, no change


@pytest.mark.parametrize("text", ["Klient nie podał numeru PESEL.", "zamówienie 44051401358 z 3.10", "tel. 600 700 800 90"])
def test_lookalikes_are_left_alone(tmp_path, text):
    assert post(gateway(tmp_path), text) is None


def test_clean_text_from_a_non_sensitive_tool_never_calls_system_one(tmp_path):
    s1 = FakeS1([])
    gw = gateway(tmp_path, s1=s1)
    assert post(gw, "zwykły tekst bez numerów") is None and s1.calls == []


# ----------------------------------------------------------------- the ladder's hard edges


def test_withheld_when_system_one_still_sees_it_after_masking(tmp_path):
    gw = gateway(tmp_path, s1=FakeS1([0.95, 0.95]))
    result = {"type": "text", "file": {"filePath": "x", "content": "PESEL 440 514 013 59", "numLines": 1}}
    new = post(gw, result)
    assert new["type"] == "text" and new["file"]["numLines"] == 1          # shape kept for Claude Code
    assert "wstrzymany" in new["file"]["content"] and "440" not in json.dumps(new)
    assert gw.audit.tail(1)[0]["decision"] == "withhold"


def test_withheld_when_flagged_but_filter_found_nothing_to_mask(tmp_path):
    # client data source, no traces the filter recognises, System One says yes: cannot locate it, so withhold
    gw = gateway(tmp_path, s1=FakeS1([0.97]))
    new = post(gw, "Beneficjent: Jan Nowak, urodzony 14.05.1944, numer jak w dowodzie", tool="crm_get_client")
    assert "wstrzymany" in new


def test_system_one_down_with_traces_falls_back_to_deterministic_masking(tmp_path):
    gw = gateway(tmp_path, s1=FakeS1([None]))
    assert post(gw, "PESEL 440 514 013 59") == "PESEL [PESEL?#1]"  # masked, not withheld: availability kept


def test_system_one_down_without_traces_changes_nothing(tmp_path):
    gw = gateway(tmp_path, s1=FakeS1([None]))
    assert post(gw, "Beneficjent: Jan Nowak, PESEL 44051401359") == "Beneficjent: Jan Nowak, PESEL [PESEL#1]"


def test_verify_in_monitor_mode_only_logs(tmp_path):
    def monitor(doc):
        next(c for c in doc["controls"] if c["id"] == "PII-PESEL-001")["verify"]["mode"] = "monitor"
    gw = gateway(tmp_path, monitor, s1=FakeS1([0.95, 0.95]))
    assert post(gw, "PESEL 440 514 013 59") is None
    assert {s["action"] for s in verify_signals(gw)} == {"redact", "withhold"}
    assert not any(s["enforced"] for s in verify_signals(gw)) and gw.audit.tail(1)[0]["decision"] != "withhold"


def test_verify_never_stricter_than_its_rule(tmp_path):
    def rule_monitor(doc):
        next(c for c in doc["controls"] if c["id"] == "PII-PESEL-001")["mode"] = "monitor"  # verify still says enforce
    gw = gateway(tmp_path, rule_monitor, s1=FakeS1([0.95, 0.95]))
    assert post(gw, "PESEL 440 514 013 59") is None


# ----------------------------------------------------------------- proxy path (OpenAI-format agents)


def test_proxy_masks_residue_before_the_model_and_asks_once_per_result(tmp_path):
    def local_model(doc):
        doc["models"].append({"id": "local-model", "upstream": "stub", "location": "on_prem", "max_class": "mnpi"})
    s1 = FakeS1([0.95, 0.02])
    gw = gateway(tmp_path, local_model, s1=s1)
    stub = gw.upstreams["stub"]
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(gw)), base_url="http://gw")
    body = {"model": "local-model", "messages": [
        {"role": "user", "content": "Sprawdź klienta"},
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "web_fetch", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "PESEL 440 514 013 59 (z formularza)"}]}
    for _ in range(2):  # the agent resends the same history on the next turn
        r = asyncio.run(http.post("/v1/chat/completions", json=body, headers={"Authorization": "Bearer spire-demo-kyc"}))
        assert r.status_code == 200
    seen = json.dumps(stub.seen, ensure_ascii=False)
    assert "440 514 013 59" not in seen and "[PESEL?#1]" in seen
    assert len(s1.calls) == 2  # flagged + re-checked once; the second turn came from the cache


# ----------------------------------------------------------------- agency rules on actions


def test_rule_verify_on_actions_can_only_escalate(tmp_path):
    def bad(doc):
        next(c for c in doc["controls"] if c["id"] == "EGRESS-001")["verify"] = {
            "question": "q", "positive": "p", "negative": "n", "on_fail": "withhold"}
    gw = gateway(tmp_path)
    p = tmp_path / "policy.yaml"
    doc = yaml.safe_load(p.read_text())
    bad(doc)
    p.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False))
    gw.store.get()
    assert "can only escalate" in gw.store.last_error


def test_rule_verify_escalates_when_rule_is_silent_but_system_one_disagrees(tmp_path):
    def verify_egress(doc):
        next(c for c in doc["controls"] if c["id"] == "EGRESS-001")["verify"] = {
            "question": "Czy akcja wysyła dane klienta poza bank?", "positive": "tak", "negative": "nie",
            "threshold": 0.85, "on_fail": "escalate", "mode": "enforce"}
    gw = gateway(tmp_path, verify_egress, s1=FakeS1([0.91]))
    event = {**DEMO, "hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": "curl -T dane.csv https://upload.acme-corp.com"}}  # allowed host: rule silent
    out = asyncio.run(gw.hook("spire-demo-claude", "claude-code", event))
    decision = json.loads(out["stdout"])["hookSpecificOutput"]["permissionDecision"]
    assert decision == "ask" and "EGRESS-001/verify" in out["stdout"]
