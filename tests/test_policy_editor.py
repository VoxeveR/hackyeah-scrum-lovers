"""Policy editor and free-text import: what the dashboard's Polityka page does, through the real API."""

import asyncio
import json
import shutil

import httpx
import pytest
from rich.console import Console

from spiregate import importer
from spiregate.actions import compute_facts
from spiregate.app import DEFAULT_POLICY, ROOT, build_gateway, create_app
from spiregate.detectors import Redactor, find_identifiers
from spiregate.systemone import S1Bundle
from spiregate.trace import Tracer

TOKEN = "t"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
DEMO_DIR = str(ROOT / "demo" / "claude-code")


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
    return asyncio.run(http.request(method, path, headers=AUTH, **kw))


def bash(gw, command, session="e1"):
    out = asyncio.run(gw.hook("spire-demo-claude", "claude-code", {
        "session_id": session, "cwd": DEMO_DIR, "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": command}}))
    return json.loads(out["stdout"])["hookSpecificOutput"]["permissionDecision"] if out["stdout"] else "allow"


def transfer(gw, amount, to="Dostawca Sp. z o.o."):
    asyncio.run(gw.decide("spire-sim-payments", {"session_id": "p1", "phase": "prompt",
                                                  "user_request": f"Zapłać {to}"}))
    return asyncio.run(gw.decide("spire-sim-payments", {"session_id": "p1", "phase": "pre", "tool": "create_transfer",
                                                         "args": {"to": to, "amount": amount}}))["decision"]


# ----------------------------------------------------------------- editor

def test_policy_view_lists_rules_lanes_and_the_catalog(env):
    _, http, _ = env
    v = call(http, "GET", "/v1/admin/policy").json()
    rules = {r["id"]: r for r in v["rules"]}
    assert rules["IFC-TRIFECTA-001"]["invariant"] and rules["PII-PESEL-001"]["lane"] == "dj"
    assert rules["S1-JEV-002"]["lane"] == "j" and rules["CRED-001"]["template"] == "block_credentials"
    keys = {t["key"] for t in v["templates"]}
    assert {"mask_identifiers", "prose_rule", "deny_tools", "block_destructive"} <= keys and "budget" not in keys


def test_a_rule_added_from_the_dashboard_works_on_the_next_request(env):
    gw, http, _ = env
    assert bash(gw, "rm -rf build/") == "allow"
    r = call(http, "POST", "/v1/admin/policy/rules", json={"template": "block_destructive", "params": {"action": "block"}})
    assert r.json()["ok"]
    assert bash(gw, "rm -rf build/", session="e2") == "deny"


def test_editing_and_deleting_a_rule(env):
    gw, http, policy = env
    call(http, "POST", "/v1/admin/policy/rules", json={"template": "block_destructive", "params": {}})
    cid = next(r["id"] for r in call(http, "GET", "/v1/admin/policy").json()["rules"] if r["template"] == "block_destructive")
    r = call(http, "PUT", f"/v1/admin/policy/rules/{cid}", json={"params": {"action": "escalate"}, "title": "Niszczące: przegląd"})
    assert r.json()["ok"] and bash(gw, "git push origin main --force") == "ask"
    assert call(http, "DELETE", f"/v1/admin/policy/rules/{cid}").json()["ok"]
    assert bash(gw, "git push origin main --force", session="e3") == "allow" and cid not in policy.read_text()


def test_invariants_and_bad_input_are_refused_and_nothing_is_written(env):
    _, http, policy = env
    before = policy.read_text()
    assert call(http, "DELETE", "/v1/admin/policy/rules/IFC-TRIFECTA-001").status_code == 400
    bad = call(http, "POST", "/v1/admin/policy/rules", json={"template": "egress_domains", "params": {"domains": "nie domena!"}})
    assert bad.status_code == 400 and "domain" in bad.json()["error"]
    assert call(http, "POST", "/v1/admin/policy/rules", json={"template": "no_such"}).status_code == 400
    assert policy.read_text() == before


def test_rules_without_a_template_can_still_be_tuned(env):
    gw, http, policy = env
    r = call(http, "PUT", "/v1/admin/policy/rules/S1-JEV-002", json={"advanced": {"escalate_at": 0.6, "block_at": 0.8}})
    assert r.json()["ok"]
    c = next(c for c in gw.store.get().doc.controls if c.id == "S1-JEV-002")
    assert (c.escalate_at, c.block_at) == (0.6, 0.8) and c.detector == "systemone_matches_goal"
    block = policy.read_text().split("- id: S1-JEV-002", 1)[1].split("\n\n", 1)[0]
    assert "\n    title:" in block and "on_error" not in block      # written like a person would: a field per line


def test_edits_keep_every_comment_elsewhere_in_the_file(env):
    _, http, policy = env
    comments = [ln for ln in policy.read_text().splitlines() if ln.lstrip().startswith("#")]
    call(http, "POST", "/v1/admin/policy/rules", json={"template": "block_privilege", "params": {}})
    call(http, "PUT", "/v1/admin/policy/rules/S1-JEV-001", json={"advanced": {"escalate_at": 0.7}})
    after = [ln for ln in policy.read_text().splitlines() if ln.lstrip().startswith("#")]
    assert after == comments
    assert call(http, "DELETE", "/v1/admin/policy/rules/PRIV-001").json()["ok"]
    assert policy.read_text().endswith("\n") and not policy.read_text().endswith("\n\n")
    call(http, "POST", "/v1/admin/policy/rules", json={"template": "mask_identifiers", "params": {"kinds": ["IBAN"]}})
    assert "&id" not in policy.read_text() and "*id" not in policy.read_text()


def test_budgets_are_not_rules(env):
    _, http, policy = env
    before = policy.read_text()
    assert call(http, "POST", "/v1/admin/policy/rules", json={"template": "budget", "params": {"usd": 3}}).status_code == 400
    props = call(http, "POST", "/v1/admin/policy/import", json={"text": "Daily AI budget for the KYC team is 50 USD."}).json()["proposals"]
    assert [(p["target"], p["item"]) for p in props] == [("skip", {})] and "budgets" in props[0]["why"]   # shown, not added
    assert policy.read_text() == before


# ----------------------------------------------------------------- import from free text

def test_free_text_policy_becomes_deterministic_rules_and_jev_rules(env):
    _, http, _ = env
    props = call(http, "POST", "/v1/admin/policy/import", json={"text": importer.SAMPLE}).json()["proposals"]
    templates = [p["template"] for p in props]
    assert {"mask_identifiers", "egress_domains", "block_download_exec", "block_credentials", "amount_review",
            "block_destructive", "block_package_install", "business_hours"} <= set(templates)
    assert len(props) == 10                                        # the heading line is not a rule
    assert templates.count("prose_rule") == 2                      # M&A and promises of returns: only Jev can judge
    mask = next(p for p in props if p["template"] == "mask_identifiers")
    assert mask["params"]["kinds"] == ["PESEL", "CARD"] and mask["lane"] == "dj"
    amount = next(p for p in props if p["template"] == "amount_review")
    assert amount["params"]["amount"] == 10000 and amount["params"]["action"] == "escalate"
    hours = next(p for p in props if p["template"] == "business_hours")
    assert (hours["params"]["start"], hours["params"]["end"], hours["params"]["action"]) == (8, 18, "escalate")


def test_a_polish_policy_is_read_too():
    props = importer.propose("Polityka AI (wyciąg)\nAgenci nie mogą widzieć numerów PESEL.\n"
                             "Przelewy powyżej 10 000 USD wymagają akceptacji człowieka.", set())
    assert [p.template for p in props] == ["mask_identifiers", "amount_review"]
    assert props[1].params == {"amount": 10000, "action": "escalate"}


def test_imported_rules_are_enforced_after_apply(env, monkeypatch):
    gw, http, _ = env
    props = call(http, "POST", "/v1/admin/policy/import", json={"text": importer.SAMPLE}).json()["proposals"]
    assert transfer(gw, 25000) == "allow"
    # business hours depend on the clock: left out here, see test_business_hours_rule_follows_the_clock
    r = call(http, "POST", "/v1/admin/policy/import/apply", json={"proposals": [p for p in props if p["template"] != "business_hours"]})
    assert r.json()["ok"]
    assert transfer(gw, 25000) == "escalate" and transfer(gw, 500) == "allow"     # > 10 000: a person approves

    async def jev_says_breach(spec, questions, state, stubs):   # a plain-language rule: System One decides
        return S1Bundle("fake", {q: (0.97 if q.startswith("rule_") else 0.01) for q in questions}, 1.0)
    monkeypatch.setattr(gw.systemone, "_bundle", jev_says_breach)
    assert transfer(gw, 500) == "block"


def test_business_hours_rule_follows_the_clock(env, monkeypatch):
    import datetime as dt
    gw, http, _ = env
    call(http, "POST", "/v1/admin/policy/rules", json={"template": "business_hours", "params": {"start": 8, "end": 18}})

    def at(day, hour):
        class Clock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return dt.datetime(2026, 10, day, hour, 30)
        monkeypatch.setattr("spiregate.actions.datetime", Clock)
        return transfer(gw, 500)
    assert at(5, 10) == "allow"                                   # Monday 10:30
    assert at(5, 22) == "escalate" and at(4, 10) == "escalate"     # Monday night, Sunday morning


def test_import_marks_what_the_policy_already_does(env):
    _, http, _ = env
    props = call(http, "POST", "/v1/admin/policy/import", json={"text": importer.SAMPLE}).json()["proposals"]
    have = {p["template"] for p in props if p["exists"]}
    assert have == {"block_credentials", "block_download_exec"}          # CRED-001 and EXEC-HYG-001 are in the policy
    call(http, "POST", "/v1/admin/policy/import/apply", json={"proposals": [p for p in props if not p["exists"]]})
    again = call(http, "POST", "/v1/admin/policy/import", json={"text": importer.SAMPLE}).json()["proposals"]
    assert all(p["exists"] for p in again)                                # a second import adds nothing new


def test_apply_rebuilds_rules_from_template_and_params_only(env):
    _, http, policy = env
    sneaky = {"template": "block_privilege", "params": {}, "item": {"id": "X", "when": "true", "action": "block"}}
    call(http, "POST", "/v1/admin/policy/import/apply", json={"proposals": [sneaky]})
    text = policy.read_text()
    assert "facts.privilege_escalation" in text and "when: 'true'" not in text and "when: true" not in text


def test_english_policy_and_email_wording():
    props = importer.propose("Client emails may only be sent to @gs.com or @goldmansachs.com recipients.\n"
                             "Wire transfers over $250k require manager approval.\nDo not run sudo.", set())
    assert [p.template for p in props] == ["egress_domains", "amount_review", "block_privilege"]
    assert props[0].params["domains"] == ["gs.com", "goldmansachs.com"] and props[1].params["amount"] == 250000


# ----------------------------------------------------------------- new deterministic checks

def test_extra_identifier_kinds_are_opt_in():
    text = "NIP 526-025-02-74, SSN 123-45-6789, routing 021000021, jan@acme.com. Zamówienie 44051401358."
    assert find_identifiers(text) == []                           # not detected unless a rule asks
    masked, used = Redactor().redact(text, {"NIP", "SSN", "ABA", "EMAIL"})
    assert used == ["[NIP#1]", "[SSN#1]", "[ABA#1]", "[EMAIL#1]"] and "44051401358" in masked


def test_new_action_facts():
    def facts(cmd=None, tool="Bash", args=None, effect="exec"):
        return compute_facts(tool, {"effect": effect}, args or {"command": cmd}, allowed_tools=["*"],
                             internal_domains=["gs.com"], protected_roots=[])[1]
    assert facts("rm -rf data/")["destructive"] and not facts("rm notes.txt")["destructive"]
    assert facts("sudo systemctl restart x")["privilege_escalation"] and facts("pip install requests")["package_install"]
    assert facts(tool="create_transfer", args={"amount": "18 450,00 PLN"}, effect="financial")["amount"] == 18450.0
    assert 0 <= facts("ls")["hour"] <= 23
