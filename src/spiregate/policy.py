"""Policy file: schema, validation, CEL compilation and hot reload with last-known-good."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from cel_expr_python import cel
from pydantic import BaseModel, ValidationError, model_validator

from .analyst import AnalystSpec
from .detectors import KNOWN_KINDS
from .feed import FeedSpec

Action = Literal["allow", "redact", "taint", "escalate", "block"]
Phase = Literal["prompt", "to_model", "tool_result", "tool_call"]   # prompt: the user's request (feed signatures)
# authoritative: deterministic rule, decides alone · corroborating: heuristic, may only taint
# advisory: System One that may at most escalate · semantic: System One that decides approve / review / block
Authority = Literal["authoritative", "corroborating", "advisory", "semantic"]

# Every control in the file is always enforced; there are no monitor or off modes. To stop a control,
# remove it from the file. These three are the floor and cannot be removed: such an edit is rejected.
INVARIANTS = frozenset({"ACC-TOOL-001", "IFC-TRIFECTA-001", "CTL-SELF-001"})

ACTION_SEVERITY = {"allow": 0, "taint": 1, "redact": 2, "escalate": 3, "block": 4}


def _reject_mode(value: Any, where: str) -> Any:
    if isinstance(value, dict) and "mode" in value:
        raise ValueError(f"{where}: there is no `mode` field; every rule always enforces. "
                         "To switch a rule off, delete it from the file.")
    return value


class Identity(BaseModel):
    agent_id: str
    desk: str
    supervisor: str
    allowed_tools: list[str] = []


class ModelSpec(BaseModel):
    id: str
    upstream: Literal["openai", "stub"]
    location: Literal["on_prem", "external"]
    max_class: str


class ToolSpec(BaseModel):
    effect: Literal["read", "write", "delete", "external_send", "financial", "exec"] = "exec"
    reversible: bool = False
    output_integrity: Literal["trusted", "untrusted"] = "trusted"
    output_class: str = "internal"
    egress_allow: list[str] = []


class SystemOneSpec(BaseModel):
    backend: Literal["jev", "stub", "off"] = "stub"
    url: str = "https://api.typesafe.ai/v1/systemone"
    model: str = "jev-latest"
    timeout_ms: int = 1500


class Price(BaseModel):
    usd_per_mtok_in: float = 0.0
    usd_per_mtok_out: float = 0.0
    usd_per_gpu_second: float = 0.0   # local models: internal chargeback per second of inference


class BudgetRule(BaseModel):
    id: str
    scope: str                        # org | desk:<name or *> | agent:<id or *>
    window: Literal["minute", "hour", "day"] = "hour"
    usd: float | None = None
    tokens: float | None = None
    requests: float | None = None
    tool_calls: float | None = None
    max_tokens_per_request: int | None = None
    tool_calls_per_session: int | None = None

    @model_validator(mode="after")
    def _check(self) -> "BudgetRule":
        if self.scope != "org" and self.scope.split(":", 1)[0] not in ("desk", "agent"):
            raise ValueError(f"{self.id}: scope must be org, desk:<name> or agent:<id> (wildcards allowed)")
        return self


class LoopSpec(BaseModel):
    same_call_repeats: int = 4
    window_s: int = 60
    cooldown_s: int = 120


class BudgetSpec(BaseModel):
    default_max_tokens: int = 4096    # reserved for the answer when a client sends no max_tokens
    rules: list[BudgetRule] = []
    loops: LoopSpec = LoopSpec()

    _no_mode = model_validator(mode="before")(lambda v: _reject_mode(v, "budgets"))


class Verify(BaseModel):
    """Second line of defence: a System One question asked AFTER the deterministic step.
    YAML 1.1 turns `true:`/`false:` keys into booleans, hence positive/negative."""
    question: str
    positive: str                      # what counts as a "yes"
    negative: str                      # what must NOT count (placeholders, look-alike numbers...)
    threshold: float = 0.85            # p ≥ threshold → on_fail (results) / human review (actions)
    on_fail: Literal["withhold", "escalate"] = "withhold"
    block_at: float | None = None      # actions only: p ≥ block_at → System One blocks the action
    # actions only: where the rule's meaning applies, e.g. 'tool.effect == "external_send"'; without it,
    # System One is asked about every risky action the rule let through
    when: str | None = None

    _no_mode = model_validator(mode="before")(lambda v: _reject_mode(v, "verify"))


class Control(BaseModel):
    id: str
    title: str
    phase: Phase
    action: Action
    when: str | None = None
    detector: str | None = None
    authority: Authority = "authoritative"
    escalate_at: float | None = None   # System One: p ≥ escalate_at → human review
    block_at: float | None = None      # System One with authority semantic: p ≥ block_at → block
    on_error: Literal["allow", "review", "block"] = "review"   # semantic: System One unavailable
    kinds: list[str] | None = None  # identifier kinds for detector "identifiers", e.g. [PESEL]
    verify: Verify | None = None
    rule: str | None = None         # detector "systemone_rule": a company rule in plain language, judged by System One
    template: str | None = None     # the catalog template this control was made from (the dashboard edits it as a form)
    params: dict[str, Any] | None = None
    # detector "signatures" (signed feed): the lowest severity that counts, and signatures switched off locally
    min_severity: Literal["low", "medium", "high", "critical"] | None = None
    exclude: list[str] | None = None

    _no_mode = model_validator(mode="before")(lambda v: _reject_mode(v, (v or {}).get("id", "kontrolka")))

    @model_validator(mode="after")
    def _check(self) -> "Control":
        if not self.when and not self.detector:
            raise ValueError(f"{self.id}: needs `when` or `detector`")
        if self.detector == "systemone_rule":
            if not (self.rule or "").strip():
                raise ValueError(f"{self.id}: detector `systemone_rule` needs `rule`: the company rule in plain language")
            if self.phase != "tool_call":
                raise ValueError(f"{self.id}: a plain-language rule is checked on actions (phase: tool_call)")
            if self.authority not in ("semantic", "advisory"):
                raise ValueError(f"{self.id}: a plain-language rule is judged by System One (authority: semantic)")
        if self.detector == "signatures":
            if self.phase not in ("prompt", "tool_call", "tool_result"):
                raise ValueError(f"{self.id}: signatures run on prompt, tool_call or tool_result")
            if self.action not in ("block", "escalate", "taint"):
                raise ValueError(f"{self.id}: for signatures `action` is the strongest one allowed: block, escalate or taint")
        elif self.min_severity is not None or self.exclude:
            raise ValueError(f"{self.id}: min_severity and exclude belong to detector `signatures`")
        if self.phase == "prompt" and self.detector != "signatures":
            raise ValueError(f"{self.id}: phase `prompt` is checked by the signature feed (detector: signatures)")
        if self.detector == "identifiers":
            if not self.kinds:
                raise ValueError(f"{self.id}: detector `identifiers` needs `kinds`, e.g. [PESEL]")
            unknown = set(self.kinds) - KNOWN_KINDS
            if unknown:
                raise ValueError(f"{self.id}: unknown kinds {sorted(unknown)}; known: {sorted(KNOWN_KINDS)}")
        if self.verify and self.phase == "tool_call" and self.verify.on_fail != "escalate":
            raise ValueError(f"{self.id}: verify on a tool_call escalates; use verify.block_at to let System One block")
        if self.verify and self.verify.block_at is not None:
            if self.phase != "tool_call":
                raise ValueError(f"{self.id}: verify.block_at is for actions; on results the ladder ends in withhold")
            if self.verify.block_at < self.verify.threshold:
                raise ValueError(f"{self.id}: verify.block_at must be ≥ verify.threshold")
        if self.block_at is not None:
            if self.authority != "semantic":
                raise ValueError(f"{self.id}: block_at needs authority: semantic (System One allowed to block)")
            if self.escalate_at is not None and self.block_at < self.escalate_at:
                raise ValueError(f"{self.id}: block_at must be ≥ escalate_at")
        if self.verify and self.phase == "tool_result" and self.detector != "identifiers":
            raise ValueError(f"{self.id}: verify on tool_result needs detector `identifiers`")
        # Advisory backends (System One, LLMs) may never block, whatever the file says.
        if self.authority == "advisory" and self.action == "block":
            raise ValueError(f"{self.id}: advisory controls may at most escalate")
        return self


class PolicyDoc(BaseModel):
    apiVersion: str
    meta: dict[str, Any]
    org: dict[str, Any] = {}
    classification: list[str]
    identities: dict[str, Identity]
    models: list[ModelSpec]
    tools: dict[str, ToolSpec]
    systemone: SystemOneSpec = SystemOneSpec()
    prices: dict[str, Price] = {}
    budgets: BudgetSpec = BudgetSpec()
    feed: FeedSpec | None = None      # signed signature feed from the threat-intel system (see feed.py)
    analyst: AnalystSpec | None = None   # background LLM analyst and daily report (see analyst.py)
    controls: list[Control]

    @model_validator(mode="before")
    @classmethod
    def _no_defaults(cls, v: Any) -> Any:
        if isinstance(v, dict) and ("defaults" in v or "profiles" in v):
            raise ValueError("there are no `defaults` or `profiles` sections; every rule always enforces")
        return v

    @model_validator(mode="after")
    def _check(self) -> "PolicyDoc":
        for m in self.models:
            if m.max_class not in self.classification:
                raise ValueError(f"model {m.id}: unknown max_class {m.max_class!r}")
        for name, t in self.tools.items():
            if t.output_class not in self.classification:
                raise ValueError(f"tool {name}: unknown output_class {t.output_class!r}")
        ids: set[str] = set()
        for c in self.controls:
            if c.id in ids:
                raise ValueError(f"duplicate control id {c.id!r}: every control needs its own id")
            ids.add(c.id)
        missing = INVARIANTS - ids
        if missing:
            raise ValueError(f"invariant controls cannot be removed: {sorted(missing)}")
        return self


_CEL_ENV = cel.NewEnv(
    variables={name: cel.Type.DYN for name in ("identity", "session", "tool", "args", "facts")}
)


@dataclass
class LoadedPolicy:
    doc: PolicyDoc
    sha: str
    compiled: dict[str, Any] = field(default_factory=dict)

    @property
    def rev(self) -> int:
        return int(self.doc.meta.get("policy_rev", 0))

    def class_rank(self, name: str) -> int:
        return self.doc.classification.index(name)

    def tool(self, name: str) -> ToolSpec:
        return self.doc.tools.get(name) or self.doc.tools.get("*") or ToolSpec()

    def model(self, model_id: str) -> ModelSpec | None:
        return next((m for m in self.doc.models if m.id == model_id), None)

    def controls_for(self, phase: Phase) -> list[Control]:
        return [c for c in self.doc.controls if c.phase == phase]

    def eval_when(self, control: Control, data: dict[str, Any], key: str | None = None) -> tuple[bool | None, str | None]:
        """Returns (matched, error). A CEL error is reported, never silently treated as False."""
        expr = self.compiled[key or control.id]
        result = expr.eval(data=data)
        if result.type() == cel.Type.BOOL:
            return bool(result.value()), None
        return None, str(result.value())


def load_policy(path: Path) -> LoadedPolicy:
    raw = path.read_bytes()
    doc = PolicyDoc.model_validate(yaml.safe_load(raw))
    loaded = LoadedPolicy(doc=doc, sha=hashlib.sha256(raw).hexdigest()[:12])
    for c in doc.controls:
        for key, expr in ((c.id, c.when), (f"{c.id}/verify", c.verify.when if c.verify else None)):
            if not expr:
                continue
            try:
                loaded.compiled[key] = _CEL_ENV.compile(expr, disable_check=True)
            except Exception as e:  # compile errors come back as generic exceptions
                raise ValueError(f"{key}: CEL does not compile: {e}") from e
    return loaded


class PolicyStore:
    """Re-reads the file when its mtime changes; on any error keeps the last good version."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._mtime = path.stat().st_mtime_ns
        self.current = load_policy(path)
        self.last_error: str | None = None
        self.events: list[str] = []

    def get(self) -> LoadedPolicy:
        try:
            mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            self._note_error("policy file missing; keeping last good version")
            return self.current
        if mtime == self._mtime:
            return self.current
        with self._lock:
            if mtime == self._mtime:
                return self.current
            self._mtime = mtime
            try:
                new = load_policy(self.path)
            except (ValidationError, ValueError, yaml.YAMLError) as e:
                self._note_error(f"rejected edit, keeping rev {self.current.rev} ({self.current.sha}): {e}")
                return self.current
            old = self.current
            self.current = new
            self.last_error = None
            self.events.append(f"loaded rev {new.rev} ({new.sha}), was rev {old.rev} ({old.sha})")
            return new

    def _note_error(self, msg: str) -> None:
        self.last_error = msg
        self.events.append(msg)
