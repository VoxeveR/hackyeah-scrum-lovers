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

from .detectors import KNOWN_KINDS

Action = Literal["allow", "redact", "taint", "escalate", "block"]
Mode = Literal["enforce", "monitor", "off"]
Phase = Literal["to_model", "tool_result", "tool_call"]
Authority = Literal["authoritative", "corroborating", "advisory"]

# The floor: these controls must exist and always run in enforce mode,
# whatever the profile or the file says. Editing the file cannot switch them off.
INVARIANTS = frozenset({"ACC-TOOL-001", "IFC-TRIFECTA-001", "CTL-SELF-001"})

ACTION_SEVERITY = {"allow": 0, "taint": 1, "redact": 2, "escalate": 3, "block": 4}


class Profile(BaseModel):
    default_mode: Mode = "enforce"
    on_eval_error: Action = "block"


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


class Verify(BaseModel):
    """Second line of defence: a System One question asked AFTER the deterministic step.
    YAML 1.1 turns `true:`/`false:` keys into booleans, hence positive/negative."""
    question: str
    positive: str                      # what counts as a "yes"
    negative: str                      # what must NOT count (placeholders, look-alike numbers...)
    threshold: float = 0.85
    on_fail: Literal["withhold", "escalate"] = "withhold"
    mode: Mode | None = None           # verify can run in monitor while the rule itself enforces


class Control(BaseModel):
    id: str
    title: str
    phase: Phase
    action: Action
    when: str | None = None
    detector: str | None = None
    mode: Mode | None = None
    authority: Authority = "authoritative"
    escalate_at: float | None = None
    kinds: list[str] | None = None  # identifier kinds for detector "identifiers", e.g. [PESEL]
    verify: Verify | None = None

    @model_validator(mode="after")
    def _check(self) -> "Control":
        if not self.when and not self.detector:
            raise ValueError(f"{self.id}: needs `when` or `detector`")
        if self.detector == "identifiers":
            if not self.kinds:
                raise ValueError(f"{self.id}: detector `identifiers` needs `kinds`, e.g. [PESEL]")
            unknown = set(self.kinds) - KNOWN_KINDS
            if unknown:
                raise ValueError(f"{self.id}: unknown kinds {sorted(unknown)}; known: {sorted(KNOWN_KINDS)}")
        if self.verify and self.phase == "tool_call" and self.verify.on_fail != "escalate":
            raise ValueError(f"{self.id}: verify on a tool_call can only escalate (System One never blocks an action alone)")
        if self.verify and self.phase == "tool_result" and self.detector != "identifiers":
            raise ValueError(f"{self.id}: verify on tool_result needs detector `identifiers`")
        # Advisory backends (System One, LLMs) may never block, whatever the file says.
        if self.authority == "advisory" and self.action == "block":
            raise ValueError(f"{self.id}: advisory controls may at most escalate")
        return self


class PolicyDoc(BaseModel):
    apiVersion: str
    meta: dict[str, Any]
    profiles: dict[str, Profile]
    org: dict[str, Any] = {}
    classification: list[str]
    identities: dict[str, Identity]
    models: list[ModelSpec]
    tools: dict[str, ToolSpec]
    systemone: SystemOneSpec = SystemOneSpec()
    controls: list[Control]

    @model_validator(mode="after")
    def _check(self) -> "PolicyDoc":
        if self.meta.get("active_profile") not in self.profiles:
            raise ValueError(f"active_profile {self.meta.get('active_profile')!r} is not defined in profiles")
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

    @property
    def profile_name(self) -> str:
        return self.doc.meta["active_profile"]

    @property
    def profile(self) -> Profile:
        return self.doc.profiles[self.profile_name]

    def mode_of(self, control: Control) -> Mode:
        if control.id in INVARIANTS:
            return "enforce"
        return control.mode or self.profile.default_mode

    def class_rank(self, name: str) -> int:
        return self.doc.classification.index(name)

    def tool(self, name: str) -> ToolSpec:
        return self.doc.tools.get(name) or self.doc.tools.get("*") or ToolSpec()

    def model(self, model_id: str) -> ModelSpec | None:
        return next((m for m in self.doc.models if m.id == model_id), None)

    def controls_for(self, phase: Phase) -> list[Control]:
        return [c for c in self.doc.controls if c.phase == phase]

    def eval_when(self, control: Control, data: dict[str, Any]) -> tuple[bool | None, str | None]:
        """Returns (matched, error). A CEL error is reported, never silently treated as False."""
        expr = self.compiled[control.id]
        result = expr.eval(data=data)
        if result.type() == cel.Type.BOOL:
            return bool(result.value()), None
        return None, str(result.value())


def load_policy(path: Path) -> LoadedPolicy:
    raw = path.read_bytes()
    doc = PolicyDoc.model_validate(yaml.safe_load(raw))
    loaded = LoadedPolicy(doc=doc, sha=hashlib.sha256(raw).hexdigest()[:12])
    for c in doc.controls:
        if c.when:
            try:
                loaded.compiled[c.id] = _CEL_ENV.compile(c.when, disable_check=True)
            except Exception as e:  # compile errors come back as generic exceptions
                raise ValueError(f"{c.id}: CEL does not compile: {e}") from e
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
