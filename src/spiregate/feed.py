"""Signed signature feed: known attacks on AI infrastructure, published by an external threat-intel system.

The feed is not part of the policy. Another team (or a vendor) publishes signatures; the gateway trusts only
bundles signed with a key pinned in the policy (`feed.trusted_keys`). Same rules as for the policy file: a bad
bundle (wrong signature, unknown key, older version, expired, a signature that fails its own examples) is
rejected and the gateway keeps the last good one. The last good bundle is cached on disk, so a restart while
the feed server is down does not drop protection.

The policy decides how the feed is applied: controls with `detector: signatures` pick the phase (prompt,
tool_call, tool_result), the lowest severity that counts (`min_severity`), exceptions (`exclude`) and the
strongest action a signature may take (`action`: block as published, escalate, or only taint).

Matchers are deterministic and never execute anything; pickles are disassembled, never loaded:
  regex          - Python regex on canonicalised text (NFKC, invisible characters removed), case-insensitive
  pickle_globals - pickle payloads (base64 or protocol-0 text in content, model files an action refers to)
                   whose imports match, e.g. posix.system, builtins.eval
  packages       - pip / uv / poetry installs of known-compromised packages or versions
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import fnmatch
import hashlib
import json
import os
import pickletools
import re
import shlex
import threading
import time
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Literal

import httpx
import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError, model_validator

from .detectors import Redactor, canonicalize

ROOT = Path(__file__).resolve().parents[2]
FORMAT = "spire-feed/v1"

Severity = Literal["low", "medium", "high", "critical"]
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SigPhase = Literal["prompt", "tool_call", "tool_result"]
SigAction = Literal["taint", "escalate", "block"]
_ACTION_RANK = {"allow": 0, "taint": 1, "redact": 2, "escalate": 3, "block": 4}  # same order as the policy's

MODEL_EXTENSIONS = ("pkl", "pickle", "pt", "pth", "bin", "ckpt", "joblib", "dill", "sav")
MAX_TEXT = 1_000_000          # characters scanned per call
MAX_FILE = 64 * 1024 * 1024   # bytes read from one model file or zip member


class FeedError(ValueError):
    """A bundle that must not be loaded; the message says why (dashboard, log, CLI)."""


# ================================================================== schema

def _public_key(b64: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise FeedError("the public key is not valid base64") from e
    if len(raw) != 32:
        raise FeedError(f"an Ed25519 public key has 32 bytes, this one has {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


class FeedSpec(BaseModel):
    """The policy's `feed:` section."""
    source: str = "feed/bundle.json"          # path relative to the repo, or an http(s) URL
    trusted_keys: dict[str, str]               # key_id -> raw Ed25519 public key, base64
    refresh_s: int = 30                        # polling interval for an http source

    @model_validator(mode="after")
    def _check(self) -> "FeedSpec":
        if not self.trusted_keys:
            raise ValueError("feed.trusted_keys: at least one public key is required")
        for kid, key in self.trusted_keys.items():
            try:
                _public_key(key)
            except FeedError as e:
                raise ValueError(f"feed.trusted_keys.{kid}: {e}") from e
        if self.refresh_s < 1:
            raise ValueError("feed.refresh_s: at least 1 second")
        return self


class PackageRule(BaseModel):
    name: str
    versions: list[str] = []      # empty: every version is malicious


class Examples(BaseModel):
    hit: list[str]                # must match (checked when signing and again when loading)
    miss: list[str] = []          # must not match


class Signature(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    phases: list[SigPhase]
    action: SigAction = "block"
    refs: list[str] = []
    regex: list[str] = []
    pickle_globals: list[str] = []
    packages: list[PackageRule] = []
    examples: Examples

    @model_validator(mode="after")
    def _check(self) -> "Signature":
        if not (self.regex or self.pickle_globals or self.packages):
            raise ValueError(f"{self.id}: needs regex, pickle_globals or packages")
        if not self.phases:
            raise ValueError(f"{self.id}: needs at least one phase")
        if not self.examples.hit:
            raise ValueError(f"{self.id}: every signature needs a `hit` example that it detects")
        return self


class BundlePayload(BaseModel):
    feed: str
    version: int
    issued_at: datetime
    expires_at: datetime
    signatures: list[Signature]

    @model_validator(mode="after")
    def _check(self) -> "BundlePayload":
        ids = [s.id for s in self.signatures]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate signature ids: {dupes}")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("issued_at and expires_at need a time zone")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self


# ================================================================== pickle analysis (nothing is ever unpickled)

_STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "SHORT_BINSTRING", "BINSTRING", "STRING"}
_PUT_OPS = {"PUT", "BINPUT", "LONG_BINPUT"}
_GET_OPS = {"GET", "BINGET", "LONG_BINGET"}
UNRESOLVED = "?.?"  # STACK_GLOBAL whose module/name could not be read: treated as dangerous


def pickle_imports(data: bytes, max_ops: int = 500_000) -> list[str] | None:
    """Imports a pickle would perform when loaded, read from its opcodes. None: not a pickle."""
    found: list[str] = []
    recent: list[Any] = []        # values pushed lately; STACK_GLOBAL takes the last two
    memo: dict[int, Any] = {}
    ops = 0
    try:
        for op, arg, _pos in pickletools.genops(data):
            ops += 1
            if ops > max_ops:
                break
            name = op.name
            if name in ("GLOBAL", "INST"):
                module, _, attr = str(arg).partition(" ")
                found.append(f"{module}.{attr}")
                recent.append(None)
            elif name == "STACK_GLOBAL":
                module, attr = (recent[-2], recent[-1]) if len(recent) >= 2 else (None, None)
                ok = isinstance(module, str) and isinstance(attr, str)
                found.append(f"{module}.{attr}" if ok else UNRESOLVED)
                recent.append(None)
            elif name in _STRING_OPS:
                recent.append(arg.decode("latin-1") if isinstance(arg, bytes) else str(arg))
            elif name == "MEMOIZE":
                memo[len(memo)] = recent[-1] if recent else None
            elif name in _PUT_OPS:
                memo[arg] = recent[-1] if recent else None
            elif name in _GET_OPS:
                recent.append(memo.get(arg))
            elif name == "STOP":
                break
            elif name not in ("PROTO", "FRAME"):
                recent.append(None)
    except Exception:  # truncated or not a pickle at all
        if not found and ops <= 1:
            return None
    return found


_B64_PICKLE = re.compile(r"(?<![A-Za-z0-9+/])gA[JNSU][A-Za-z0-9+/]{6,}={0,2}")  # base64 of \x80\x02 .. \x80\x05 (pickle PROTO)
_PROTO0_GLOBAL = re.compile(r"(?:^|[^\w])[ci]([A-Za-z_][\w.]*)\n([A-Za-z_][\w.]*)\n")


def text_pickle_imports(text: str, max_candidates: int = 20) -> list[tuple[str, str]]:
    """(import, where) for pickles embedded in text: base64 blobs and protocol-0 text."""
    out: list[tuple[str, str]] = []
    for m in list(_B64_PICKLE.finditer(text))[:max_candidates]:
        s = m.group(0)
        try:
            data = base64.b64decode(s + "=" * (-len(s) % 4))
        except (binascii.Error, ValueError):
            continue
        out += [(imp, "base64") for imp in (pickle_imports(data[:MAX_FILE]) or [])]
    out += [(f"{mod}.{name}", "protocol 0") for mod, name in _PROTO0_GLOBAL.findall(text)]
    return out


_FILE_CACHE: dict[tuple[str, int, int], list[str] | None] = {}


def model_file_imports(path: Path) -> list[str] | None:
    """Imports inside a model file: a PyTorch zip (every *.pkl member) or a raw pickle. None: not a pickle."""
    try:
        st = path.stat()
    except OSError:
        return None
    key = (str(path), st.st_mtime_ns, st.st_size)
    if key in _FILE_CACHE:
        return _FILE_CACHE[key]
    result: list[str] | None = None
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if info.filename.endswith(".pkl") and info.file_size <= MAX_FILE:
                        result = (result or []) + (pickle_imports(z.read(info)) or [])
        else:
            with path.open("rb") as f:
                head = f.read(MAX_FILE)
            if head[:1] in (b"\x80", b"c", b"(", b"]", b"}"):
                result = pickle_imports(head)
    except (OSError, zipfile.BadZipFile):
        result = None
    if len(_FILE_CACHE) > 256:
        _FILE_CACHE.clear()
    _FILE_CACHE[key] = result
    return result


_MODEL_PATH = re.compile(r"[\w.~/-]*[\w-]\.(?:" + "|".join(MODEL_EXTENSIONS) + r")\b", re.I)


def model_paths(texts: Iterable[str], cwd: str | None = None, limit: int = 10) -> list[Path]:
    """Existing model files an action refers to (a path in a command, a file_path argument...)."""
    out: list[Path] = []
    for t in texts:
        for m in _MODEL_PATH.finditer(t):
            p = Path(os.path.expanduser(m.group(0)))
            if not p.is_absolute():
                p = Path(cwd or os.getcwd()) / p
            try:
                if p.is_file() and p not in out:
                    out.append(p)
            except OSError:
                continue
            if len(out) >= limit:
                return out
    return out


# ================================================================== package installs

_INSTALL = re.compile(
    r"\b(?:pip3?(?:\.\d+)?|python3?(?:\.\d+)?\s+-m\s+pip|uv\s+pip|uv|poetry|pipx|pdm|rye)\s+(?:install|add)\b([^\n;&|]*)",
    re.I)
_OPTS_WITH_VALUE = {"-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-f",
                    "--find-links", "-t", "--target", "--prefix", "--root", "--python", "-p", "--group", "-e",
                    "--editable", "--source"}
_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:===?\s*([A-Za-z0-9.!+_-]+))?")
_PINNED = re.compile(r"(?<![\w.-])([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.!+_-]+)")


def _norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def installed_packages(text: str) -> list[tuple[str, str | None]]:
    """(name, pinned version or None) for every package an install command (or a pinned requirement) names."""
    out: list[tuple[str, str | None]] = []
    for m in _INSTALL.finditer(text):
        try:
            tokens = shlex.split(m.group(1))
        except ValueError:
            tokens = m.group(1).split()
        skip = False
        for t in tokens:
            if skip:
                skip = False
                continue
            if t.startswith("-"):
                skip = t in _OPTS_WITH_VALUE
                continue
            if "://" in t or t.startswith((".", "/")):
                continue
            r = _REQ.match(t)
            if r:
                out.append((_norm_pkg(r.group(1)), r.group(2)))
    out += [(_norm_pkg(n), v) for n, v in _PINNED.findall(text)]
    return out


# ================================================================== compiled signatures

def _snippet(s: str, n: int = 80) -> str:
    s = " ".join(s.split())
    s = Redactor().redact(s)[0]  # a matched fragment may carry PII or secrets; logs never get them raw
    return s if len(s) <= n else s[: n - 1] + "…"


def _prepare(texts: Iterable[str]) -> list[str]:
    out, budget = [], MAX_TEXT
    for t in texts:
        if not isinstance(t, str) or not t or budget <= 0:
            continue
        t = t[:budget]
        budget -= len(t)
        out.append(canonicalize(t)[0])
    return out


@dataclass
class Hit:
    signature: Signature
    detail: str


class CompiledSignature:
    def __init__(self, sig: Signature):
        self.sig = sig
        try:
            self.regex = [re.compile(p, re.I | re.M) for p in sig.regex]
        except re.error as e:
            raise FeedError(f"{sig.id}: regex does not compile: {e}") from e
        self.packages = [(_norm_pkg(p.name), set(p.versions)) for p in sig.packages]

    def _dangerous(self, imp: str) -> bool:
        return imp == UNRESOLVED or any(fnmatch.fnmatchcase(imp, p) for p in self.sig.pickle_globals)

    def match_text(self, text: str) -> str | None:
        for rx in self.regex:
            m = rx.search(text)
            if m:
                return f"\"{_snippet(m.group(0))}\""
        if self.sig.pickle_globals:
            for imp, where in text_pickle_imports(text):
                if self._dangerous(imp):
                    return f"pickle ({where}) imports {imp}"
        for name, version in installed_packages(text) if self.packages else ():
            for bad, versions in self.packages:
                if name == bad and (not versions or version in versions):
                    return f"package {name}" + (f"=={version}" if version else "")
        return None

    def match_file(self, path: Path, imports: list[str]) -> str | None:
        if self.sig.pickle_globals:
            for imp in imports:
                if self._dangerous(imp):
                    return f"file {path.name} imports {imp} when loaded"
        return None


def self_test(compiled: list[CompiledSignature]) -> list[str]:
    """Every signature proves itself: each `hit` example matches, no `miss` example does."""
    problems = []
    for c in compiled:
        for i, ex in enumerate(c.sig.examples.hit):
            if not any(c.match_text(t) for t in _prepare([ex])):
                problems.append(f"{c.sig.id}: example hit[{i}] does not match")
        for i, ex in enumerate(c.sig.examples.miss):
            detail = next((d for t in _prepare([ex]) if (d := c.match_text(t))), None)
            if detail:
                problems.append(f"{c.sig.id}: example miss[{i}] matches ({detail})")
    return problems


@dataclass
class LoadedFeed:
    payload: BundlePayload
    sha: str
    key_id: str
    origin: str
    compiled: list[CompiledSignature]
    loaded_at: datetime = field(default_factory=lambda: _now())

    @property
    def version(self) -> int:
        return self.payload.version

    def expired(self, now: datetime | None = None) -> bool:
        return (now or _now()) > self.payload.expires_at

    def scan(self, phase: str, texts: Iterable[str], files: Iterable[Path] = (), *,
             min_severity: str | None = None, exclude: Iterable[str] = ()) -> list[Hit]:
        floor = SEVERITY_RANK.get(min_severity or "low", 0)
        excluded = set(exclude)
        sigs = [c for c in self.compiled if phase in c.sig.phases and c.sig.id not in excluded
                and SEVERITY_RANK[c.sig.severity] >= floor]
        if not sigs:
            return []
        prepared = _prepare(texts)
        file_imports: list[tuple[Path, list[str]]] = []
        if any(c.sig.pickle_globals for c in sigs):
            file_imports = [(p, imps) for p in files for imps in [model_file_imports(p)] if imps]
        hits = []
        for c in sigs:
            detail = next((d for t in prepared if (d := c.match_text(t))), None)
            if detail is None:
                detail = next((d for p, imps in file_imports if (d := c.match_file(p, imps))), None)
            if detail:
                hits.append(Hit(c.sig, detail))
        return hits


# ================================================================== signing and verification

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def public_key_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def generate_key(path: Path, key_id: str, note: str = "") -> str:
    """Writes a new private key (JSON) and returns its public key for the policy's trusted_keys."""
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"key_id": key_id, "note": note, "public_key": public_key_b64(key),
                                "private_key": base64.b64encode(raw).decode()}, indent=2) + "\n", encoding="utf-8")
    return public_key_b64(key)


def load_private_key(path: Path) -> tuple[Ed25519PrivateKey, str]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(doc["private_key"])), doc["key_id"]


def sign_payload(payload: dict[str, Any], key: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    signature = base64.b64encode(key.sign(canonical(payload))).decode()
    return {"format": FORMAT, "key_id": key_id, "signature": signature, "payload": payload}


def _first_error(e: ValidationError) -> str:
    err = e.errors()[0]
    where = ".".join(str(x) for x in err.get("loc", ()))
    return f"{where}: {err.get('msg')}" if where else str(err.get("msg"))


def _compile(payload: dict[str, Any]) -> tuple[BundlePayload, list[CompiledSignature]]:
    try:
        doc = BundlePayload.model_validate(payload)
    except ValidationError as e:
        raise FeedError(f"invalid schema: {_first_error(e)}") from e
    compiled = [CompiledSignature(s) for s in doc.signatures]
    problems = self_test(compiled)
    if problems:
        raise FeedError("a signature fails its own examples: " + "; ".join(problems[:3]))
    return doc, compiled


def build_bundle(source: Path, key_path: Path, previous: Path | None = None, days: int = 30,
                 now: datetime | None = None) -> dict[str, Any]:
    """Signatures source (YAML, edited by the threat-intel team) -> signed bundle with the next version.
    Validated and self-tested exactly as the gateway will, so a broken signature is never signed."""
    doc = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    key, key_id = load_private_key(key_path)
    prev = 0
    if previous is not None and previous.exists():
        try:
            prev = int(json.loads(previous.read_bytes())["payload"]["version"])
        except (ValueError, KeyError, TypeError):
            prev = 0
    now = now or _now()
    payload = {"feed": str(doc.get("feed") or "spire-intel"), "version": max(prev + 1, int(doc.get("version") or 0)),
               "issued_at": _iso(now), "expires_at": _iso(now + timedelta(days=days)),
               "signatures": doc.get("signatures") or []}
    parsed, _ = _compile(payload)
    # sign the normalised form, so what the gateway re-validates is byte-for-byte what was signed
    payload["signatures"] = [s.model_dump(mode="json") for s in parsed.signatures]
    return sign_payload(payload, key, key_id)


def verify_bundle(raw: bytes, trusted_keys: dict[str, str], origin: str) -> LoadedFeed:
    try:
        env = json.loads(raw)
    except ValueError as e:
        raise FeedError("not JSON") from e
    if not isinstance(env, dict) or env.get("format") != FORMAT:
        raise FeedError(f"unknown bundle format (expected {FORMAT})")
    key_id = env.get("key_id")
    if key_id not in trusted_keys:
        raise FeedError(f"signed with key {key_id!r}, which the policy does not trust (feed.trusted_keys)")
    payload = env.get("payload")
    if not isinstance(payload, dict):
        raise FeedError("no payload")
    public = _public_key(trusted_keys[key_id])
    try:
        public.verify(base64.b64decode(str(env.get("signature", "")), validate=True), canonical(payload))
    except (InvalidSignature, binascii.Error, ValueError) as e:
        raise FeedError(f"bad signature (key {key_id}): content changed after signing, or signed with another key") from e
    doc, compiled = _compile(payload)
    return LoadedFeed(doc, hashlib.sha256(canonical(payload)).hexdigest()[:12], key_id, origin, compiled)


# ================================================================== store: hot reload, polling, cache

def _remote(source: str) -> bool:
    return source.startswith(("http://", "https://"))


class FeedStore:
    """Holds the last good bundle. A local source is re-read when its mtime changes (on every request,
    like the policy); an http source is polled in the background every refresh_s, with ETag."""

    def __init__(self, root: Path = ROOT, cache_path: Path | None = None,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.root = root
        self.cache_path = cache_path
        self.transport = transport              # tests inject the feed server's ASGI app here
        self.current: LoadedFeed | None = None
        self.last_error: str | None = None
        self.events: list[dict[str, Any]] = []
        self.last_pull: dict[str, Any] | None = None
        self._lock = threading.RLock()  # sync() holds it while the cache is loaded through accept()
        self._spec_key: tuple | None = None
        self._mtime: int | str | None = None
        self._etag: str | None = None
        self._next_pull = 0.0
        self._task: asyncio.Task | None = None

    # ------------------------------------------------------------ public
    def sync(self, spec: FeedSpec | None) -> LoadedFeed | None:
        """Called on every request with the policy's current `feed` section."""
        key = (spec.source, tuple(sorted(spec.trusted_keys.items()))) if spec else None
        if key != self._spec_key:
            with self._lock:
                if key != self._spec_key:
                    self._reset(spec, key)
        if spec is None:
            return None
        if _remote(spec.source):
            self._schedule_pull(spec)
        else:
            self._check_file(spec)
        return self.current

    async def pull(self, spec: FeedSpec, force: bool = False) -> bool:
        """Fetches an http source now. Returns True when a new version was loaded."""
        if not _remote(spec.source):
            if force:
                self._mtime = None
            before = self.current.sha if self.current else None
            self._check_file(spec)
            return bool(self.current and self.current.sha != before)
        self._next_pull = time.monotonic() + spec.refresh_s
        headers = {"If-None-Match": self._etag} if self._etag and not force else {}
        t = time.perf_counter()
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=5, trust_env=False) as client:
                r = await client.get(spec.source, headers=headers)
        except httpx.HTTPError as e:
            self.last_pull = {"ts": _iso(_now()), "ok": False, "status": None, "ms": _ms(t)}
            self._error(f"feed server unreachable ({type(e).__name__}); {self._keeping()}", quiet_repeat=True)
            return False
        self.last_pull = {"ts": _iso(_now()), "ok": r.status_code in (200, 304), "status": r.status_code, "ms": _ms(t)}
        if r.status_code == 304:
            return False
        if r.status_code != 200:
            self._error(f"feed server returned HTTP {r.status_code}; {self._keeping()}", quiet_repeat=True)
            return False
        ok = self.accept(r.content, spec, origin=spec.source)
        if ok:
            self._etag = r.headers.get("etag")
        return ok

    def accept(self, raw: bytes, spec: FeedSpec, origin: str, *, from_cache: bool = False) -> bool:
        try:
            new = verify_bundle(raw, spec.trusted_keys, origin)
        except FeedError as e:
            self._error(f"rejected bundle from {origin}: {e}; {self._keeping()}")
            return False
        with self._lock:
            cur = self.current
            if cur is not None and new.sha == cur.sha:
                return False
            if cur is not None and new.payload.feed == cur.payload.feed and new.version <= cur.version:
                self._error(f"rejected v{new.version} from {origin}: not newer than the running v{cur.version} "
                            "(rollback protection)")
                return False
            if new.expired() and not from_cache:
                self._error(f"rejected v{new.version} from {origin}: bundle expired {_iso(new.payload.expires_at)}; "
                            f"{self._keeping()}")
                return False
            self.current = new
            self.last_error = None
        stale = " (EXPIRED, from cache)" if new.expired() else ""
        was = f", was v{cur.version}" if cur else ""
        self._event(True, f"loaded {new.payload.feed} v{new.version}{stale}: {len(new.compiled)} signatures, "
                          f"key {new.key_id}, source {'cache' if from_cache else origin}{was}")
        if not from_cache:
            self._write_cache(raw)
        return True

    def status(self, spec: FeedSpec | None) -> dict[str, Any]:
        cur = self.current
        out: dict[str, Any] = {
            "configured": spec is not None, "source": spec.source if spec else None,
            "remote": bool(spec and _remote(spec.source)), "refresh_s": spec.refresh_s if spec else None,
            "trusted_keys": sorted(spec.trusted_keys) if spec else [], "loaded": cur is not None,
            "error": self.last_error, "events": self.events[-10:], "last_pull": self.last_pull,
        }
        if cur is not None:
            out.update(feed=cur.payload.feed, version=cur.version, sha=cur.sha, key_id=cur.key_id, origin=cur.origin,
                       issued_at=_iso(cur.payload.issued_at), expires_at=_iso(cur.payload.expires_at),
                       expired=cur.expired(), loaded_at=_iso(cur.loaded_at),
                       signatures=[{"id": c.sig.id, "title": c.sig.title, "category": c.sig.category,
                                    "severity": c.sig.severity, "action": c.sig.action, "phases": c.sig.phases,
                                    "refs": c.sig.refs} for c in cur.compiled])
        return out

    # ------------------------------------------------------------ internals
    def _reset(self, spec: FeedSpec | None, key: tuple | None) -> None:
        had = self._spec_key is not None
        self._spec_key, self.current, self._mtime, self._etag, self._next_pull = key, None, None, None, 0.0
        if spec is None:
            if had:
                self._event(False, "the policy has no feed section: signatures are off")
            return
        if had:
            self._event(True, f"feed source or keys changed in the policy: reloading ({spec.source})")
        self._load_cache(spec)

    def _path(self, source: str) -> Path:
        p = Path(os.path.expanduser(source))
        return p if p.is_absolute() else self.root / p

    def _check_file(self, spec: FeedSpec) -> None:
        path = self._path(spec.source)
        try:
            mtime: int | str = path.stat().st_mtime_ns
        except OSError:
            mtime = "missing"
        if mtime == self._mtime:
            return
        self._mtime = mtime
        if mtime == "missing":
            self._error(f"feed file missing: {path}; {self._keeping()}")
            return
        self.accept(path.read_bytes(), spec, origin=str(spec.source))

    def _schedule_pull(self, spec: FeedSpec) -> None:
        if time.monotonic() < self._next_pull or (self._task is not None and not self._task.done()):
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no event loop (CLI, sync tests): the next request inside the server pulls
        self._next_pull = time.monotonic() + spec.refresh_s
        self._task = loop.create_task(self.pull(spec))

    def _load_cache(self, spec: FeedSpec) -> None:
        if self.cache_path is None or not self.cache_path.exists():
            return
        self.accept(self.cache_path.read_bytes(), spec, origin=str(self.cache_path), from_cache=True)

    def _write_cache(self, raw: bytes) -> None:
        if self.cache_path is None:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_bytes(raw)
            tmp.replace(self.cache_path)
        except OSError as e:
            self._event(False, f"could not write the feed cache: {e}")

    def _keeping(self) -> str:
        cur = self.current
        return f"v{cur.version} keeps running" if cur else "no signatures loaded"

    def _error(self, message: str, quiet_repeat: bool = False) -> None:
        repeat = self.last_error == message
        self.last_error = message
        if not (quiet_repeat and repeat):
            self._event(False, message)

    def _event(self, ok: bool, message: str) -> None:
        self.events.append({"ts": _iso(_now()), "ok": ok, "message": message})
        del self.events[:-50]


def _ms(t: float) -> float:
    return round((time.perf_counter() - t) * 1000, 1)


# ================================================================== what the decision core calls

def signals_for(feed: LoadedFeed | None, controls: Iterable[Any], phase: str, texts: Iterable[str],
                files: Iterable[Path] = ()) -> list[dict[str, Any]]:
    """Signals from every `detector: signatures` control of this phase.

    The control's `action` caps what a signature may do: block (as published), escalate (at most human
    review) or taint (only label the session). `min_severity` and `exclude` choose which signatures count."""
    controls = [c for c in controls if getattr(c, "detector", None) == "signatures"]
    if feed is None or not controls:
        return []
    texts, files = list(texts), list(files)
    out = []
    for c in controls:
        hits = feed.scan(phase, texts, files, min_severity=getattr(c, "min_severity", None),
                         exclude=getattr(c, "exclude", None) or ())
        for h in hits:
            action = min(h.signature.action, c.action, key=_ACTION_RANK.__getitem__)
            out.append({"control": c.id, "action": action, "authority": "authoritative",
                        "reason": f"{h.signature.id} {h.signature.title}: {h.detail}",
                        "signature": h.signature.id, "severity": h.signature.severity,
                        "category": h.signature.category, "refs": h.signature.refs[:3], "feed": feed.version})
    return out


def stops(signals: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Feed signals that stop the content (a result is withheld, a prompt is refused)."""
    return [s for s in signals if s.get("signature") and s.get("action") in ("block", "escalate")]


def withhold_notice(signals: list[dict[str, Any]], event: int | None = None) -> str:
    ids = ", ".join(sorted({s["signature"] for s in signals}))
    where = f", event #{event}" if event is not None else ""
    return f"[SpireGate: content withheld — known attack pattern from the signature feed ({ids}){where}]"


def hit_counts(entries: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Signature id -> number of audit entries where it acted (for the dashboard)."""
    counts: Counter = Counter()
    for e in entries:
        for s in {s.get("signature") for s in e.get("signals", []) if s.get("signature") and s.get("action") != "allow"}:
            counts[s] += 1
    return dict(counts)


def view(status: dict[str, Any], controls: Iterable[Any], entries: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Feed status for the dashboard: per signature, where the policy applies it, with which action, and hits."""
    sig_controls = [c for c in controls if getattr(c, "detector", None) == "signatures"]
    hits = hit_counts(entries)
    for s in status.get("signatures", []):
        s["hits"] = hits.get(s["id"], 0)
        s["applied"] = [{"control": c.id, "phase": c.phase,
                         "action": min(s["action"], c.action, key=_ACTION_RANK.__getitem__)}
                        for c in sig_controls
                        if c.phase in s["phases"] and s["id"] not in (c.exclude or [])
                        and SEVERITY_RANK[s["severity"]] >= SEVERITY_RANK.get(c.min_severity or "low", 0)]
    status["controls"] = [{"id": c.id, "phase": c.phase, "action": c.action, "min_severity": c.min_severity,
                           "exclude": list(c.exclude or [])} for c in sig_controls]
    return status


def posture_check(status: dict[str, Any]) -> dict[str, Any]:
    if not status.get("configured"):
        return {"name": "Signature feed", "ok": False, "detail": "no feed section in the policy"}
    if not status.get("loaded"):
        return {"name": "Signature feed", "ok": False, "detail": "no bundle loaded"}
    stale = status.get("expired")
    detail = (f"{status['feed']} v{status['version']} · {len(status.get('signatures', []))} signatures"
              + (" · EXPIRED" if stale else "") + (" · new bundle rejected" if status.get("error") else ""))
    return {"name": "Signature feed", "ok": not stale and not status.get("error"), "detail": detail}


# ================================================================== demo feed server and demo model files

def create_feed_app(bundle_path: Path):
    """A stand-in for an external threat-intel service: serves the signed bundle with an ETag."""
    app = FastAPI(title="spire-intel (demo threat-intel service)")

    @app.get("/v1/feed/bundle")
    async def bundle(request: Request) -> Response:
        try:
            raw = bundle_path.read_bytes()
        except FileNotFoundError:
            return JSONResponse({"error": f"no bundle {bundle_path.name}"}, status_code=404)
        etag = '"' + hashlib.sha256(raw).hexdigest()[:16] + '"'
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"ETag": etag})
        return Response(raw, media_type="application/json", headers={"ETag": etag, "Cache-Control": "no-cache"})

    @app.get("/healthz")
    async def healthz() -> dict:
        try:
            payload = json.loads(bundle_path.read_bytes())["payload"]
            return {"ok": True, "feed": payload["feed"], "version": payload["version"]}
        except (OSError, ValueError, KeyError):
            return {"ok": False}

    return app


class _Echo:
    """Pickled into the demo 'malicious' checkpoint: loading it would run a harmless echo."""

    def __reduce__(self):
        return (os.system, ("echo 'SpireGate demo: this would run on torch.load()'",))


def write_demo_models(directory: Path) -> dict[str, Path]:
    """Two PyTorch-style checkpoints (zip with archive/data.pkl) for `spiregate scan-model` and the demo."""
    directory.mkdir(parents=True, exist_ok=True)
    import pickle

    # clean: the globals a real state_dict uses (built from raw opcodes, so torch is not needed)
    clean_pkl = (b"\x80\x02ccollections\nOrderedDict\n)R" + b"X\x06\x00\x00\x00weight"
                 + b"ctorch._utils\n_rebuild_tensor_v2\n)Rs.")
    files = {"clean": (directory / "clean_model.pt", clean_pkl),
             "evil": (directory / "evil_model.pt", pickle.dumps(_Echo(), protocol=2))}
    for path, pkl in files.values():
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("archive/data.pkl", pkl)
            z.writestr("archive/version", "3\n")
            z.writestr("archive/data/0", b"\x00" * 16)
    return {k: p for k, (p, _) in files.items()}


# ================================================================== CLI (spiregate feed ..., spiregate scan-model)

def spec_from_policy(path: Path) -> FeedSpec | None:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return FeedSpec.model_validate(doc["feed"]) if doc.get("feed") else None


def _load_for_cli(policy: Path) -> tuple[FeedSpec, LoadedFeed]:
    spec = spec_from_policy(policy)
    if spec is None:
        raise FeedError(f"{policy}: the policy has no `feed` section")
    store = FeedStore()
    if _remote(spec.source):
        asyncio.run(store.pull(spec, force=True))
    else:
        store.sync(spec)
    if store.current is None:
        raise FeedError(store.last_error or "feed not loaded")
    return spec, store.current


def cli(args) -> int:
    try:
        if args.cmd == "scan-model":
            return _scan_models(args.paths, args.policy)
        if args.feed_cmd == "sign":
            env = build_bundle(args.source, args.key, previous=args.out, days=args.days)
            args.out.write_text(json.dumps(env, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            p = env["payload"]
            print(f"signed {p['feed']} v{p['version']}: {len(p['signatures'])} signatures, key {env['key_id']}, "
                  f"valid until {p['expires_at']} → {args.out}")
            print("a gateway with a local source loads it on the next request; with a feed server, on the next poll")
        elif args.feed_cmd == "verify":
            spec = spec_from_policy(args.policy)
            if spec is None:
                raise FeedError(f"{args.policy}: the policy has no `feed` section")
            loaded = verify_bundle(args.bundle.read_bytes(), spec.trusted_keys, str(args.bundle))
            state = "EXPIRED" if loaded.expired() else f"valid until {_iso(loaded.payload.expires_at)}"
            print(f"OK  {loaded.payload.feed} v{loaded.version} ({loaded.sha}), key {loaded.key_id}, "
                  f"{len(loaded.compiled)} signatures, examples pass, {state}")
        elif args.feed_cmd == "serve":
            import uvicorn

            print(f"spire-intel (demo) at http://127.0.0.1:{args.port}/v1/feed/bundle  ·  bundle: {args.bundle}", flush=True)
            uvicorn.run(create_feed_app(args.bundle), host="127.0.0.1", port=args.port, log_level="warning")
        elif args.feed_cmd == "keygen":
            pub = generate_key(args.out, args.key_id)
            print(f"private key: {args.out}\nadd to the policy:\n  feed:\n    trusted_keys:\n      {args.key_id}: \"{pub}\"")
        elif args.feed_cmd == "demo-models":
            for kind, path in write_demo_models(args.dir).items():
                print(f"{kind:5} {path}")
    except (FeedError, OSError, KeyError, ValueError) as e:
        print(f"ERROR  {e}")
        return 1
    return 0


def _scan_models(paths: list[Path], policy: Path) -> int:
    _, loaded = _load_for_cli(policy)
    print(f"signatures: {loaded.payload.feed} v{loaded.version} ({loaded.sha})")
    worst = 0
    for p in paths:
        imports = model_file_imports(p)
        if imports is None:
            print(f"{p}  —  not a pickle or a PyTorch zip (e.g. safetensors): nothing runs when it is loaded")
            continue
        hits = loaded.scan("tool_call", [], [p])
        verdict = "BLOCKED" if hits else "OK"
        worst = max(worst, 1 if hits else 0)
        print(f"{p}  {verdict}")
        print(f"    imports on load: {', '.join(dict.fromkeys(imports)) or 'none'}")
        for h in hits:
            print(f"    {h.signature.id} [{h.signature.severity}] {h.signature.title}: {h.detail}")
    return worst
