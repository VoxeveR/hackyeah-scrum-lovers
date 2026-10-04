"""Edits of the policy file from the dashboard: add, change and remove rules.

Only the block of the rule being changed is rewritten; comments and layout elsewhere stay exactly as written.
Every edit is validated on the whole file BEFORE it is written, and written atomically, so the gateway's hot
reload never sees a half-written or invalid policy. Invariant controls cannot be removed.
"""

from __future__ import annotations

import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .policy import INVARIANTS, load_policy

_LOCK = threading.Lock()
_ITEM = re.compile(r"^  - id:\s*['\"]?([^'\"\s#]+)")
_TOP = re.compile(r"^[^\s#]")


def _section(lines: list[str], key: str) -> tuple[int, int]:
    """(first line after `key:`, end) of a top-level section."""
    start = next((i for i, ln in enumerate(lines) if re.match(rf"^{key}:\s*(#.*)?$", ln.rstrip("\n"))), None)
    if start is None:
        raise ValueError(f"the policy has no {key} section")
    end = start + 1
    while end < len(lines) and not _TOP.match(lines[end]):
        end += 1
    return start + 1, end


def _blocks(lines: list[str]) -> list[tuple[str, int, int]]:
    """(control id, start, end) for every control; a comment right above an item belongs to it."""
    lo, hi = _section(lines, "controls")
    heads = [i for i in range(lo, hi) if _ITEM.match(lines[i])]
    out = []
    for n, h in enumerate(heads):
        start = h
        while start - 1 >= lo and lines[start - 1].startswith("  #"):
            start -= 1
        nxt = heads[n + 1] if n + 1 < len(heads) else hi
        end = nxt
        while end - 1 > h and lines[end - 1].startswith("  #"):   # the next item's leading comment
            end -= 1
        out.append((_ITEM.match(lines[h]).group(1), start, end))
    return out


class _Dumper(yaml.SafeDumper):
    """A control is always written field per line; only short lists and small maps inside it stay inline."""

    def ignore_aliases(self, data: Any) -> bool:   # no &id001 anchors in a file people read
        return True


class _Top(dict):
    pass


def _inline(items: Any) -> bool:
    return all(not isinstance(v, (dict, list)) for v in items)


_Dumper.add_representer(_Top, lambda d, data: d.represent_mapping("tag:yaml.org,2002:map", data, flow_style=False))
_Dumper.add_representer(dict, lambda d, data: d.represent_mapping(
    "tag:yaml.org,2002:map", data, flow_style=_inline(data.values()) and len(str(data)) <= 100))
_Dumper.add_representer(list, lambda d, data: d.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=_inline(data)))


def _render_control(ctrl: dict[str, Any]) -> list[str]:
    body = yaml.dump(_Top(ctrl), Dumper=_Dumper, allow_unicode=True, sort_keys=False, width=1000).splitlines()
    return ["  - " + body[0] + "\n"] + ["    " + ln + "\n" for ln in body[1:]] + ["\n"]



def _bump_rev(lines: list[str]) -> list[str]:
    for i, ln in enumerate(lines):
        m = re.match(r"^(\s*policy_rev:\s*)(\d+)(.*)$", ln, re.S)
        if m:
            lines[i] = f"{m.group(1)}{int(m.group(2)) + 1}{m.group(3)}"
            return lines
    raise ValueError("the policy has no policy_rev")


def _commit(path: Path, lines: list[str]) -> None:
    """Validate the whole new file, then replace the old one in a single rename."""
    while lines and not lines[-1].strip():          # one newline at the end, however the edit left it
        lines.pop()
    text = "".join(_bump_rev(lines))
    fd, tmp = tempfile.mkstemp(suffix=".yaml", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        try:
            load_policy(Path(tmp))
        except ValidationError as e:
            raise ValueError("; ".join(_explain(err) for err in e.errors()[:3])) from None
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _explain(err: dict[str, Any]) -> str:
    msg = str(err.get("msg", "")).removeprefix("Value error, ")
    where = ".".join(str(x) for x in err.get("loc", ()) if not isinstance(x, int))
    return f"{where}: {msg}" if where and where not in msg else msg


def ids(path: Path) -> set[str]:
    """Every id in the policy (controls and budget rules), so a new rule never reuses one."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    budgets = (doc.get("budgets") or {}).get("rules") or []
    return {str(c.get("id")) for c in doc.get("controls") or []} | {str(b.get("id")) for b in budgets}


# ---------------------------------------------------------------- controls
def apply(path: Path, add: list[dict[str, Any]] = (), replace: dict[str, dict[str, Any]] | None = None,
          remove: list[str] = ()) -> None:
    """All changes of one user action in one validated write (one policy revision)."""
    with _LOCK:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        for cid in remove:
            if cid in INVARIANTS:
                raise ValueError(f"{cid} is an invariant: it cannot be removed")
        existing = {cid for cid, _, _ in _blocks(lines)}
        for c in add:
            if c["id"] in existing:
                raise ValueError(f"rule {c['id']} already exists")
        # bottom-up so earlier offsets stay valid
        edits = []
        for cid, start, end in _blocks(lines):
            if cid in remove:
                edits.append((start, end, []))
            elif replace and cid in replace:
                h = next(i for i in range(start, end) if _ITEM.match(lines[i]))
                edits.append((h, end, _render_control(replace[cid])))
        missing = (set(remove) | set(replace or {})) - existing
        if missing:
            raise ValueError(f"no rule {', '.join(sorted(missing))}")
        for start, end, new in sorted(edits, reverse=True):
            lines[start:end] = new
        if add:
            _, end = _section(lines, "controls")
            hi = end
            while hi > 0 and not lines[hi - 1].strip():
                hi -= 1
            lines[hi:end] = ["\n"] + [ln for c in add for ln in _render_control(c)]   # ends with one blank line
        _commit(path, lines)
