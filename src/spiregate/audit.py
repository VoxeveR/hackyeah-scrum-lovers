"""Append-only, hash-chained decision log: change or delete one line and verification fails."""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(prev_hash: str, record: dict[str, Any]) -> str:
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._prev = self._tail()

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last = None
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)
        return (last["seq"], last["hash"]) if last else (0, GENESIS)

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            body = {"seq": self._seq, "ts": datetime.now(timezone.utc).isoformat(), **record}
            entry = {**body, "prev_hash": self._prev, "hash": _digest(self._prev, body)}
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._prev = entry["hash"]
            return entry

    def tail(self, n: int = 50) -> list[dict[str, Any]]:
        """Last n entries, reading the file from the end (the log grows fast under load)."""
        if not self.path.exists():
            return []
        with self.path.open("rb") as f:
            f.seek(0, 2)
            pos, chunks, newlines = f.tell(), [], 0
            while pos > 0 and newlines <= n:
                step = min(1 << 16, pos)
                pos -= step
                f.seek(pos)
                chunk = f.read(step)
                chunks.append(chunk)
                newlines += chunk.count(b"\n")
        lines = [ln for ln in b"".join(reversed(chunks)).decode("utf-8", "replace").splitlines() if ln.strip()]
        if pos > 0:
            lines = lines[1:]  # the first line may be cut in the middle
        return [json.loads(line) for line in lines[-n:]]


def verify(path: Path) -> tuple[bool, str]:
    prev = GENESIS
    expected_seq = 1
    if not path.exists():
        return True, "brak logu"
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            entry = json.loads(line)
            body = {k: v for k, v in entry.items() if k not in ("prev_hash", "hash")}
            if entry.get("seq") != expected_seq:
                return False, f"line {lineno}: expected seq {expected_seq}, found {entry.get('seq')} (missing or inserted entry)"
            if entry.get("prev_hash") != prev:
                return False, f"line {lineno} (seq {entry['seq']}): broken prev_hash chain"
            if _digest(prev, body) != entry.get("hash"):
                return False, f"line {lineno} (seq {entry['seq']}): content changed after it was written"
            prev = entry["hash"]
            expected_seq += 1
    return True, f"OK, {expected_seq - 1} entries, chain intact"
