"""Human-readable decision trace on the console, so you can watch what the gateway decides and why."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

from rich.console import Console
from rich.markup import escape

from .events import SIMULATED

# Lines emitted inside one request's task; concurrent requests (load generator) never mix into it.
_CAPTURE: ContextVar[list[str] | None] = ContextVar("spire_trace_capture", default=None)

_STYLE = {
    "allow": "bold green",
    "redact": "bold blue",
    "taint": "bold yellow",
    "escalate": "bold magenta",
    "block": "bold red",
    "withhold": "bold red",
}


class Tracer:
    def __init__(self, console: Console | None = None, enabled: bool = True):
        self.console = console or Console()
        self.enabled = enabled
        self.lines: list[str] = []  # plain-text copy, handy in tests

    def _out(self, markup: str, plain: str) -> None:
        self.lines.append(plain)
        if len(self.lines) > 20000:  # long-running server: keep memory flat
            del self.lines[:10000]
        captured = _CAPTURE.get()
        if captured is not None:
            captured.append(plain)
        if self.enabled and not SIMULATED.get():  # synthetic load stays off the console
            self.console.print(markup)

    def header(self, text: str) -> None:
        self._out(f"\n[bold cyan]SpireGate ▸ {escape(text)}[/]", f"== {text}")

    def info(self, text: str) -> None:
        self._out(f"  [cyan]│[/] {escape(text)}", f"  | {text}")

    def policy(self, text: str) -> None:
        self._out(f"  [bold yellow]⚑ polityka:[/] {escape(text)}", f"  ! policy: {text}")

    @contextmanager
    def capture(self) -> Iterator[list[str]]:
        token = _CAPTURE.set([])
        try:
            yield _CAPTURE.get()
        finally:
            _CAPTURE.reset(token)

    def decision(self, action: str, control: str, text: str) -> None:
        tag = f"[{_STYLE.get(action, 'bold')}]{action.upper():8}[/]"
        plain = f"  {action.upper():8} {control}: {text}"
        self._out(f"  [cyan]│[/] {tag} [bold]{escape(control)}[/] {escape(text)}", plain)

    def verdict(self, action: str, text: str) -> None:
        self._out(f"  [cyan]└─[/] [{_STYLE.get(action, 'bold')}]{action.upper()}[/] {escape(text)}",
                  f"  => {action.upper()} {text}")
