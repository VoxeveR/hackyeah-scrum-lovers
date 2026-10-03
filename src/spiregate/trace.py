"""Human-readable decision trace on the console, so you can watch what the gateway decides and why."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape

_STYLE = {
    "allow": "bold green",
    "redact": "bold blue",
    "taint": "bold yellow",
    "escalate": "bold magenta",
    "block": "bold red",
    "withhold": "bold red",
    "would": "dim",
}


class Tracer:
    def __init__(self, console: Console | None = None, enabled: bool = True):
        self.console = console or Console()
        self.enabled = enabled
        self.lines: list[str] = []  # plain-text copy, handy in tests

    def _out(self, markup: str, plain: str) -> None:
        self.lines.append(plain)
        if self.enabled:
            self.console.print(markup)

    def header(self, text: str) -> None:
        self._out(f"\n[bold cyan]SpireGate ▸ {escape(text)}[/]", f"== {text}")

    def info(self, text: str) -> None:
        self._out(f"  [cyan]│[/] {escape(text)}", f"  | {text}")

    def policy(self, text: str) -> None:
        self._out(f"  [bold yellow]⚑ polityka:[/] {escape(text)}", f"  ! policy: {text}")

    def decision(self, action: str, control: str, text: str, *, enforced: bool = True) -> None:
        if enforced:
            tag = f"[{_STYLE.get(action, 'bold')}]{action.upper():8}[/]"
            plain = f"  {action.upper():8} {control}: {text}"
        else:
            tag = f"[{_STYLE['would']}]would_{action:8}[/]"
            plain = f"  would_{action} {control}: {text}"
        self._out(f"  [cyan]│[/] {tag} [bold]{escape(control)}[/] {escape(text)}", plain)

    def verdict(self, action: str, text: str) -> None:
        self._out(f"  [cyan]└─[/] [{_STYLE.get(action, 'bold')}]{action.upper()}[/] {escape(text)}",
                  f"  => {action.upper()} {text}")
