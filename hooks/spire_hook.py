#!/usr/bin/env python3
"""SpireGate hook for Claude Code and Codex (PreToolUse, PostToolUse, UserPromptSubmit).

Standard library only, so it runs with any python3. It forwards the hook event to the gateway and
prints whatever the gateway says. If the gateway cannot be reached, a PreToolUse event is BLOCKED
(fail-closed) and a PostToolUse result has its text hidden, because it could not be checked for PII.

Usage (Claude Code settings.json / Codex config.toml):
    python3 /path/to/spire_hook.py --format claude-code --key spire-demo-claude
"""

import argparse
import json
import os
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.environ.get("SPIRE_URL", "http://127.0.0.1:8787"))
    ap.add_argument("--key", default=os.environ.get("SPIRE_AGENT_KEY", ""))
    ap.add_argument("--format", choices=["claude-code", "codex"], default="claude-code")
    ap.add_argument("--timeout", type=float, default=4.0)
    args = ap.parse_args()

    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
        event_name = event.get("hook_event_name", "")
    except (ValueError, AttributeError):
        event, event_name = {}, ""
    blocking = event_name in ("PreToolUse", "")  # unknown or unreadable event: treat as blocking

    try:
        request = urllib.request.Request(
            f"{args.url.rstrip('/')}/v1/hooks/{args.format}",
            data=raw.encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {args.key}"},
            method="POST",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never route via a proxy
        with opener.open(request, timeout=args.timeout) as response:
            reply = json.loads(response.read().decode("utf-8"))
    except Exception as e:  # unreachable, timeout, HTTP error, bad JSON: all the same to us
        if blocking:
            sys.stderr.write(f"SpireGate niedostępny ({type(e).__name__}): blokuję (fail-closed)\n")
            return 2
        if event_name == "PostToolUse" and args.format == "claude-code" and "tool_response" in event:
            # Cannot check the result for PII, so hide its text (same shape, so Claude Code accepts it).
            hidden = {"hookEventName": "PostToolUse", "updatedToolOutput": _hide(event["tool_response"])}
            sys.stdout.write(json.dumps({"hookSpecificOutput": hidden}, ensure_ascii=False))
        return 0

    if reply.get("stdout"):
        sys.stdout.write(reply["stdout"])
    if reply.get("stderr"):
        sys.stderr.write(reply["stderr"])
    return int(reply.get("exit", 0))


def _hide(value):
    """Replaces content strings, keeps short structural ones (types, ids) so the output shape stays valid."""
    if isinstance(value, str):
        return value if len(value) < 24 else "[SpireGate niedostępny: treść ukryta]"
    if isinstance(value, list):
        return [_hide(v) for v in value]
    if isinstance(value, dict):
        return {k: _hide(v) for k, v in value.items()}
    return value


if __name__ == "__main__":
    sys.exit(main())
