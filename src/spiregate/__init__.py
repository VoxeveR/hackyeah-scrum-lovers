"""SpireGate: an AI control layer between any agent and the models and tools it uses."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


def main() -> None:
    from .app import DEFAULT_AUDIT, DEFAULT_POLICY, load_dotenv

    load_dotenv()
    p = argparse.ArgumentParser(prog="spiregate")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="uruchom gateway (OpenAI-compatible) na 127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    s.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)

    d = sub.add_parser("demo", help="scenariusz KYC: agent + gateway w jednym procesie")
    d.add_argument("--scenario", choices=["benign", "attack"], default="benign")
    d.add_argument("--model", default="stub-model", help="stub-model (bez klucza) albo gpt-5-mini (OPENAI_API_KEY)")
    d.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    d.add_argument("--gateway-url", default=None, help="użyj działającego `spiregate serve` zamiast procesu w pamięci")
    d.add_argument("--prompt", default=None, help="własne polecenie dla agenta (domyślnie: scenariusz KYC)")

    a = sub.add_parser("audit", help="log audytowy")
    a.add_argument("action", choices=["verify", "show"])
    a.add_argument("--path", type=Path, default=DEFAULT_AUDIT)

    args = p.parse_args()
    if args.cmd == "serve":
        import uvicorn

        from .app import build_gateway, create_app

        app = create_app(build_gateway(args.policy, args.audit))
        print(f"SpireGate na http://127.0.0.1:{args.port}  ·  dashboard: "
              f"http://127.0.0.1:{args.port}/ui/#token={app.state.admin_token}", flush=True)
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    elif args.cmd == "demo":
        from .demo.run import run_demo

        asyncio.run(run_demo(args.scenario, args.model, args.policy, args.gateway_url, args.prompt))
    elif args.cmd == "audit":
        from .audit import verify

        if args.action == "verify":
            ok, msg = verify(args.path)
            print(("OK  " if ok else "BŁĄD  ") + msg)
            sys.exit(0 if ok else 1)
        import json

        from .audit import AuditLog

        for e in AuditLog(args.path).tail(20):
            sig = ", ".join(f"{s['control']}:{s['action']}" for s in e.get("signals", []) if s.get("enforced"))
            print(f"#{e['seq']:>3} {e['ts'][11:19]} {e.get('agent')} {e.get('model')} → {e['decision'].upper():8} {sig}")
