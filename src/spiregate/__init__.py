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
    d.add_argument("--scenario", choices=["benign", "attack", "loop"], default="benign")
    d.add_argument("--model", default="stub-model", help="stub-model (bez klucza) albo gpt-5-mini (OPENAI_API_KEY)")
    d.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    d.add_argument("--gateway-url", default=None, help="użyj działającego `spiregate serve` zamiast procesu w pamięci")
    d.add_argument("--prompt", default=None, help="własne polecenie dla agenta (domyślnie: scenariusz KYC)")

    g = sub.add_parser("load", help="symulowana flota agentów: prawdziwe żądania do działającego gatewaya")
    g.add_argument("--n", type=int, default=None, help="liczba żądań (domyślnie 100)")
    g.add_argument("--seconds", type=float, default=None, help="zamiast liczby: wysyłaj przez tyle sekund")
    g.add_argument("--rate", type=float, default=12.0, help="nowe scenariusze na sekundę")
    g.add_argument("--gateway-url", default="http://127.0.0.1:8787")

    a = sub.add_parser("audit", help="log audytowy")
    a.add_argument("action", choices=["verify", "show"])
    a.add_argument("--path", type=Path, default=DEFAULT_AUDIT)

    from .feed import ROOT as REPO

    feed_dir = REPO / "feed"
    f = sub.add_parser("feed", help="signed feed of known-attack signatures (external threat-intel system)")
    fsub = f.add_subparsers(dest="feed_cmd", required=True)
    fs = fsub.add_parser("sign", help="validate the source, run every signature's examples, sign the next version")
    fs.add_argument("--source", type=Path, default=feed_dir / "signatures.yaml")
    fs.add_argument("--key", type=Path, default=feed_dir / "demo-signing-key.json")
    fs.add_argument("--out", type=Path, default=feed_dir / "bundle.json")
    fs.add_argument("--days", type=int, default=30, help="bundle validity in days")
    fv = fsub.add_parser("verify", help="verify a bundle with the keys the policy trusts")
    fv.add_argument("--bundle", type=Path, default=feed_dir / "bundle.json")
    fv.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    fsv = fsub.add_parser("serve", help="demo threat-intel server: serves the bundle over HTTP")
    fsv.add_argument("--port", type=int, default=8788)
    fsv.add_argument("--bundle", type=Path, default=feed_dir / "bundle.json")
    fk = fsub.add_parser("keygen", help="new signing key; prints the public key for feed.trusted_keys")
    fk.add_argument("--out", type=Path, required=True)
    fk.add_argument("--key-id", required=True)
    fd = fsub.add_parser("demo-models", help="two .pt files for the demo: clean and malicious (pickle with os.system → echo)")
    fd.add_argument("--dir", type=Path, default=REPO / "demo" / "models")

    r = sub.add_parser("report", help="daily AI security report (HTML + JSON in var/analyst/reports)")
    r.add_argument("--date", default=None, help="YYYY-MM-DD, default today")
    r.add_argument("--assess", action="store_true", help="first assess the decisions not assessed yet")
    r.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    r.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)

    sm = sub.add_parser("scan-model", help="scan model files (pickle, PyTorch .pt) with the feed's signatures, without loading them")
    sm.add_argument("paths", type=Path, nargs="+")
    sm.add_argument("--policy", type=Path, default=DEFAULT_POLICY)

    args = p.parse_args()
    if args.cmd == "report":
        from datetime import date

        from .analyst import Analyst
        from .app import build_gateway

        async def go() -> dict:
            analyst = Analyst(build_gateway(args.policy, args.audit))
            if args.assess:
                entry = await analyst.assess()
                print(f"assessment: {entry['window']['requests']} requests, score {entry['posture_score']}, "
                      f"{entry['backend']}" if entry else "assessment: nothing new to assess")
            report = await analyst.daily(date.fromisoformat(args.date) if args.date else None)
            return report, analyst.reports_dir / f"{report['date']}.html"

        rep, page = asyncio.run(go())
        print(f"{rep['date']}: score {rep['posture_score']} ({rep['risk_level']}), {rep['backend']}"
              + (f" — {rep['note']}" if rep.get("note") else ""))
        print(f"  {rep['narrative']['headline']}")
        print(f"  {page}")
        return
    if args.cmd in ("feed", "scan-model"):
        from .feed import cli

        sys.exit(cli(args))
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
    elif args.cmd == "load":
        import httpx

        from .app import ROOT
        from .loadgen import run

        async def go() -> dict:
            async with httpx.AsyncClient(base_url=args.gateway_url.rstrip("/"), timeout=30, trust_env=False) as client:
                return await run(client, n=args.n, seconds=args.seconds, rate=args.rate, cwd=str(ROOT / "demo" / "claude-code"))

        summary = asyncio.run(go())
        print(f"{summary['n']} żądań w {summary['seconds']} s · {summary['outcomes']} · podgląd: {args.gateway_url}/ui/#/engine")
    elif args.cmd == "audit":
        from .audit import verify

        if args.action == "verify":
            ok, msg = verify(args.path)
            print(("OK  " if ok else "BŁĄD  ") + msg)
            sys.exit(0 if ok else 1)
        import json

        from .audit import AuditLog

        for e in AuditLog(args.path).tail(20):
            sig = ", ".join(f"{s['control']}:{s['action']}" for s in e.get("signals", [])
                            if s.get("action") != "allow" and s.get("enforced", True) is not False)
            print(f"#{e['seq']:>3} {e['ts'][11:19]} {e.get('agent')} {e.get('model')} → {e['decision'].upper():8} {sig}")
