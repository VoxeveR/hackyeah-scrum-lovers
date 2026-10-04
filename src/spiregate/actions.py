"""Facts about a single action: where it sends data, which files it touches, whether it runs fetched code.

Facts are computed in Python and handed to the policy's CEL conditions, so the policy stays declarative.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .detectors import is_internal, recipient_matches

SHELL_TOOLS = {"Bash", "shell", "exec_command", "local_shell", "container.exec"}
PATH_KEYS = ("file_path", "notebook_path", "path")

_NETWORK_BINS = {"curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp", "rsync",
                 "ftp", "socat", "http", "https", "xh", "aria2c"}
_URL_HOST = re.compile(r"\b(?:https?|ftp|wss?)://(?:[^@/\s'\"]+@)?([A-Za-z0-9.-]+)", re.I)
_SCP_HOST = re.compile(r"\b[\w.-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+):")
_DEV_TCP = re.compile(r"/dev/(?:tcp|udp)/([A-Za-z0-9.-]+)")
_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    r"|\bbase64\s+(?:-d|--decode|-D)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b", re.I)
_KILL_SELF = re.compile(r"\b(?:kill|pkill|killall)\b[^;&|]*\b(?:spiregate|uvicorn|spire_hook)\b", re.I)
_INLINE_HTTP = re.compile(r"\b(?:python3?|node|ruby|perl)\b.*\s-[ce]\s.*(?:https?://|socket|requests|urllib|fetch\()", re.I)

# Whole directories: listing, globbing or reading anything inside them is credential access.
CREDENTIAL_DIRS = ["~/.aws", "~/.ssh", "~/.gnupg", "~/.kube", "~/.docker", "~/.azure", "~/.config/gcloud", "~/.oci"]
# Single files that hold secrets wherever they live.
CREDENTIAL_GLOBS = ["*/.netrc", "*/.npmrc", "*/.pypirc", "*/.git-credentials", "*.pem", "*/id_rsa*", "*/id_ed25519*",
                    "*/id_ecdsa*", "*/credentials.json", "*/.vault-token"]
# Markers anywhere in a shell command, for forms paths cannot catch: `cd ~/.aws && cat config`, loops, find.
_CREDENTIAL_MARKER = re.compile(
    r"(?:^|[\s'\"=:(/~}])\.(?:aws|ssh|gnupg|kube|docker|azure|oci)\b|\.config/gcloud\b"
    r"|\b(?:id_rsa|id_ed25519|id_ecdsa|\.netrc|\.git-credentials|\.pypirc|\.vault-token)\b")
_GLOB_CHARS = re.compile(r"[*?\[]")

# Opt-in facts for rules from the catalog: each is a plain boolean or number the policy can test in CEL.
_DESTRUCTIVE = re.compile(
    r"\brm\s+(?:-[a-zA-Z]*[rRf][a-zA-Z]*\s+)+|\bgit\s+push\b[^;&|]*\s(?:--force(?:-with-lease)?|-f)\b"
    r"|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-zA-Z]*f|\b(?:drop|truncate)\s+(?:table|database|schema)\b"
    r"|\bmkfs\b|\bdd\s+if=|\bshred\b|\bkubectl\s+delete\b|\bterraform\s+destroy\b|\bhelm\s+uninstall\b", re.I)
_PRIVILEGE = re.compile(
    r"(?:^|[\s;&|(])(?:sudo|doas|su)\b|\bchmod\s+(?:-R\s+)?(?:[0-7]*[4-7][0-7]{3}|[ugoa]*\+s|777)\b|\bchown\s+(?:-R\s+)?root\b"
    r"|\bsetcap\b|\bvisudo\b")
_PACKAGE_INSTALL = re.compile(
    r"\b(?:pip3?|uv\s+pip|python3?\s+-m\s+pip)\s+install\b|\b(?:uv|poetry|pdm)\s+add\b|\bnpm\s+(?:i|install|add)\b"
    r"|\b(?:yarn|pnpm)\s+(?:add|install)\b|\bbrew\s+install\b|\bapt(?:-get)?\s+install\b|\bgem\s+install\b"
    r"|\bcargo\s+install\b|\bgo\s+install\b|\bconda\s+install\b", re.I)
_AMOUNT_KEYS = ("amount", "value", "kwota", "total", "sum", "suma")


def _amount(args: dict[str, Any]) -> float:
    """The amount of a payment-like action, 0.0 when there is none ("18 450,00" and 18450.0 both work)."""
    for k in _AMOUNT_KEYS:
        v = args.get(k)
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            digits = re.sub(r"[^\d,.-]", "", v).replace(",", ".")
            if digits.count(".") > 1:   # 18.450.00 -> thousands separators
                head, _, tail = digits.rpartition(".")
                digits = head.replace(".", "") + "." + tail
            try:
                return float(digits)
            except ValueError:
                continue
    return 0.0


@dataclass
class ShellFacts:
    network: bool = False
    hosts: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    pipe_to_shell: bool = False
    kills_gateway: bool = False


def analyze_shell(command: str) -> ShellFacts:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:  # unbalanced quotes: fall back to whitespace, keep analysing
        tokens = command.split()
    names = {os.path.basename(t) for t in tokens}
    hosts = _URL_HOST.findall(command) + _SCP_HOST.findall(command) + _DEV_TCP.findall(command)
    network = bool(names & _NETWORK_BINS) or bool(_DEV_TCP.search(command)) or bool(_INLINE_HTTP.search(command))
    for i, t in enumerate(tokens):  # `nc host port`, `telnet host`
        if os.path.basename(t) in {"nc", "ncat", "netcat", "telnet", "socat"}:
            for nxt in tokens[i + 1:]:
                if not nxt.startswith("-"):
                    hosts.append(nxt)
                    break
    paths = []
    for t in tokens:
        t = t.lstrip("@<>")  # curl -d @file, redirections
        if t.startswith(("/", "./", "../", "~")) or ("/" in t and "://" not in t) or t.startswith("."):
            paths.append(t)
    return ShellFacts(network=network, hosts=sorted(set(h.lower() for h in hosts)), paths=paths,
                      pipe_to_shell=bool(_PIPE_TO_SHELL.search(command)), kills_gateway=bool(_KILL_SELF.search(command)))


def _command_of(args: dict[str, Any]) -> str:
    cmd = args.get("command") or args.get("cmd") or ""
    return " ".join(map(str, cmd)) if isinstance(cmd, list) else str(cmd)


def _resolve(p: str, cwd: str | None) -> str:
    p = re.sub(r"\$\{?HOME\}?", os.path.expanduser("~"), p)  # $HOME/.aws and ${HOME}/.aws
    g = _GLOB_CHARS.search(p)
    if g:  # ~/.aws/* -> ~/.aws : the directory a wildcard would expand inside
        p = p[:g.start()].rstrip("/") or "/"
    p = os.path.expanduser(p)
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    return os.path.realpath(p)  # resolves symlinks, so a link into the policy dir is still caught


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _dest_internal(dest: str, internal_domains: list[str]) -> bool:
    if "@" in dest:
        return is_internal(dest, internal_domains)
    return any(dest == d or dest.endswith("." + d) for d in internal_domains)


def compute_facts(name: str, spec: dict[str, Any], args: dict[str, Any], *, allowed_tools: list[str],
                  internal_domains: list[str], protected_roots: list[str], cwd: str | None = None
                  ) -> tuple[dict[str, Any], dict[str, Any]]:
    """Returns (effective tool metadata, facts). Every fact key is always present, so CEL never sees a missing field."""
    effective = dict(spec)
    dests: list[str] = []
    raw_paths: list[str] = []
    pipe = kills = False
    if name in SHELL_TOOLS:
        sf = analyze_shell(_command_of(args))
        if sf.network:
            effective["effect"] = "external_send"  # a shell command that talks to the network is an egress
            dests = sf.hosts or ["<nieznany-host>"]
        raw_paths, pipe, kills = sf.paths, sf.pipe_to_shell, sf.kills_gateway
    else:
        to = args.get("to")
        if to:
            dests = [str(x) for x in to] if isinstance(to, list) else [str(to)]
        raw_paths = [str(args[k]) for k in PATH_KEYS if args.get(k)]
        if name in ("Glob", "Grep") and isinstance(args.get("pattern"), str) and "/" in args["pattern"]:
            raw_paths.append(args["pattern"])

    resolved = [_resolve(p, cwd) for p in raw_paths]
    cred_dirs = [os.path.realpath(os.path.expanduser(d)) for d in CREDENTIAL_DIRS]
    command = _command_of(args) if name in SHELL_TOOLS else ""
    now = datetime.now()
    touches_credentials = (any(_under(r, d) for r in resolved for d in cred_dirs)
                           or any(fnmatch.fnmatch(r, g) for r in resolved for g in CREDENTIAL_GLOBS)
                           or bool(command and _CREDENTIAL_MARKER.search(command)))
    egress_allow = spec.get("egress_allow", [])
    facts = {
        "tool_allowed": any(fnmatch.fnmatchcase(name, p) for p in allowed_tools),
        "destinations": dests,
        "recipient_allowed": bool(dests) and all(recipient_matches(d, egress_allow) for d in dests),
        "recipient_internal": bool(dests) and all(_dest_internal(d, internal_domains) for d in dests),
        "pipe_to_shell": pipe,
        "touches_protected": kills or any(_under(r, root) for r in resolved for root in protected_roots),
        "touches_credentials": touches_credentials,
        "destructive": effective.get("effect") == "delete" or bool(command and _DESTRUCTIVE.search(command)),
        "privilege_escalation": bool(command and _PRIVILEGE.search(command)),
        "package_install": bool(command and _PACKAGE_INSTALL.search(command)),
        "amount": _amount(args),
        "recipient_count": len(dests),
        "hour": now.hour,
        "weekday": now.weekday(),   # 0 = Monday, 5-6 = weekend
    }
    return effective, facts


def output_is_untrusted(name: str, spec: dict[str, Any], args: dict[str, Any]) -> bool:
    """Integrity of a tool's OUTPUT. A shell command is untrusted only if it reached the network."""
    if name in SHELL_TOOLS:
        return analyze_shell(_command_of(args)).network
    return spec.get("output_integrity") == "untrusted"


def protected_roots(repo_root: Path, extra: list[str]) -> list[str]:
    base = [repo_root / "policy", repo_root / ".env", repo_root / "var", repo_root / "hooks",
            repo_root / "src", repo_root / "demo" / "claude-code" / ".claude",
            repo_root / "feed"]   # signed signature feed and its demo key
    return [os.path.realpath(p) for p in base] + [os.path.realpath(os.path.expanduser(p)) for p in extra]
