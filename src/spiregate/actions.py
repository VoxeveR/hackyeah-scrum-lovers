"""Facts about a single action: where it sends data, which files it touches, whether it runs fetched code.

Facts are computed in Python and handed to the policy's CEL conditions, so the policy stays declarative.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shlex
from dataclasses import dataclass, field
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

CREDENTIAL_GLOBS = ["*/.aws/credentials", "*/.aws/config", "*/.ssh/id_*", "*/.netrc", "*/.docker/config.json",
                    "*/.npmrc", "*/.pypirc", "*/.config/gcloud/*", "*.pem", "*/.kube/config", "*/.git-credentials"]


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

    resolved = [_resolve(p, cwd) for p in raw_paths]
    egress_allow = spec.get("egress_allow", [])
    facts = {
        "tool_allowed": any(fnmatch.fnmatchcase(name, p) for p in allowed_tools),
        "destinations": dests,
        "recipient_allowed": bool(dests) and all(recipient_matches(d, egress_allow) for d in dests),
        "recipient_internal": bool(dests) and all(_dest_internal(d, internal_domains) for d in dests),
        "pipe_to_shell": pipe,
        "touches_protected": kills or any(_under(r, root) for r in resolved for root in protected_roots),
        "touches_credentials": any(fnmatch.fnmatch(r, g) for r in resolved for g in CREDENTIAL_GLOBS),
    }
    return effective, facts


def output_is_untrusted(name: str, spec: dict[str, Any], args: dict[str, Any]) -> bool:
    """Integrity of a tool's OUTPUT. A shell command is untrusted only if it reached the network."""
    if name in SHELL_TOOLS:
        return analyze_shell(_command_of(args)).network
    return spec.get("output_integrity") == "untrusted"


def protected_roots(repo_root: Path, extra: list[str]) -> list[str]:
    base = [repo_root / "policy", repo_root / ".env", repo_root / "var", repo_root / "hooks",
            repo_root / "src", repo_root / "demo" / "claude-code" / ".claude"]
    return [os.path.realpath(p) for p in base] + [os.path.realpath(os.path.expanduser(p)) for p in extra]
