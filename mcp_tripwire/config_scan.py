"""Scan MCP client configuration files (Claude Desktop, Cursor, VS Code and others)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .findings import Finding

SECRET_KEY = re.compile(r"(api[_-]?key|token|secret|password|passwd|private[_-]?key|auth)", re.I)
TOKEN_FORMATS = re.compile(
    r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|glpat-[A-Za-z0-9_-]{20})\b"
)
PLACEHOLDER = re.compile(r"^(\$\{.*\}|\$[A-Z_]+|<.*>|your[-_ ].*|changeme|xxx+|)$", re.I)
SHELLS = {"bash", "sh", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")


def load_servers(path: str | Path) -> dict[str, dict]:
    """Return every server defined in a client config.

    Handles the common shapes: ``mcpServers`` (Claude Desktop, Cursor, Claude
    Code ``.mcp.json``), ``servers`` (VS Code), ``mcp.servers``, and Claude
    Code's ``~/.claude.json``, which also keeps servers per project.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    found = False
    servers: dict[str, dict] = {}
    for candidate in (data.get("mcpServers"), data.get("servers"), (data.get("mcp") or {}).get("servers")):
        if isinstance(candidate, dict):
            found = True
            servers.update(candidate)
    for project, settings in (data.get("projects") or {}).items():
        project_servers = (settings or {}).get("mcpServers") if isinstance(settings, dict) else None
        if isinstance(project_servers, dict):
            found = True
            label = Path(project).name or project
            servers.update({f"{name} ({label})": server for name, server in project_servers.items()})
    if not found:
        raise ValueError("no 'mcpServers' or 'servers' object found")
    return servers


def _package_arg(args: list[str]) -> str | None:
    for arg in args:
        if not arg.startswith("-"):
            return arg
    return None


def _is_unpinned(command: str, args: list[str]) -> str | None:
    """Return the package spec if it is not pinned to an exact version."""
    base = Path(command).name.lower()
    if base in {"npx", "bunx", "pnpx"} or (base in {"pnpm", "yarn"} and args[:1] == ["dlx"]):
        spec = _package_arg(args[1:] if base in {"pnpm", "yarn"} else args)
        if spec is None:
            return None
        name, _, version = spec.rpartition("@") if spec.count("@") > (1 if spec.startswith("@") else 0) else (spec, "", "")
        if not version or version in {"latest", "next"} or not re.match(r"^\d+\.\d+\.\d+", version):
            return spec
    if base in {"uvx", "pipx"}:
        rest = args[1:] if base == "pipx" and args[:1] == ["run"] else args
        if "--from" in rest:
            index = rest.index("--from")
            spec = rest[index + 1] if index + 1 < len(rest) else ""
        else:
            spec = _package_arg(rest) or ""
        if spec and not re.search(r"(==|@)\d", spec):
            return spec
    return None


def scan_server(name: str, server: dict) -> list[Finding]:
    target = f"config/{name}"
    findings: list[Finding] = []
    command = str(server.get("command") or "")
    args = [str(arg) for arg in server.get("args") or []]

    for key, value in (server.get("env") or {}).items():
        value = str(value)
        if TOKEN_FORMATS.search(value):
            findings.append(Finding("TW201", "critical", target, f"env.{key} contains a token in a known provider format", value[:6] + "…"))
        elif SECRET_KEY.search(key) and not PLACEHOLDER.match(value.strip()):
            findings.append(Finding("TW201", "high", target, f"env.{key} holds a literal secret in the config file", value[:3] + "…"))
    for header, value in (server.get("headers") or {}).items():
        if header.lower() in {"authorization", "x-api-key"} and not PLACEHOLDER.match(str(value).strip()) and "${" not in str(value):
            findings.append(Finding("TW201", "high", target, f"headers.{header} holds a literal credential"))
    for arg in args:
        if TOKEN_FORMATS.search(arg):
            findings.append(Finding("TW201", "critical", target, "A command-line argument contains a token", arg[:6] + "…"))

    if spec := _is_unpinned(command, args):
        findings.append(Finding("TW202", "medium", target, f"Package '{spec}' is not pinned to an exact version"))

    if Path(command).name.lower() in SHELLS and any(arg in {"-c", "/c", "-Command"} for arg in args):
        script = " ".join(args)
        if re.search(r"(curl|wget|iwr|Invoke-WebRequest)\b[^|]*\|\s*(ba|z)?sh\b|\|\s*(iex|Invoke-Expression)\b", script, re.I):
            findings.append(Finding("TW203", "critical", target, "Downloads a script and pipes it straight into a shell", script[:80]))
        else:
            findings.append(Finding("TW203", "medium", target, f"Server is launched through '{command}' with an inline script"))

    url = str(server.get("url") or server.get("serverUrl") or "")
    if url.startswith("http://") and not any(host in url for host in LOCAL_HOSTS):
        findings.append(Finding("TW204", "high", target, f"Remote server uses plain HTTP: {url}"))

    if Path(command).name.lower() in {"docker", "podman"}:
        if "--privileged" in args:
            findings.append(Finding("TW205", "high", target, "Container runs with --privileged"))
        for index, arg in enumerate(args):
            mount = args[index + 1] if arg in {"-v", "--volume"} and index + 1 < len(args) else arg.split("=", 1)[1] if arg.startswith("--volume=") else None
            if mount and re.match(r"^(/|~|/home|/Users|C:\\)(:|$)", mount.split(":")[0] + ":"):
                findings.append(Finding("TW205", "high", target, f"Mounts a whole host directory: {mount}"))
        if "--network=host" in args or ("--network" in args and "host" in args):
            findings.append(Finding("TW205", "low", target, "Container shares the host network"))

    if any("server-filesystem" in arg for arg in args):
        roots = [arg for arg in args[args.index(next(a for a in args if "server-filesystem" in a)) + 1 :] if not arg.startswith("-")]
        for root in roots:
            if root in {"/", "~", "C:\\", "C:/"} or re.fullmatch(r"(/home/[^/]+|/Users/[^/]+|~)/?", root):
                findings.append(Finding("TW205", "high", target, f"Filesystem server can read and write all of '{root}'"))
    return findings


def scan_config(path: str | Path) -> list[Finding]:
    return [finding for name, server in load_servers(path).items() for finding in scan_server(name, server)]
