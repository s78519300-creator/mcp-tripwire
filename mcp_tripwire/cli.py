"""Command-line interface for mcp-tripwire (``mcptw``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .client import MCPError, fetch_tools
from .config_scan import load_servers, scan_config
from .findings import SEVERITIES, Finding, at_least
from .pinning import build_lock, read_lock, verify
from .proxy import run_proxy
from .report import to_html, to_json, to_sarif, to_text
from .tool_scan import scan_servers


def _command(args: argparse.Namespace) -> list[str]:
    command = [part for part in args.command if part != "--"]
    if not command:
        raise SystemExit("error: give the server command after --, for example: -- npx -y @scope/server@1.2.3")
    return command


def _emit(findings: list[Finding], args: argparse.Namespace, artifact: str, subtitle: str) -> int:
    renderers = {
        "text": lambda: to_text(findings, color=sys.stdout.isatty() and args.output is None),
        "json": lambda: to_json(findings),
        "sarif": lambda: to_sarif(findings, artifact),
        "html": lambda: to_html(findings, subtitle=subtitle),
    }
    output = renderers[args.format]()
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Wrote {args.format} report to {args.output} ({len(findings)} findings)")
    else:
        print(output)
    return 1 if any(at_least(f.severity, args.fail_on) for f in findings) else 0


def _live_tools(config: Path, timeout: float, skip: set[str] = frozenset()) -> tuple[dict[str, list[dict]], list[str]]:
    """Launch each stdio server and list its tools. Servers in ``skip`` are never started."""
    servers, errors = {}, []
    for name, server in load_servers(config).items():
        if not server.get("command"):
            continue  # Remote servers are covered by the static config scan.
        if name in skip:
            errors.append(f"{name}: not launched because the config scan rated it high risk (use --launch-risky to override)")
            continue
        command = [str(server["command"]), *[str(arg) for arg in server.get("args") or []]]
        try:
            servers[name] = fetch_tools(command, timeout)
        except (MCPError, OSError) as exc:
            errors.append(f"{name}: {exc}")
    return servers, errors


def cmd_config(args: argparse.Namespace) -> int:
    findings = scan_config(args.config)
    return _emit(findings, args, str(args.config), f"Static scan of {args.config}")


def cmd_audit(args: argparse.Namespace) -> int:
    findings = scan_config(args.config)
    risky = set() if args.launch_risky else {f.target.split("/", 1)[1] for f in findings if at_least(f.severity, "high")}
    servers, errors = _live_tools(args.config, args.timeout, risky)
    findings += scan_servers(servers)
    if args.lock:
        findings += verify(servers, read_lock(args.lock))
    for error in errors:
        print(f"warning: could not list tools from {error}", file=sys.stderr)
    total = sum(len(tools) for tools in servers.values())
    return _emit(findings, args, str(args.config), f"{len(servers)} live servers · {total} tools · config {Path(args.config).name}")


def cmd_tools(args: argparse.Namespace) -> int:
    if args.from_json:
        data = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        tools = data["tools"] if isinstance(data, dict) else data
    else:
        tools = fetch_tools(_command(args), args.timeout)
    servers = {args.server: tools}
    findings = scan_servers(servers)
    if args.lock:
        findings += verify(servers, read_lock(args.lock))
    return _emit(findings, args, args.from_json or args.server, f"{len(tools)} tools from '{args.server}'")


def cmd_pin(args: argparse.Namespace) -> int:
    servers, errors = _live_tools(args.config, args.timeout)
    for error in errors:
        print(f"warning: could not list tools from {error}", file=sys.stderr)
    lock = build_lock(servers)
    Path(args.lock).write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(f"Pinned {sum(len(t) for t in servers.values())} tools from {len(servers)} servers to {args.lock}")
    return 0


def cmd_proxy(args: argparse.Namespace) -> int:
    policy = json.loads(Path(args.policy).read_text(encoding="utf-8")) if args.policy else None
    lock = read_lock(args.lock) if args.lock else None
    return run_proxy(_command(args), args.server, policy, lock, Path(args.audit) if args.audit else None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcptw", description="Find and stop poisoned, rug-pulled and over-privileged MCP servers.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def outputs(p: argparse.ArgumentParser) -> None:
        p.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
        p.add_argument("--output", "-o")
        p.add_argument("--fail-on", choices=SEVERITIES, default="high", help="exit 1 at or above this severity (default: high)")

    p = sub.add_parser("config", help="static scan of an MCP client config (runs nothing)")
    p.add_argument("config", type=Path)
    outputs(p)
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("audit", help="config scan plus live tool scan of every stdio server in the config")
    p.add_argument("config", type=Path)
    p.add_argument("--lock", help="also check tools against a pin file")
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--launch-risky", action="store_true", help="also start servers the config scan rates high risk")
    outputs(p)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("tools", help="scan the tools of one server")
    p.add_argument("--server", default="server")
    p.add_argument("--from-json", help="read a saved tools/list result instead of launching a server")
    p.add_argument("--lock")
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("command", nargs=argparse.REMAINDER)
    outputs(p)
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("pin", help="record approved tool definitions from a config to a lock file")
    p.add_argument("config", type=Path)
    p.add_argument("--lock", default="mcp-tripwire.lock.json")
    p.add_argument("--timeout", type=float, default=15)
    p.set_defaults(func=cmd_pin)

    p = sub.add_parser("proxy", help="run a server behind the runtime firewall")
    p.add_argument("--server", default="server")
    p.add_argument("--policy")
    p.add_argument("--lock")
    p.add_argument("--audit", help="append JSON Lines audit events to this file")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_proxy)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, KeyError, MCPError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

