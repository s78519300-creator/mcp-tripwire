"""Command-line interface for mcp-tripwire (``mcptw``)."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from pathlib import Path

from .client import MCPError, fetch_tools
from .config_scan import load_servers, scan_config
from .discover import discover
from .findings import SEVERITIES, Finding, at_least
from .pinning import approve, build_lock, describe_change, read_lock, tool_status, verify
from .proxy import run_proxy
from .report import to_html, to_json, to_sarif, to_text
from .score import badge_svg, grade
from .tool_scan import scan_servers, scan_tool

PRO_URL = "https://github.com/s78519300-creator/mcp-tripwire#free-vs-pro"
# Rules that MCP Tripwire Pro's hardening script can fix automatically.
AUTO_FIXABLE = {"TW201", "TW202", "TW204", "TW205", "TW206"}


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
    _tip(findings, args)
    return 1 if any(at_least(f.severity, args.fail_on) for f in findings) else 0


def _tip(findings: list[Finding], args: argparse.Namespace) -> None:
    """One quiet line, on stderr, and only for human-readable output."""
    if args.format != "text" or getattr(args, "no_tips", False) or os.environ.get("MCPTW_NO_TIPS"):
        return
    fixable = sum(1 for f in findings if f.rule in AUTO_FIXABLE)
    if fixable:
        print(f"\nTip: {fixable} of these can be fixed automatically with MCP Tripwire Pro: {PRO_URL} (hide with --no-tips)", file=sys.stderr)


def _live_tools(config: Path, timeout: float, skip: set[str] = frozenset(),
                only: set[str] | None = None) -> tuple[dict[str, list[dict]], list[str]]:
    """Launch each stdio server and list its tools. Servers in ``skip`` are never started."""
    servers, errors = {}, []
    for name, server in load_servers(config).items():
        if only is not None and name not in only:
            continue
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


def cmd_scan(args: argparse.Namespace) -> int:
    configs = discover(project=args.project)
    if not configs:
        print("No MCP client configs found. Point at one directly with: mcptw config <path>")
        return 0
    findings: list[Finding] = []
    lines = []
    for label, path in configs:
        try:
            found = scan_config(path)
        except (OSError, ValueError) as exc:
            lines.append(f"  ! {label}: could not read {path} ({exc})")
            continue
        servers = len(load_servers(path))
        letter, _ = grade(found)
        lines.append(f"  {letter}  {label:<22} {servers} servers, {len(found)} findings  ({path})")
        findings += [dataclasses.replace(f, target=f.target.replace("config/", f"{label}/", 1)) for f in found]
    letter, score = grade(findings)
    if args.format == "text" and not args.output:
        print(f"Scanned {len(configs)} MCP configs. Overall grade {letter} ({score}/100). Nothing was started.")
        print("\n".join(lines) + "\n")
    return _emit(findings, args, "mcp-configs", f"{len(configs)} MCP client configs on this machine · grade {letter}")


def cmd_badge(args: argparse.Namespace) -> int:
    letter, score = grade(scan_config(args.config))
    Path(args.output).write_text(badge_svg(letter), encoding="utf-8")
    print(f"Grade {letter} ({score}/100). Badge written to {args.output}")
    print(f"Add it to your README:  ![MCP security: grade {letter}]({args.output})")
    return 0


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


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("Not approving: no terminal to confirm in. Re-run with --yes once you have reviewed the change.", file=sys.stderr)
        return False
    return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}


def cmd_approve(args: argparse.Namespace) -> int:
    """Approve reviewed changes one tool at a time, leaving every other change flagged."""
    lock_path = Path(args.lock)
    lock = read_lock(lock_path)
    wanted: dict[str, set[str] | None] = {}
    for target in args.targets:
        if "/" not in target:
            raise ValueError(f"'{target}' should look like server/tool, or server/* for every change in a server")
        server, tool = target.split("/", 1)
        if tool == "*":
            wanted[server] = None
        elif wanted.get(server, set()) is not None:
            wanted.setdefault(server, set()).add(tool)

    known = load_servers(args.config)
    missing = [server for server in wanted if server not in known]
    if missing:
        raise ValueError(f"not in {args.config}: {', '.join(missing)}")
    servers, errors = _live_tools(args.config, args.timeout, only=set(wanted))
    for error in errors:
        print(f"warning: could not list tools from {error}", file=sys.stderr)

    approved = 0
    for server, names in wanted.items():
        if server not in servers:
            print(f"{server}: skipped, could not list its tools")
            continue
        current = {str(t.get("name")): t for t in servers[server]}
        pinned = set(lock["servers"].get(server, {}))
        if names is None:
            names = {n for n in current | dict.fromkeys(pinned) if tool_status(lock, server, n, current.get(n)) != "approved"}
            if not names:
                print(f"{server}: nothing to approve, every tool matches the lock file")
        for name in sorted(names):
            tool = current.get(name)
            status = tool_status(lock, server, name, tool)
            label = f"{server}/{name}"
            if status == "approved":
                print(f"{label}: already approved, nothing to do")
                continue
            if status == "unknown":
                print(f"{label}: no such tool on the server or in the lock file")
                continue
            print(f"\n{label}: {status}")
            if status == "changed":
                before = lock.get("definitions", {}).get(server, {}).get(name)
                if before is not None:
                    changed, diff = describe_change(before, tool)
                    print(f"  changed: {', '.join(changed)}")
                    print(f"  {diff}")
                else:
                    print("  (this lock file has no stored definition, so the exact diff is unavailable)")
            if status in {"changed", "new"}:
                print(f"  description now: {str(tool.get('description') or '')[:300]!r}")
                serious = [f for f in scan_tool(tool, server) if at_least(f.severity, "high")]
                if serious and not args.force:
                    print("  REFUSED: the new definition fails the security scan:")
                    for f in serious:
                        print(f"    [{f.severity}] {f.rule} {f.message}")
                    print("  Use --force only if you have confirmed these findings are false positives.")
                    continue
            if status == "removed":
                print("  the server no longer offers this tool; approving removes it from the lock file")
            if _confirm(f"  Approve {label}?", args.yes):
                lock = approve(lock, server, name, tool)
                approved += 1
                print(f"  approved {label}")
            else:
                print(f"  left {label} unapproved")

    if approved:
        tmp = lock_path.with_suffix(lock_path.suffix + ".tmp")
        tmp.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        tmp.replace(lock_path)
        print(f"\nUpdated {lock_path}: {approved} change(s) approved. Other changes stay flagged until you review them.")
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
        p.add_argument("--no-tips", action="store_true", help="do not print the Pro tip")

    p = sub.add_parser("scan", help="find and scan every MCP config on this machine (runs nothing)")
    p.add_argument("--project", type=Path, default=Path.cwd(), help="also check project configs in this folder (default: current folder)")
    outputs(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("badge", help="write an SVG security-grade badge for a config")
    p.add_argument("config", type=Path)
    p.add_argument("--output", "-o", default="mcp-security-badge.svg")
    p.set_defaults(func=cmd_badge)

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

    p = sub.add_parser("approve", help="approve reviewed tool changes one at a time")
    p.add_argument("config", type=Path)
    p.add_argument("targets", nargs="+", metavar="server/tool", help="tools to approve, or server/* for every change in a server")
    p.add_argument("--lock", default="mcp-tripwire.lock.json")
    p.add_argument("--yes", "-y", action="store_true", help="approve without asking (for scripts, after review)")
    p.add_argument("--force", action="store_true", help="approve even if the new definition fails the security scan")
    p.add_argument("--timeout", type=float, default=15)
    p.set_defaults(func=cmd_approve)

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

