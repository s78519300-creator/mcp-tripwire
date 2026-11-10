"""Known-vulnerable and known-malicious MCP packages.

Version ranges come from the OSV records linked in each entry. Ranges are
lists of alternatives; each alternative is a list of (operator, version)
conditions that must all hold.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Advisory:
    id: str
    package: str
    ecosystem: str
    severity: str
    summary: str
    affected: tuple[tuple[tuple[str, str], ...], ...]
    fixed: str | None
    url: str
    malicious: bool = False


ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        "CVE-2025-6514", "mcp-remote", "npm", "critical",
        "OS command injection when connecting to an untrusted MCP server",
        (((">=", "0.0.5"), ("<=", "0.1.15")),), "0.1.16",
        "https://osv.dev/vulnerability/CVE-2025-6514",
    ),
    Advisory(
        "CVE-2025-49596", "@modelcontextprotocol/inspector", "npm", "critical",
        "Remote code execution through the Inspector's unauthenticated proxy",
        ((("<", "0.14.1"),),), "0.14.1",
        "https://osv.dev/vulnerability/CVE-2025-49596",
    ),
    Advisory(
        "CVE-2025-53109", "@modelcontextprotocol/server-filesystem", "npm", "high",
        "Symlink handling lets the server escape its allowed directories",
        ((("<", "0.6.4"),), ((">=", "2025.0.0"), ("<", "2025.7.1"))), "2025.7.1",
        "https://osv.dev/vulnerability/CVE-2025-53109",
    ),
    Advisory(
        "CVE-2025-53110", "@modelcontextprotocol/server-filesystem", "npm", "high",
        "Path-prefix check can be bypassed to reach directories outside the allowed ones",
        ((("<", "0.6.4"),), ((">=", "2025.0.0"), ("<", "2025.7.1"))), "2025.7.1",
        "https://osv.dev/vulnerability/CVE-2025-53110",
    ),
    Advisory(
        "MAL-2025-postmark-mcp", "postmark-mcp", "npm", "critical",
        "Unofficial package not published by Postmark; version 1.0.16 secretly BCC'd every email to an attacker",
        ((("*", ""),),), None,
        "https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html",
        malicious=True,
    ),
)


def parse_version(version: str) -> tuple[int, ...]:
    parts = [int(part) for part in re.findall(r"\d+", version)[:3]]
    return tuple(parts + [0] * (3 - len(parts)))


def _holds(version: tuple[int, ...], op: str, bound: str) -> bool:
    if op == "*":
        return True
    other = parse_version(bound)
    return {"<": version < other, "<=": version <= other, ">": version > other, ">=": version >= other, "==": version == other}[op]


def is_affected(advisory: Advisory, version: str) -> bool:
    parsed = parse_version(version)
    return any(all(_holds(parsed, op, bound) for op, bound in alternative) for alternative in advisory.affected)


def for_package(ecosystem: str, name: str) -> list[Advisory]:
    return [a for a in ADVISORIES if a.ecosystem == ecosystem and a.package.lower() == name.lower()]


def split_spec(ecosystem: str, spec: str) -> tuple[str, str | None]:
    """Split 'name@1.2.3' (npm) or 'name==1.2.3' / 'name@1.2.3' (PyPI) into name and version."""
    if ecosystem == "npm":
        at = spec.rfind("@")
        if at > 0:
            return spec[:at], spec[at + 1 :] or None
        return spec, None
    match = re.match(r"^([A-Za-z0-9_.\-\[\]]+?)\s*(?:==|@)\s*([\w.+-]+)$", spec)
    return (match.group(1), match.group(2)) if match else (re.split(r"[<>=!~@\[]", spec)[0], None)
