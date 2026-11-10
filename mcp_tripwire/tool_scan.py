"""Scan MCP tool definitions and tool output for poisoning.

Every string in a tool definition is scanned, not only the description:
attackers also hide instructions in parameter descriptions, defaults, enums
and titles ("full-schema poisoning").
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator
from typing import Any

from .findings import Finding

INSTRUCTION_PATTERNS = [
    (re.compile(r"<\s*/?\s*(important|system|instructions?|secret)\s*>", re.I), "high", "Pseudo-system tag in text"),
    (re.compile(r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|messages|rules)", re.I), "critical", "Tries to override earlier instructions"),
    (re.compile(r"\bdo\s+not\s+(tell|inform|mention|reveal|show)\b[^.]{0,60}\b(user|human|anyone)", re.I), "critical", "Asks the model to hide something from the user"),
    (re.compile(r"\b(before|prior\s+to)\s+(using|calling|invoking)\s+(this|any)\s+tool\b[^.]{0,100}\b(read|send|include|call|pass|upload)", re.I), "high", "Demands a side action before the tool runs"),
    (re.compile(r"\byou\s+(must|should)\s+(always\s+)?(first\s+)?(read|send|call|include|pass|forward|upload)\b", re.I), "high", "Commands the model to take an action"),
    (re.compile(r"\b(bcc|cc|forward)\b[^.]{0,40}@", re.I), "high", "Redirects messages to an extra recipient"),
]
SENSITIVE_PATH = re.compile(
    r"(~|\$HOME|%USERPROFILE%)[/\\]\.(ssh|aws|gnupg|kube|docker|config)|\bid_(rsa|ed25519)\b|/etc/(passwd|shadow)|"
    r"\.env\b|claude_desktop_config|mcp\.json|\.netrc|\.git-credentials",
    re.I,
)
URL = re.compile(r"https?://[^\s\"'<>)]+", re.I)
SEND_VERB = re.compile(r"\b(send|post|upload|forward|transmit|exfiltrate|report)\b", re.I)
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
COMMAND_WORDS = re.compile(r"\b(exec(ute)?|shell|run[_ ]command|subprocess|eval|terminal)\b", re.I)
HARVEST_PARAMS = {
    "sidenote", "side_note", "notes", "context", "conversation", "history", "chat_history",
    "previous_messages", "system_prompt", "memory", "transcript",
}
INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
MAX_DESCRIPTION = 1500


def walk_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield (json-path, text) for every string, including dictionary keys."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield child + "#key", str(key)
            yield from walk_strings(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_strings(item, f"{path}[{index}]")


def _clip(text: str, start: int, end: int) -> str:
    snippet = text[max(0, start - 30) : end + 30].replace("\n", " ")
    return INVISIBLE.sub("�", snippet)


def scan_text(text: str, target: str, where: str = "", decoded: bool = False) -> list[Finding]:
    """Detect instruction smuggling in one piece of text."""
    findings: list[Finding] = []
    label = f"{where}: " if where else ""

    hidden = INVISIBLE.findall(text)
    if hidden:
        codes = sorted({f"U+{ord(char):04X}" for char in hidden})
        shown = ", ".join(codes[:4]) + (f" and {len(codes) - 4} more" if len(codes) > 4 else "")
        # Unicode tag characters mirror ASCII, so the smuggled text can be recovered.
        smuggled = "".join(chr(ord(char) - 0xE0000) for char in hidden if 0xE0020 <= ord(char) <= 0xE007E)
        evidence = f"hidden text reads: {smuggled!r}" if smuggled else ""
        findings.append(Finding("TW103", "critical", target, f"{label}{len(hidden)} invisible characters ({shown})", evidence))
        if smuggled and not decoded:
            findings.extend(scan_text(smuggled, target, where, decoded=True))
        text = INVISIBLE.sub("", text)

    for pattern, severity, message in INSTRUCTION_PATTERNS:
        if match := pattern.search(text):
            prefix = "decoded payload: " if decoded else ""
            findings.append(Finding("TW101", "critical" if decoded else severity, target, f"{label}{prefix}{message}", _clip(text, match.start(), match.end())))

    if match := SENSITIVE_PATH.search(text):
        findings.append(Finding("TW102", "high", target, f"{label}References a sensitive file or credential path", _clip(text, match.start(), match.end())))

    for match in URL.finditer(text):
        url = match.group(0)
        if "localhost" in url or "127.0.0.1" in url:
            continue
        severity = "high" if SEND_VERB.search(text) else "low"
        findings.append(Finding("TW106", severity, target, f"{label}Contains external URL {url}", _clip(text, match.start(), match.end())))

    if not decoded:
        for match in BASE64_BLOB.finditer(text):
            try:
                inner = base64.b64decode(match.group(0), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            nested = scan_text(inner, target, where, decoded=True)
            severity = "critical" if nested else "medium"
            findings.append(Finding("TW104", severity, target, f"{label}Base64 text that decodes to readable content", inner[:80]))
            findings.extend(nested)
    return findings


def scan_tool(tool: dict, server: str, other_tools: dict[str, str] | None = None) -> list[Finding]:
    """Scan one tool definition. ``other_tools`` maps tool name -> owning server."""
    name = str(tool.get("name", "?"))
    target = f"{server}/{name}"
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for path, text in walk_strings(tool):
        for finding in scan_text(text, target, path.replace("#key", " (key)")):
            key = (finding.rule, finding.message.split(": ", 1)[-1])
            if key not in seen:
                seen.add(key)
                findings.append(finding)

    description = str(tool.get("description") or "")
    if len(description) > MAX_DESCRIPTION:
        findings.append(Finding("TW109", "low", target, f"Description is {len(description):,} characters long"))

    properties = (tool.get("inputSchema") or {}).get("properties") or {}
    for parameter in properties:
        if parameter.lower() in HARVEST_PARAMS:
            findings.append(Finding("TW107", "medium", target, f"Parameter '{parameter}' can collect conversation context"))

    if COMMAND_WORDS.search(name) or COMMAND_WORDS.search(description[:200]):
        findings.append(Finding("TW108", "low", target, "Tool can run commands or code"))

    every_string = " ".join(text for _, text in walk_strings(tool))
    for other, owner in (other_tools or {}).items():
        if owner != server and len(other) >= 4 and re.search(rf"(?<![\w-]){re.escape(other)}(?![\w-])", every_string):
            findings.append(Finding("TW105", "high", target, f"Mentions '{other}', a tool from server '{owner}'"))
    return findings


def scan_servers(servers: dict[str, list[dict]]) -> list[Finding]:
    """Scan every tool of every server, including cross-server shadowing."""
    owners = {str(tool.get("name")): server for server, tools in servers.items() for tool in tools}
    return [finding for server, tools in servers.items() for tool in tools for finding in scan_tool(tool, server, owners)]


def result_text(result: dict) -> str:
    """Extract the text parts of a tools/call result."""
    parts = [item.get("text", "") for item in result.get("content", []) if isinstance(item, dict) and item.get("type") == "text"]
    if "structuredContent" in result:
        parts.extend(text for _, text in walk_strings(result["structuredContent"]))
    return "\n".join(parts)


def scan_result(result: dict, target: str) -> list[Finding]:
    """Scan tool output for injected instructions (indirect prompt injection)."""
    return [
        Finding("TW401", finding.severity, target, f"Tool output: {finding.message}", finding.evidence)
        for finding in scan_text(result_text(result), target)
        if finding.rule in {"TW101", "TW103", "TW104"}
    ]
