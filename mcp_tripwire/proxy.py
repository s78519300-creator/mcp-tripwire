"""A stdio firewall that sits between an MCP client and server.

It hides poisoned or rug-pulled tools from the model, blocks calls that the
policy forbids, withholds tool output that carries injected instructions, and
writes an audit log of every decision.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import IO, Any

from .findings import Finding, at_least
from .pinning import changed_tools
from .tool_scan import scan_result, scan_tool

DEFAULT_POLICY = {"block_severity": "high", "deny_tools": [], "allow_tools": None, "scan_results": True}


class Firewall:
    """Pure decision logic, kept separate from I/O so it is easy to test."""

    def __init__(self, server: str, policy: dict | None = None, lock: dict | None = None, audit: IO[str] | None = None):
        self.server = server
        self.policy = {**DEFAULT_POLICY, **(policy or {})}
        self.lock = lock
        self.audit = audit
        self.pending: dict[Any, tuple[str, str | None]] = {}
        self.hidden_tools: set[str] = set()
        self._audit_lock = threading.Lock()

    def log(self, event: str, **fields: Any) -> None:
        if self.audit is None:
            return
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "server": self.server, "event": event, **fields}
        with self._audit_lock:
            self.audit.write(json.dumps(record) + "\n")
            self.audit.flush()

    def _blocked_reason(self, tool: str) -> str | None:
        allow = self.policy.get("allow_tools")
        if tool in self.policy.get("deny_tools", []):
            return f"'{tool}' is on the deny list"
        if allow is not None and tool not in allow:
            return f"'{tool}' is not on the allow list"
        if tool in self.hidden_tools:
            return f"'{tool}' was hidden because it failed the security scan"
        return None

    def from_client(self, message: dict) -> tuple[dict | None, dict | None]:
        """Return (message for the server, reply straight to the client)."""
        method = message.get("method")
        if "id" in message and method:
            tool = (message.get("params") or {}).get("name") if method == "tools/call" else None
            if tool is not None and (reason := self._blocked_reason(tool)):
                self.log("call_blocked", tool=tool, reason=reason)
                error = {"code": -32001, "message": f"Blocked by mcp-tripwire: {reason}"}
                return None, {"jsonrpc": "2.0", "id": message["id"], "error": error}
            self.pending[message["id"]] = (method, tool)
            if tool is not None:
                self.log("call_allowed", tool=tool, arguments=list(((message.get("params") or {}).get("arguments") or {}).keys()))
        return message, None

    def from_server(self, message: dict) -> dict:
        method, tool = self.pending.pop(message.get("id"), (None, None)) if "id" in message else (None, None)
        result = message.get("result")
        if not isinstance(result, dict):
            return message
        if method == "tools/list":
            message = {**message, "result": self._filter_tools(result)}
        elif method == "tools/call" and self.policy.get("scan_results"):
            findings = scan_result(result, f"{self.server}/{tool}")
            serious = [f for f in findings if at_least(f.severity, self.policy["block_severity"])]
            if serious:
                self.log("output_withheld", tool=tool, findings=[f.to_dict() for f in serious])
                notice = "[mcp-tripwire] Output withheld: it contained instructions aimed at the model (" + "; ".join(f.message for f in serious) + ")."
                message = {**message, "result": {"content": [{"type": "text", "text": notice}], "isError": True}}
        return message

    def _filter_tools(self, result: dict) -> dict:
        tools = result.get("tools", [])
        rugged = changed_tools(self.server, tools, self.lock) if self.lock else set()
        kept = []
        for tool in tools:
            name = str(tool.get("name"))
            findings: list[Finding] = [f for f in scan_tool(tool, self.server) if at_least(f.severity, self.policy["block_severity"])]
            if name in rugged:
                findings.append(Finding("TW301", "critical", f"{self.server}/{name}", "Tool definition changed after it was approved"))
            if findings:
                self.hidden_tools.add(name)
                self.log("tool_hidden", tool=name, findings=[f.to_dict() for f in findings])
            else:
                kept.append(tool)
        self.log("tools_listed", offered=len(tools), exposed=len(kept))
        return {**result, "tools": kept}


def run_proxy(command: list[str], server: str, policy: dict | None, lock: dict | None, audit_path: Path | None,
              stdin: IO[str] = sys.stdin, stdout: IO[str] = sys.stdout) -> int:
    audit = audit_path.open("a", encoding="utf-8") if audit_path else None
    firewall = Firewall(server, policy, lock, audit)
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1)
    write_lock = threading.Lock()

    def emit(message: dict) -> None:
        with write_lock:
            stdout.write(json.dumps(message) + "\n")
            stdout.flush()

    def server_to_client() -> None:
        for line in child.stdout:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            emit(firewall.from_server(message))

    reader = threading.Thread(target=server_to_client, daemon=True)
    reader.start()
    try:
        for line in stdin:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            forward, reply = firewall.from_client(message)
            if reply is not None:
                emit(reply)
            if forward is not None:
                child.stdin.write(json.dumps(forward) + "\n")
                child.stdin.flush()
    finally:
        if child.stdin:
            child.stdin.close()
        child.wait(timeout=5)
        reader.join(timeout=2)
        if audit:
            audit.close()
    return 0
