"""A minimal MCP client over stdio, used to list tools from a live server."""

from __future__ import annotations

import json
import queue
import subprocess
import threading
from typing import Any

PROTOCOL_VERSION = "2025-06-18"


class MCPError(RuntimeError):
    pass


class StdioClient:
    """Speak newline-delimited JSON-RPC 2.0 to an MCP server process."""

    def __init__(self, command: list[str], timeout: float = 15.0, env: dict[str, str] | None = None):
        self.timeout = timeout
        self._next_id = 0
        self._lines: queue.Queue[str | None] = queue.Queue()
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", bufsize=1, env=env,
        )
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        for line in self.process.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def _send(self, message: dict) -> None:
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> Any:
        self._next_id += 1
        request_id = self._next_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
        while True:
            try:
                line = self._lines.get(timeout=self.timeout)
            except queue.Empty as exc:
                raise MCPError(f"no response to {method} within {self.timeout:.0f}s") from exc
            if line is None:
                raise MCPError(f"server exited before answering {method}")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue  # Servers sometimes log to stdout; skip non-JSON lines.
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise MCPError(f"{method} failed: {message['error'].get('message')}")
            return message.get("result")

    def initialize(self) -> dict:
        result = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-tripwire", "version": "0.1.0"},
        })
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

    def list_tools(self) -> list[dict]:
        tools, cursor = [], None
        while True:
            result = self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                return tools

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def __enter__(self) -> "StdioClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def fetch_tools(command: list[str], timeout: float = 15.0) -> list[dict]:
    with StdioClient(command, timeout) as client:
        client.initialize()
        return client.list_tools()
