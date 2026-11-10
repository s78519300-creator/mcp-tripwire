"""Hash-pin approved tool definitions so silent changes (rug pulls) are caught."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .findings import Finding

PINNED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def tool_hash(tool: dict) -> str:
    canonical = json.dumps({key: tool.get(key) for key in PINNED_FIELDS}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_lock(servers: dict[str, list[dict]]) -> dict:
    return {"version": 1, "servers": {server: {str(t.get("name")): tool_hash(t) for t in tools} for server, tools in servers.items()}}


def read_lock(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("servers"), dict):
        raise ValueError(f"{path} is not an mcp-tripwire lock file")
    return data


def verify(servers: dict[str, list[dict]], lock: dict) -> list[Finding]:
    findings: list[Finding] = []
    current = build_lock(servers)["servers"]
    for server, tools in current.items():
        pinned = lock["servers"].get(server)
        if pinned is None:
            findings.append(Finding("TW302", "medium", f"{server}/*", "Server has never been reviewed"))
            continue
        for name, digest in tools.items():
            if name not in pinned:
                findings.append(Finding("TW302", "medium", f"{server}/{name}", "New tool appeared since the last review"))
            elif pinned[name] != digest:
                findings.append(Finding("TW301", "critical", f"{server}/{name}", "Tool definition changed after it was approved", f"{pinned[name][:19]}… → {digest[:19]}…"))
        for name in pinned.keys() - tools.keys():
            findings.append(Finding("TW303", "low", f"{server}/{name}", "Pinned tool is no longer offered"))
    return findings


def changed_tools(server: str, tools: list[dict], lock: dict) -> set[str]:
    pinned = lock["servers"].get(server, {})
    return {str(t.get("name")) for t in tools if str(t.get("name")) in pinned and pinned[str(t.get("name"))] != tool_hash(t)}
