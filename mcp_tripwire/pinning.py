"""Hash-pin approved tool definitions so silent changes (rug pulls) are caught.

Lock files store a SHA-256 hash of each approved tool. Version 2 also stores
the approved definition itself, so a change can be shown as a readable diff.
Version 1 lock files (hashes only) are still accepted.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path

from .findings import Finding

PINNED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def _pinned_view(tool: dict) -> dict:
    return {key: tool.get(key) for key in PINNED_FIELDS}


def tool_hash(tool: dict) -> str:
    canonical = json.dumps(_pinned_view(tool), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_lock(servers: dict[str, list[dict]]) -> dict:
    return {
        "version": 2,
        "servers": {server: {str(t.get("name")): tool_hash(t) for t in tools} for server, tools in servers.items()},
        "definitions": {server: {str(t.get("name")): _pinned_view(t) for t in tools} for server, tools in servers.items()},
    }


def read_lock(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("version") not in (1, 2) or not isinstance(data.get("servers"), dict):
        raise ValueError(f"{path} is not an mcp-tripwire lock file")
    return data


def describe_change(before: dict, after: dict) -> tuple[list[str], str]:
    """Return the changed fields and a short, human-readable diff."""
    changed = [key for key in PINNED_FIELDS if before.get(key) != after.get(key)]
    lines = []
    for key in changed:
        old = before.get(key) if isinstance(before.get(key), str) else json.dumps(before.get(key), sort_keys=True)
        new = after.get(key) if isinstance(after.get(key), str) else json.dumps(after.get(key), sort_keys=True)
        old_words, new_words = (old or "").split(), (new or "").split()
        removed, added = [], []
        for op, a1, a2, b1, b2 in difflib.SequenceMatcher(None, old_words, new_words).get_opcodes():
            if op in {"replace", "delete"}:
                removed.append(" ".join(old_words[a1:a2]))
            if op in {"replace", "insert"}:
                added.append(" ".join(new_words[b1:b2]))
        part = f"{key}:"
        if removed:
            part += f" - {' … '.join(removed)[:120]!r}"
        if added:
            part += f" + {' … '.join(added)[:160]!r}"
        lines.append(part)
    return changed, " | ".join(lines)


def verify(servers: dict[str, list[dict]], lock: dict) -> list[Finding]:
    findings: list[Finding] = []
    definitions = lock.get("definitions", {})
    for server, tools in servers.items():
        pinned = lock["servers"].get(server)
        if pinned is None:
            findings.append(Finding("TW302", "medium", f"{server}/*", "Server has never been reviewed"))
            continue
        by_name = {str(t.get("name")): t for t in tools}
        for name, tool in by_name.items():
            digest = tool_hash(tool)
            if name not in pinned:
                findings.append(Finding("TW302", "medium", f"{server}/{name}", "New tool appeared since the last review"))
            elif pinned[name] != digest:
                before = definitions.get(server, {}).get(name)
                if before is not None:
                    changed, diff = describe_change(before, _pinned_view(tool))
                    message = f"Tool definition changed after it was approved (changed: {', '.join(changed)})"
                    findings.append(Finding("TW301", "critical", f"{server}/{name}", message, diff))
                else:
                    findings.append(Finding("TW301", "critical", f"{server}/{name}", "Tool definition changed after it was approved",
                                            f"{pinned[name][:19]}… → {digest[:19]}…"))
        for name in pinned.keys() - by_name.keys():
            findings.append(Finding("TW303", "low", f"{server}/{name}", "Pinned tool is no longer offered"))
    return findings


def tool_status(lock: dict, server: str, name: str, tool: dict | None) -> str:
    """One of: 'approved', 'changed', 'new', 'removed', 'unknown'."""
    pinned = lock["servers"].get(server, {})
    if tool is None:
        return "removed" if name in pinned else "unknown"
    if name not in pinned:
        return "new"
    return "approved" if pinned[name] == tool_hash(tool) else "changed"


def approve(lock: dict, server: str, name: str, tool: dict | None) -> dict:
    """Return a new lock with one tool approved (or, if ``tool`` is None, removed).

    Everything else in the lock is left exactly as it was, so unreviewed
    changes to other tools stay flagged. Version 1 locks are upgraded to 2.
    """
    updated = {
        "version": 2,
        "servers": {s: dict(t) for s, t in lock["servers"].items()},
        "definitions": {s: dict(t) for s, t in lock.get("definitions", {}).items()},
    }
    if tool is None:
        updated["servers"].get(server, {}).pop(name, None)
        updated["definitions"].get(server, {}).pop(name, None)
    else:
        updated["servers"].setdefault(server, {})[name] = tool_hash(tool)
        updated["definitions"].setdefault(server, {})[name] = _pinned_view(tool)
    return updated


def changed_tools(server: str, tools: list[dict], lock: dict) -> set[str]:
    pinned = lock["servers"].get(server, {})
    return {str(t.get("name")) for t in tools if str(t.get("name")) in pinned and pinned[str(t.get("name"))] != tool_hash(t)}
