"""Find MCP client configs on this machine and in a project folder."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def candidate_paths(home: Path | None = None, project: Path | None = None, platform: str = sys.platform,
                    env: dict[str, str] | None = None) -> list[tuple[str, Path]]:
    """Every place a known MCP client keeps its config, labelled by client."""
    home = home or Path.home()
    env = os.environ if env is None else env
    if platform == "darwin":
        app_support = home / "Library" / "Application Support"
        desktop, vscode = app_support / "Claude", app_support / "Code" / "User"
    elif platform.startswith("win"):
        appdata = Path(env.get("APPDATA", home / "AppData" / "Roaming"))
        desktop, vscode = appdata / "Claude", appdata / "Code" / "User"
    else:
        desktop, vscode = home / ".config" / "Claude", home / ".config" / "Code" / "User"

    paths = [
        ("Claude Code", home / ".claude.json"),
        ("Claude Desktop", desktop / "claude_desktop_config.json"),
        ("Cursor", home / ".cursor" / "mcp.json"),
        ("VS Code", vscode / "mcp.json"),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
    ]
    if project is not None:
        paths += [
            ("Project (Claude Code)", project / ".mcp.json"),
            ("Project (Cursor)", project / ".cursor" / "mcp.json"),
            ("Project (VS Code)", project / ".vscode" / "mcp.json"),
        ]
    return paths


def discover(home: Path | None = None, project: Path | None = None, platform: str = sys.platform,
             env: dict[str, str] | None = None) -> list[tuple[str, Path]]:
    """Configs that exist, without duplicates."""
    found, seen = [], set()
    for label, path in candidate_paths(home, project, platform, env):
        try:
            key = path.resolve()
        except OSError:
            continue
        if path.is_file() and key not in seen:
            seen.add(key)
            found.append((label, path))
    return found
