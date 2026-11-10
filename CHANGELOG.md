# Changelog

## 0.2.1

- `mcptw approve`: approve reviewed tool changes one at a time. It shows the diff, refuses new definitions that fail the security scan (unless `--force`), asks for confirmation, and leaves every other change flagged. Thanks to Sagar V for the question that prompted this.

## 0.2.0

- `mcptw scan`: finds and grades every MCP config on the machine (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf) plus project configs. Runs nothing.
- TW206: known-vulnerable and malicious package checks for `mcp-remote`, MCP Inspector, the filesystem server and `postmark-mcp`, with links to the OSV records.
- Letter grade on every scan, and `mcptw badge` writes an SVG badge for your README.
- Rug-pull findings now show exactly what changed. Lock files store approved definitions (version 2); version 1 lock files still work.
- Agent skill and Claude Code `~/.claude.json` support, including per-project servers.

## 0.1.0

- Config scanner, tool scanner, hash pinning, runtime firewall proxy, SARIF/JSON/HTML output and GitHub Action.
