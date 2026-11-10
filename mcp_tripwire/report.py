"""Render findings as text, JSON, SARIF 2.1.0 or a self-contained HTML report."""

from __future__ import annotations

import json
from collections import Counter
from html import escape

from . import __version__
from .findings import OWASP, RULES, SEVERITIES, Finding, sort_findings

COLORS = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[96m", "low": "\033[37m"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def to_text(findings: list[Finding], color: bool = False) -> str:
    if not findings:
        return "No findings."
    lines = []
    for f in sort_findings(findings):
        tag = f"{COLORS[f.severity]}{f.severity.upper():<8}\033[0m" if color else f"{f.severity.upper():<8}"
        lines.append(f"{tag} {f.rule} {f.owasp}  {f.target}  {f.message}")
        if f.evidence:
            lines.append(f"         evidence: {f.evidence}")
    counts = Counter(f.severity for f in findings)
    lines.append("")
    lines.append("Summary: " + ", ".join(f"{counts.get(s, 0)} {s}" for s in SEVERITIES))
    return "\n".join(lines)


def to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in sort_findings(findings)], indent=2)


def to_sarif(findings: list[Finding], artifact: str = "mcp-config") -> str:
    used = sorted({f.rule for f in findings})
    rules = [
        {
            "id": rule,
            "name": RULES[rule][0],
            "shortDescription": {"text": RULES[rule][0].replace("-", " ")},
            "help": {"text": RULES[rule][2]},
            "properties": {"tags": ["security", "mcp", RULES[rule][1]], "precision": "medium"},
        }
        for rule in used
    ]
    results = [
        {
            "ruleId": f.rule,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.target}: {f.message}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": artifact}, "region": {"startLine": 1}},
                "logicalLocations": [{"fullyQualifiedName": f.target}],
            }],
            "properties": {"security-severity": SECURITY_SEVERITY[f.severity], "owasp-mcp": f.owasp},
        }
        for f in sort_findings(findings)
    ]
    driver = {"name": "mcp-tripwire", "version": __version__, "informationUri": "https://github.com/s78519300-creator/mcp-tripwire", "rules": rules}
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": results}]}, indent=2)


STYLE = """
:root{--bg:#060a12;--panel:#0e1524;--line:#1f2a40;--text:#eef3ff;--muted:#8d9ab8;--critical:#ff4d6d;--high:#ff9f43;--medium:#4cc9f0;--low:#94a3b8;--ok:#2dd4bf}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1100px 520px at 85% -15%,#3b0a1e 0,transparent 60%),radial-gradient(900px 500px at -10% 10%,#0b2a4a 0,transparent 55%),var(--bg);color:var(--text);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1120px;margin:auto;padding:40px 20px 64px}.eyebrow{color:var(--critical);font-weight:800;font-size:13px;letter-spacing:.16em;text-transform:uppercase}h1{font-size:42px;line-height:1.1;margin:6px 0 8px}h2{font-size:20px;margin:30px 0 12px}.sub{color:var(--muted);margin:0 0 26px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}.card,.box,.tile{background:var(--panel);border:1px solid var(--line);border-radius:14px}.card{padding:18px;border-top:3px solid var(--c)}.card b{display:block;font-size:36px;line-height:1.1}.card span{color:var(--muted);font-size:13px;text-transform:capitalize}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}.tile{padding:14px}.tile .id{font:800 12px ui-monospace,monospace;color:var(--muted)}.tile .t{font-size:13px;margin:4px 0 8px;min-height:38px}.tile .n{font:800 22px ui-monospace,monospace}.tile.hit{border-color:#5b1a2c;background:linear-gradient(160deg,#2a0f1a,var(--panel))}.tile.hit .n{color:var(--critical)}.tile .n.zero{color:var(--ok)}
.f{display:grid;grid-template-columns:92px 1fr;gap:12px;padding:14px 16px;border-top:1px solid var(--line)}.f:first-child{border:0}.sev{font:800 11px ui-monospace,monospace;text-transform:uppercase;padding:4px 8px;border-radius:7px;height:fit-content;text-align:center;color:#06101d;background:var(--c)}
.target{font:700 13px ui-monospace,monospace;color:#c7d7ff;overflow-wrap:anywhere}.msg{margin:2px 0}.ev{font:12px ui-monospace,monospace;color:var(--muted);background:#070c16;border-radius:8px;padding:6px 9px;margin:6px 0;overflow-wrap:anywhere}.fix{font-size:13px;color:var(--ok)}.meta{font:12px ui-monospace,monospace;color:var(--muted)}
@media(max-width:640px){h1{font-size:32px}.f{grid-template-columns:1fr}}
"""


def to_html(findings: list[Finding], title: str = "MCP Tripwire Report", subtitle: str = "") -> str:
    counts = Counter(f.severity for f in findings)
    by_owasp = Counter(f.owasp for f in findings)
    cards = "".join(f'<div class="card" style="--c:var(--{s})"><b>{counts.get(s, 0)}</b><span>{s}</span></div>' for s in SEVERITIES)
    tiles = "".join(
        f'<div class="tile{" hit" if by_owasp.get(code) else ""}"><div class="id">{code}</div><div class="t">{escape(name)}</div>'
        f'<div class="n{"" if by_owasp.get(code) else " zero"}">{by_owasp.get(code, 0)}</div></div>'
        for code, name in OWASP.items()
    )
    rows = "".join(
        f'<div class="f"><span class="sev" style="--c:var(--{f.severity})">{f.severity}</span><div>'
        f'<div class="target">{escape(f.target)}</div><div class="msg">{escape(f.message)}</div>'
        + (f'<div class="ev">{escape(f.evidence)}</div>' if f.evidence else "")
        + f'<div class="fix">Fix: {escape(f.fix)}</div><div class="meta">{f.rule} · {escape(f.name)} · {f.owasp}</div></div></div>'
        for f in sort_findings(findings)
    ) or '<div class="f"><div></div><div>No findings.</div></div>'
    return (
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{escape(title)}</title><style>{STYLE}</style><main>"
        f'<div class="eyebrow">MCP security scan</div><h1>{escape(title)}</h1><p class="sub">{escape(subtitle)}</p>'
        f'<section class="cards">{cards}</section><h2>Findings by OWASP MCP Top 10 category</h2><section class="grid">{tiles}</section>'
        f'<h2>Findings</h2><section class="box">{rows}</section></main></html>'
    )
