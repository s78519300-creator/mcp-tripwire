"""A simple letter grade for a set of findings, plus a README badge."""

from __future__ import annotations

from html import escape

from .findings import Finding

PENALTY = {"critical": 25, "high": 10, "medium": 4, "low": 1}
GRADE_COLORS = {"A": "#16a34a", "B": "#65a30d", "C": "#d97706", "D": "#ea580c", "F": "#dc2626"}


def grade(findings: list[Finding]) -> tuple[str, int]:
    """Return (letter, score out of 100). Any critical finding means F."""
    score = max(0, 100 - sum(PENALTY[f.severity] for f in findings))
    if any(f.severity == "critical" for f in findings):
        score = min(score, 39)
    letter = next(g for g, floor in (("A", 90), ("B", 75), ("C", 60), ("D", 40), ("F", 0)) if score >= floor)
    return letter, score


def _text_width(text: str) -> int:
    return int(sum(7.2 if ch.isupper() else 6.3 for ch in text)) + 12


def badge_svg(letter: str, label: str = "MCP security") -> str:
    """A flat, shields-style SVG badge."""
    value = f"grade {letter}"
    left, right = _text_width(label), _text_width(value)
    total = left + right
    color = GRADE_COLORS[letter]
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{escape(label)}: {value}">'
        f"<title>{escape(label)}: {value}</title>"
        f'<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{left}" height="20" fill="#555"/><rect x="{left}" width="{right}" height="20" fill="{color}"/>'
        f'<rect width="{total}" height="20" fill="url(#s)"/></g>'
        f'<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{left / 2:.1f}" y="14">{escape(label)}</text><text x="{left + right / 2:.1f}" y="14">{value}</text></g></svg>'
    )
