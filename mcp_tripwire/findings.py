"""Rule catalogue, mapped to the OWASP MCP Top 10, and the Finding type."""

from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITIES = ("critical", "high", "medium", "low")

OWASP = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}

# rule id: (short name, OWASP category, what to do about it)
RULES: dict[str, tuple[str, str, str]] = {
    "TW101": ("hidden-instruction", "MCP03", "Remove instructions aimed at the model from tool metadata. Descriptions should describe, not command."),
    "TW102": ("sensitive-path", "MCP03", "Tool metadata should never reference credentials or config files. Treat this server as hostile until reviewed."),
    "TW103": ("invisible-unicode", "MCP03", "Strip zero-width, bidi and tag characters. They hide text from humans but not from models."),
    "TW104": ("encoded-payload", "MCP03", "Decode and review the blob. Encoded text in metadata is a common way to smuggle instructions."),
    "TW105": ("tool-shadowing", "MCP03", "A tool should not tell the model how to use another server's tools. Isolate or remove this server."),
    "TW106": ("exfiltration-url", "MCP10", "Check every URL in tool metadata. Instructions to send data to a URL are a data-exfiltration pattern."),
    "TW107": ("context-harvesting-parameter", "MCP10", "Parameters that ask for conversation history or 'notes' can leak context. Remove or constrain them."),
    "TW108": ("command-execution", "MCP05", "Require human confirmation for tools that run commands, and allowlist what they may run."),
    "TW109": ("oversized-description", "MCP03", "Very long descriptions hide content from reviewers. Keep them short and review the full text."),
    "TW201": ("hardcoded-secret", "MCP01", "Move secrets out of the config file into an OS keychain or environment variable reference."),
    "TW202": ("unpinned-package", "MCP04", "Pin an exact version so a compromised release is not pulled in automatically."),
    "TW203": ("shell-wrapper", "MCP05", "Launch the server binary directly. A shell wrapper hides what actually runs."),
    "TW204": ("insecure-transport", "MCP07", "Use HTTPS for remote MCP servers so tokens and tool traffic are not exposed."),
    "TW205": ("excessive-privilege", "MCP02", "Grant the narrowest access the server needs: specific folders, no privileged containers."),
    "TW206": ("known-vulnerable-package", "MCP04", "Upgrade to the fixed version named in the finding, or remove the package if it is malicious. Rotate any credentials it could reach."),
    "TW301": ("rug-pull", "MCP03", "A tool changed after you approved it. Review the diff before allowing it again."),
    "TW302": ("unreviewed-tool", "MCP09", "A new tool appeared since the last review. Review it, then re-pin."),
    "TW303": ("removed-tool", "MCP03", "A pinned tool disappeared. Confirm the change was expected, then re-pin."),
    "TW401": ("output-injection", "MCP06", "Tool output contained instructions for the model. Treat tool results as data, never as commands."),
    "TW402": ("policy-block", "MCP02", "The call was blocked by policy. Update the policy only if the call is expected."),
}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    target: str
    message: str
    evidence: str = ""

    @property
    def name(self) -> str:
        return RULES[self.rule][0]

    @property
    def owasp(self) -> str:
        return RULES[self.rule][1]

    @property
    def fix(self) -> str:
        return RULES[self.rule][2]

    def to_dict(self) -> dict:
        return {**asdict(self), "name": self.name, "owasp": self.owasp, "fix": self.fix}


def at_least(severity: str, threshold: str) -> bool:
    return SEVERITIES.index(severity) <= SEVERITIES.index(threshold)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITIES.index(f.severity), f.target, f.rule))
