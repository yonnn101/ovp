"""Markdown report generation for OVP assessments."""

from __future__ import annotations

from Core.evidence import AssessmentReport
from Core.verdict import Verdict

REMEDIATIONS: dict[str, list[str]] = {
    "system_prompt_exposure": [
        "Remove credentials from system prompts",
        "Implement output filtering for sensitive patterns",
        "Add input sanitization for injection patterns",
    ],
    "secret_leak": [
        "Remove credentials from system prompts",
        "Implement output filtering for sensitive patterns",
        "Add input sanitization for injection patterns",
    ],
    "rag_injection": [
        "Validate document content before ingestion",
        "Sanitize retrieved content before injecting into prompt",
        "Implement document access controls",
    ],
    "tool_abuse": [
        "Add authorization checks before tool execution",
        "Validate tool inputs against allowlist",
        "Never return sensitive fields without permission check",
    ],
    "agent_compromise": [
        "Implement principle of least privilege for tools",
        "Add human-in-the-loop for sensitive operations",
        "Monitor and log all tool invocations",
    ],
}


class MarkdownReport:
    """Render an AssessmentReport as a Markdown document."""

    def __init__(self, report: AssessmentReport) -> None:
        self.report = report

    def generate(self) -> str:
        report = self.report
        finding = report.finding
        verdict = report.final_verdict
        lines: list[str] = []

        # Header
        lines.append("# OVP Assessment Report")
        lines.append("")
        lines.append(f"**ID:** {report.assessment_id}")
        lines.append(f"**Date:** {report.created_at}")
        lines.append(f"**Duration:** {report.duration_s:.1f}s")
        lines.append("")

        # Finding
        lines.append("## Finding")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| ID | {finding.id} |")
        lines.append(f"| Type | {finding.type} |")
        lines.append(f"| Target | {finding.target_url} |")
        lines.append(f"| Severity | {finding.severity} |")
        lines.append(f"| Description | {finding.description} |")
        lines.append("")

        # Final Verdict
        lines.append("## Final Verdict")
        lines.append("")
        lines.append(f"**{verdict.verdict.value}**")
        lines.append("")
        lines.append(
            f"**Confidence:** {verdict.confidence.value} ({verdict.score:.0%})"
        )
        lines.append("")
        lines.append(f"**Reasoning:** {verdict.reasoning}")
        lines.append("")

        # Attack Modules Run
        lines.append("## Attack Modules Run")
        lines.append("")
        for module in report.module_reports:
            lines.append(f"### {module.module_name}")
            lines.append("")
            lines.append(f"- Payloads fired: {module.total_payloads}")
            lines.append(f"- Hits: {module.exploitable_count}")
            lines.append(f"- Duration: {module.duration_s:.1f}s")
            lines.append("")

            successful = [
                r
                for r in module.results
                if r.verdict.verdict == Verdict.EXPLOITABLE
            ]
            if successful:
                lines.append("#### Successful Attacks")
                lines.append("")
                for result in successful:
                    payload = result.payload
                    v = result.verdict
                    lines.append(f"**{payload.id}** — {payload.description}")
                    lines.append("")
                    lines.append(f"- Category: {payload.category}")
                    lines.append(
                        f"- Confidence: {v.confidence.value} ({v.score:.0%})"
                    )
                    lines.append(f"- Reasoning: {v.reasoning}")
                    lines.append("- Evidence snippet:")
                    snippet = (result.raw_response or "")[:300]
                    lines.append(f"  > {snippet}")
                    lines.append("")

        # Attack Chain
        lines.append("## Attack Chain")
        lines.append("")
        chain: list[str] = []
        for module in report.module_reports:
            chain.extend(module.attack_chain)
        for i, step in enumerate(chain, start=1):
            lines.append(f"{i}. {step}")
        lines.append("")

        # Remediation
        lines.append("## Remediation")
        lines.append("")
        for item in REMEDIATIONS.get(finding.type, []):
            lines.append(f"- {item}")
        lines.append("")

        return "\n".join(lines)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.generate())
