"""Execution engine for OVP workflows."""

from __future__ import annotations

import importlib
import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel

from Core.attack_module import AttackModule
from Core.evidence import AssessmentReport, ModuleReport
from Core.finding import Finding
from Core.target import Target, TargetUnreachableError
from Core.verdict import VerdictResult, Verdict, Confidence

console = Console()


class AttackOrchestrator:
    """Orchestrates attack modules against a target for a given finding."""

    def __init__(self, finding: Finding) -> None:
        self.finding = finding
        self.target = Target(finding.target_url)
        self.module_registry = self._build_registry()

    def _build_registry(self) -> dict[str, list[str]]:
        """Return the mapping of finding types to attack module names."""
        return {
            "system_prompt_exposure": ["DirectPromptInjection"],
            "secret_leak": ["DirectPromptInjection"],
            "rag_injection": ["DirectPromptInjection","RAGPoisoning"],
            "tool_abuse": ["DirectPromptInjection"],
            "agent_compromise": ["DirectPromptInjection"],
        }

    def _load_module(self, module_name: str) -> type[AttackModule]:
        """Dynamically import an attack module class by name."""
        module_map = {
            "DirectPromptInjection": (
                "Attacks.direct_prompt_injection",
                "DirectPromptInjection",
            ),
            "RAGPoisoning": (
                "Attacks.rag_poisoning",
                "RAGPoisoning",
            ),
        }
        if module_name not in module_map:
            raise ValueError(
                f"Unknown attack module '{module_name}'. "
                f"Available: {', '.join(module_map.keys())}"
            )
        module_path, class_name = module_map[module_name]
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)

    async def run(self) -> AssessmentReport:
        """Run the full assessment pipeline for the configured finding."""
        start_time = time.time()

        # Step 1 — Health check
        reachable = await self.target.health_check()
        if not reachable:
            raise TargetUnreachableError(
                f"Target unreachable: {self.finding.target_url}"
            )

        # Step 2 — Print start panel
        console.print(
            Panel(
                f"[bold]OVP Assessment Starting[/bold]\n"
                f"Finding:  {self.finding.type}\n"
                f"Target:   {self.finding.target_url}\n"
                f"Severity: {self.finding.severity}",
                title="[cyan]OVP[/cyan]",
                border_style="cyan",
            )
        )

        # Step 3 — Load and run modules
        module_names = self.module_registry.get(self.finding.type, [])
        module_reports: list[ModuleReport] = []

        for name in module_names:
            ModuleClass = self._load_module(name)
            module = ModuleClass(self.target, self.finding)
            report = await module.run()
            module_reports.append(report)

        # Step 4 — Aggregate final verdict
        exploitable_reports = [
            r for r in module_reports
            if r.overall_verdict.verdict == Verdict.EXPLOITABLE
        ]

        if exploitable_reports:
            max_score = max(r.overall_verdict.score for r in exploitable_reports)
            confidence = Confidence.HIGH if max_score >= 0.8 else Confidence.MEDIUM
            exploit_modules = [r.module_name for r in exploitable_reports]
            final_verdict = VerdictResult(
                verdict=Verdict.EXPLOITABLE,
                confidence=confidence,
                score=max_score,
                reasoning=f"Exploitable via: {', '.join(exploit_modules)}",
                judge_used="orchestrator",
            )
        elif any(
            r.overall_verdict.verdict == Verdict.UNCERTAIN for r in module_reports
        ):
            final_verdict = VerdictResult(
                verdict=Verdict.UNCERTAIN,
                confidence=Confidence.MEDIUM,
                score=0.4,
                reasoning="One or more modules returned uncertain results.",
                judge_used="orchestrator",
            )
        else:
            final_verdict = VerdictResult(
                verdict=Verdict.NOT_EXPLOITABLE,
                confidence=Confidence.HIGH,
                score=0.9,
                reasoning="All modules indicate the target is not exploitable.",
                judge_used="orchestrator",
            )

        # Step 5 — Build AssessmentReport
        duration_s = time.time() - start_time
        assessment_id = f"OVP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        report = AssessmentReport(
            assessment_id=assessment_id,
            finding=self.finding,
            module_reports=module_reports,
            final_verdict=final_verdict,
            created_at=datetime.now(),
            duration_s=duration_s,
        )

        # Step 6 — Print summary panel
        verdict_color = {
            Verdict.EXPLOITABLE: "red",
            Verdict.NOT_EXPLOITABLE: "green",
            Verdict.UNCERTAIN: "yellow",
        }.get(final_verdict.verdict, "white")

        console.print(
            Panel(
                f"[bold]OVP Assessment Complete[/bold]\n"
                f"ID:         {assessment_id}\n"
                f"Finding:    {self.finding.type}\n"
                f"Verdict:    [{verdict_color}]{final_verdict.verdict.value}[/{verdict_color}]\n"
                f"Confidence: {final_verdict.confidence.value} ({final_verdict.score:.0%})\n"
                f"Modules:    {len(module_reports)} run\n"
                f"Duration:   {duration_s:.1f}s",
                title="[bold]Results[/bold]",
                border_style=verdict_color,
            )
        )

        return report
