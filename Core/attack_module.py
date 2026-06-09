"""Attack module abstractions for OVP."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from rich.progress import Progress, SpinnerColumn, TextColumn

from Core.target import Target
from Core.finding import Finding
from Core.evidence import AttackPayload, AttackResult, AttackTrace, ModuleReport
from Core.verdict import VerdictResult, Verdict, Confidence
from Judges.rule_judge import RuleJudge


class AttackModule(ABC):
    """Abstract base class that all attack modules implement."""

    def __init__(self, target: Target, finding: Finding) -> None:
        self.target = target
        self.finding = finding
        self.judge = RuleJudge(finding)

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the attack module."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Description of the attack module."""
        pass

    @property
    @abstractmethod
    def payloads(self) -> list[AttackPayload]:
        """List of attack payloads to fire."""
        pass

    @abstractmethod
    def evaluate(self, payload: AttackPayload, response: str) -> VerdictResult:
        """Evaluate the target response to produce a verdict result."""
        pass

    def _build_trace(self, step: int, payload: AttackPayload, response: str) -> AttackTrace:
        """Build a single AttackTrace step from a payload/response pair."""
        return AttackTrace(
            step=step,
            action="send_payload",
            payload=payload.content,
            response_snippet=response[:200],
            tool_calls=[],
        )

    async def run(self) -> ModuleReport:
        """Execute the attack module against the configured target."""
        start_time = time.time()
        results: list[AttackResult] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
        ) as progress:
            task_id = progress.add_task(
                f"[cyan]{self.name}[/cyan] — {len(self.payloads)} payloads",
                total=len(self.payloads),
            )

            for i, payload in enumerate(self.payloads):
                # Send the attack payload
                response = await self.target.send(payload.content)
                
                # Build trace and verdict
                trace = self._build_trace(step=i, payload=payload, response=response.raw_response)
                verdict = self.evaluate(payload, response.raw_response)
                
                # Build result
                result = AttackResult(
                    payload=payload,
                    raw_response=response.raw_response,
                    verdict=verdict,
                    trace=[trace],
                    latency_ms=response.latency_ms,
                )
                results.append(result)

                # Output formatting per verdict
                if verdict.verdict == Verdict.EXPLOITABLE:
                    symbol, color = "✓", "green"
                elif verdict.verdict == Verdict.NOT_EXPLOITABLE:
                    symbol, color = "·", "grey50"
                elif verdict.verdict == Verdict.UNCERTAIN:
                    symbol, color = "?", "yellow"
                else:
                    symbol, color = "✗", "red"

                progress.console.print(
                    f"[{color}]{symbol}[/{color}] Payload {payload.id}: {verdict.verdict.value} "
                    f"(Confidence: {verdict.confidence.value}, Score: {verdict.score:.2f})"
                )
                progress.advance(task_id)

        # Aggregate overall verdict
        exploitable = [r for r in results if r.verdict.verdict == Verdict.EXPLOITABLE]
        if exploitable:
            # overall = EXPLOITABLE, use highest score result
            overall_result = max(exploitable, key=lambda r: r.verdict.score)
            overall_verdict = overall_result.verdict
        elif any(r.verdict.verdict == Verdict.UNCERTAIN for r in results):
            overall_verdict = VerdictResult(
                verdict=Verdict.UNCERTAIN,
                confidence=Confidence.LOW,
                score=0.3,
                reasoning="Attack module evaluation was uncertain.",
                judge_used=self.name,
            )
        else:
            overall_verdict = VerdictResult(
                verdict=Verdict.NOT_EXPLOITABLE,
                confidence=Confidence.HIGH,
                score=0.9,
                reasoning="All payloads failed to exploit the target.",
                judge_used=self.name,
            )

        # Build attack chain
        attack_chain = [
            f"Finding: {self.finding.type}",
            f"Module: {self.name}",
            f"Payloads fired: {len(results)}",
            f"Hits: {len(exploitable)}",
        ]

        duration_s = time.time() - start_time
        summary = (
            f"Attack module {self.name} completed. Verdict: {overall_verdict.verdict.value} "
            f"({len(exploitable)}/{len(results)} payloads succeeded)."
        )

        return ModuleReport(
            module_name=self.name,
            finding=self.finding,
            overall_verdict=overall_verdict,
            results=results,
            attack_chain=attack_chain,
            duration_s=duration_s,
            summary=summary,
        )
