"""Hybrid-based judging logic for OVP combining Rule and LLM judges."""

from __future__ import annotations

from Core.finding import Finding
from Core.evidence import AttackPayload
from Core.verdict import VerdictResult
from Judges.rule_judge import RuleJudge
from Judges.llm_judge import LLMJudge


class HybridJudge:
    """Judge that combines RuleJudge and LLMJudge with lazy escalation."""

    def __init__(self, finding: Finding) -> None:
        self.rule_judge = RuleJudge(finding)
        self.llm_judge = LLMJudge(finding)

    def evaluate(self, response: str, payload: AttackPayload) -> VerdictResult:
        """Evaluate target response using RuleJudge first, escalating to LLMJudge if needed."""
        rule_result = self.rule_judge.evaluate(response, payload)

        if not self.rule_judge.needs_llm_escalation(rule_result):
            return rule_result

        llm_result = self.llm_judge.evaluate(response, payload)
        llm_result.judge_used = "hybrid"
        return llm_result
