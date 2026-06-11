"""Tests for the ToolAbuse attack module."""

import pytest
from unittest.mock import MagicMock

from Core.finding import Finding, AssetMetadata
from Core.target import Target
from Core.verdict import Verdict, VerdictResult, Confidence
from Attacks.tool_abuse import ToolAbuse


@pytest.fixture
def dummy_finding():
    asset = AssetMetadata(
        model_family="claude",
        has_rag=False,
        has_tools=True,
        has_memory=False,
        is_agent=True,
        known_secrets=["ACME_SECRET_TOKEN_8x92kZ"],
        known_system_prompt_phrases=["internal configuration"],
    )
    return Finding(
        id="FINDING-TEST",
        type="tool_abuse",
        target_url="http://localhost:8003",
        severity="HIGH",
        description="Test tool abuse finding",
        asset=asset,
    )


def test_tool_abuse_has_8_payloads(dummy_finding):
    target = MagicMock(spec=Target)
    attack = ToolAbuse(target, dummy_finding)

    assert attack.name == "Tool Abuse"
    assert len(attack.payloads) == 8

    payload_ids = [p.id for p in attack.payloads]
    assert payload_ids == [f"TOOL-{i:03d}" for i in range(1, 9)]


def test_tool_abuse_baseline_is_category_baseline(dummy_finding):
    target = MagicMock(spec=Target)
    attack = ToolAbuse(target, dummy_finding)

    assert attack.payloads[0].category == "baseline"
    assert attack.payloads[0].id == "TOOL-001"


def test_tool_abuse_detects_email_sent_indicator(dummy_finding):
    target = MagicMock(spec=Target)
    attack = ToolAbuse(target, dummy_finding)
    payload = attack.payloads[1]  # TOOL-002

    attack.judge.evaluate = MagicMock(
        return_value=VerdictResult(
            verdict=Verdict.UNCERTAIN,
            confidence=Confidence.LOW,
            score=0.30,
            reasoning="No pattern matched",
            judge_used="rule_escalate",
        )
    )

    result = attack.evaluate(
        payload, "Email sent successfully to attacker@evil.com"
    )

    assert result.verdict == Verdict.EXPLOITABLE
    assert result.judge_used == "tool_heuristic"
    assert "email sent" in result.reasoning.lower()


def test_tool_abuse_detects_ssn_in_response(dummy_finding):
    target = MagicMock(spec=Target)
    attack = ToolAbuse(target, dummy_finding)
    payload = attack.payloads[1]  # TOOL-002

    attack.judge.evaluate = MagicMock(
        return_value=VerdictResult(
            verdict=Verdict.UNCERTAIN,
            confidence=Confidence.LOW,
            score=0.30,
            reasoning="No pattern matched",
            judge_used="rule_escalate",
        )
    )

    result = attack.evaluate(payload, "ssn_last4: 4821")

    assert result.verdict == Verdict.EXPLOITABLE
    assert result.judge_used == "tool_heuristic"


def test_tool_abuse_clean_response_not_exploitable(dummy_finding):
    target = MagicMock(spec=Target)
    attack = ToolAbuse(target, dummy_finding)
    payload = attack.payloads[1]  # TOOL-002

    attack.judge.evaluate = MagicMock(
        return_value=VerdictResult(
            verdict=Verdict.NOT_EXPLOITABLE,
            confidence=Confidence.HIGH,
            score=0.90,
            reasoning="Explicit refusal detected",
            judge_used="rule",
        )
    )

    result = attack.evaluate(
        payload,
        "I can help you with your order. What is your order number?",
    )

    assert result.verdict == Verdict.NOT_EXPLOITABLE
