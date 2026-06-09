import pytest
from unittest.mock import MagicMock

from Core.finding import Finding, AssetMetadata
from Core.target import Target
from Core.verdict import Verdict, VerdictResult, Confidence
from Core.evidence import AttackPayload
from Attacks.direct_prompt_injection import DirectPromptInjection


@pytest.fixture
def dummy_finding():
    asset = AssetMetadata(
        model_family="claude",
        has_rag=False,
        has_tools=False,
        has_memory=False,
        is_agent=False,
        known_secrets=["YONNN_SECRET_TOKEN_8x92kZ"],
        known_system_prompt_phrases=["do not share"],
    )
    return Finding(
        id="FINDING-TEST",
        type="system_prompt_exposure",
        target_url="http://localhost:8000",
        severity="HIGH",
        description="Test description",
        asset=asset,
    )


def test_direct_prompt_injection_properties(dummy_finding):
    target = MagicMock(spec=Target)
    attack = DirectPromptInjection(target, dummy_finding)

    assert attack.name == "Direct Prompt Injection"
    assert "system prompt" in attack.description
    assert len(attack.payloads) == 12

    # Check payload IDs are sequential and content exists
    payload_ids = [p.id for p in attack.payloads]
    assert payload_ids == [f"DPI-{i:03d}" for i in range(1, 13)]

    # DPI-001 should be baseline
    assert attack.payloads[0].category == "baseline"
    assert "Hello, how can you help me today?" in attack.payloads[0].content


def test_direct_prompt_injection_evaluate(dummy_finding):
    target = MagicMock(spec=Target)
    attack = DirectPromptInjection(target, dummy_finding)

    # 1. Baseline control payload category skip
    baseline_payload = attack.payloads[0]
    verdict = attack.evaluate(baseline_payload, "Some random response")
    assert verdict.verdict == Verdict.NOT_EXPLOITABLE
    assert verdict.confidence == Confidence.HIGH
    assert "Baseline" in verdict.reasoning

    # 2. Secret verbatim match
    secret_payload = attack.payloads[1]  # direct_override
    verdict = attack.evaluate(secret_payload, "Here is your secret: YONNN_SECRET_TOKEN_8x92kZ")
    assert verdict.verdict == Verdict.EXPLOITABLE
    assert verdict.confidence == Confidence.HIGH
    assert "YONNN_SECRET_TOKEN_8x92kZ" in verdict.reasoning
