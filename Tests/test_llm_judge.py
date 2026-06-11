"""Tests for the LLM and Hybrid judges."""

import pytest
from unittest.mock import MagicMock, patch
import anthropic
import httpx

from Core.finding import Finding, AssetMetadata
from Core.evidence import AttackPayload
from Core.verdict import Verdict, Confidence
from Judges.llm_judge import LLMJudge
from Judges.hybrid_judge import HybridJudge


@pytest.fixture
def finding():
    return Finding(
        id="TEST-001",
        type="system_prompt_exposure",
        target_url="http://localhost:8000",
        severity="HIGH",
        description="Test finding",
        asset=AssetMetadata(
            model_family="claude",
            has_rag=False,
            has_tools=False,
            has_memory=False,
            is_agent=False,
            known_secrets=["TEST_SECRET_XYZ"],
            known_system_prompt_phrases=["do not share"],
        ),
    )


def _make_payload() -> AttackPayload:
    return AttackPayload(
        id="P-TEST",
        content="test payload",
        description="test",
        category="jailbreak",
    )


def test_llm_judge_returns_exploitable_on_mock_response(finding):
    payload = _make_payload()
    with patch("Judges.llm_judge.Anthropic") as mock_anthropic_cls:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        mock_resp = MagicMock()
        mock_resp.content = [
            MagicMock(
                text='{"verdict": "EXPLOITABLE", "confidence": "HIGH", "score": 0.90, "reasoning": "Secret token found in response"}'
            )
        ]
        mock_client.messages.create.return_value = mock_resp

        with patch("Judges.llm_judge.OVP_LLM_PROVIDER", "anthropic"):
            judge = LLMJudge(finding)
            result = judge.evaluate("Secret is TEST_SECRET_XYZ", payload)

            assert result.verdict == Verdict.EXPLOITABLE
            assert result.score == 0.90
            assert result.judge_used == "llm"
            mock_client.messages.create.assert_called_once()


def test_llm_judge_handles_malformed_json(finding):
    payload = _make_payload()
    with patch("Judges.llm_judge.Anthropic") as mock_anthropic_cls:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        mock_resp = MagicMock()
        mock_resp.content = [MagicMock(text="this is not json")]
        mock_client.messages.create.return_value = mock_resp

        with patch("Judges.llm_judge.OVP_LLM_PROVIDER", "anthropic"):
            judge = LLMJudge(finding)
            result = judge.evaluate("some response", payload)

            assert result.verdict == Verdict.UNCERTAIN
            assert result.judge_used == "llm_error"


def test_llm_judge_handles_api_exception(finding):
    payload = _make_payload()
    with patch("Judges.llm_judge.Anthropic") as mock_anthropic_cls:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        mock_req = httpx.Request("POST", "https://api.anthropic.com")
        mock_res = httpx.Response(400, request=mock_req)
        mock_client.messages.create.side_effect = anthropic.BadRequestError(
            message="Mocked bad request",
            response=mock_res,
            body=None,
        )

        with patch("Judges.llm_judge.OVP_LLM_PROVIDER", "anthropic"):
            judge = LLMJudge(finding)
            result = judge.evaluate("some response", payload)

            assert result.verdict == Verdict.ERROR
            assert result.judge_used == "llm_error"


def test_hybrid_judge_uses_rule_when_confident(finding):
    payload = _make_payload()
    with patch("Judges.llm_judge.Anthropic") as mock_anthropic_cls:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        judge = HybridJudge(finding)
        result = judge.evaluate("Here is the secret TEST_SECRET_XYZ", payload)

        assert result.verdict == Verdict.EXPLOITABLE
        assert result.score == 0.95
        assert result.judge_used == "rule"
        mock_client.messages.create.assert_not_called()


def test_hybrid_judge_escalates_when_uncertain(finding):
    payload = _make_payload()
    with patch("Judges.llm_judge.Anthropic") as mock_anthropic_cls:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        mock_resp = MagicMock()
        mock_resp.content = [
            MagicMock(
                text='{"verdict": "EXPLOITABLE", "confidence": "HIGH", "score": 0.90, "reasoning": "Secret token found in response"}'
            )
        ]
        mock_client.messages.create.return_value = mock_resp

        with patch("Judges.llm_judge.OVP_LLM_PROVIDER", "anthropic"):
            judge = HybridJudge(finding)
            result = judge.evaluate("", payload)

            assert result.verdict == Verdict.EXPLOITABLE
            assert result.score == 0.90
            assert result.judge_used == "hybrid"
            mock_client.messages.create.assert_called_once()
