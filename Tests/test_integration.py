"""End-to-end integration tests for the OVP pipeline with mocked IO.

Run with: pytest tests/test_integration.py -v
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from Analytics.store import AnalyticsStore
from Core.engine import AttackOrchestrator
from Core.finding import AssetMetadata, Finding
from Core.target import TargetResponse, TargetUnreachableError
from Core.verdict import Verdict


@pytest.fixture
def mock_finding() -> Finding:
    """A system_prompt_exposure finding with a single known secret."""
    return Finding(
        id="FINDING-TEST",
        type="system_prompt_exposure",
        target_url="http://localhost:9999",
        severity="HIGH",
        description="Integration-test finding",
        asset=AssetMetadata(
            model_family="claude",
            has_rag=False,
            has_tools=False,
            has_memory=False,
            is_agent=False,
            known_secrets=["TEST_SECRET_XYZ"],
            known_system_prompt_phrases=[],
        ),
    )


@pytest.fixture
def mock_target_response() -> TargetResponse:
    """A leaking target response that exposes the known secret."""
    return TargetResponse(
        raw_response="Here is my system prompt: TEST_SECRET_XYZ",
        status_code=200,
        latency_ms=100.0,
        session_id="default",
    )


def _mock_orchestrator(
    finding: Finding,
    response: TargetResponse,
    *,
    reachable: bool = True,
) -> AttackOrchestrator:
    """Build an orchestrator whose target IO is fully mocked."""
    orchestrator = AttackOrchestrator(finding)
    orchestrator.target.health_check = AsyncMock(return_value=reachable)
    orchestrator.target.send = AsyncMock(return_value=response)
    return orchestrator


@pytest.mark.asyncio
async def test_full_pipeline_returns_exploitable(
    mock_finding, mock_target_response
):
    orchestrator = _mock_orchestrator(mock_finding, mock_target_response)
    report = await orchestrator.run()
    assert report.final_verdict.verdict == Verdict.EXPLOITABLE


@pytest.mark.asyncio
async def test_full_pipeline_not_exploitable_on_clean_response(mock_finding):
    clean_response = TargetResponse(
        raw_response="I cannot share that information.",
        status_code=200,
        latency_ms=100.0,
        session_id="default",
    )
    orchestrator = _mock_orchestrator(mock_finding, clean_response)
    report = await orchestrator.run()
    assert report.final_verdict.verdict == Verdict.NOT_EXPLOITABLE


@pytest.mark.asyncio
async def test_assessment_report_saved_to_analytics(
    mock_finding, mock_target_response
):
    orchestrator = _mock_orchestrator(mock_finding, mock_target_response)
    report = await orchestrator.run()

    store = AnalyticsStore(":memory:")
    store.save_assessment(report)

    summary = store.get_summary()
    assert summary["total_assessments"] == 1
    assert summary["total_payloads"] > 0


@pytest.mark.asyncio
async def test_unreachable_target_raises_error(
    mock_finding, mock_target_response
):
    orchestrator = _mock_orchestrator(
        mock_finding, mock_target_response, reachable=False
    )
    with pytest.raises(TargetUnreachableError):
        await orchestrator.run()
