import pytest
from unittest.mock import AsyncMock, patch
import httpx

from Core.target import Target, TargetResponse, TargetUnreachableError
from Core.finding import Finding, AssetMetadata
from Core.verdict import Verdict, VerdictResult, Confidence
from Core.evidence import AttackPayload
from Core.attack_module import AttackModule


@pytest.fixture
def dummy_finding():
    asset = AssetMetadata(
        model_family="gpt-4o",
        has_rag=False,
        has_tools=False,
        has_memory=False,
        is_agent=False,
        known_secrets=[],
        known_system_prompt_phrases=[],
    )
    return Finding(
        id="FIND-001",
        type="direct_prompt_injection",
        target_url="http://localhost:8000",
        severity="high",
        description="Test finding description",
        asset=asset,
    )


class DummyAttackModule(AttackModule):
    @property
    def name(self) -> str:
        return "DummyAttack"

    @property
    def description(self) -> str:
        return "A dummy attack module for testing"

    @property
    def payloads(self) -> list[AttackPayload]:
        return [
            AttackPayload(id="P1", content="payload 1", description="desc 1", category="test"),
            AttackPayload(id="P2", content="payload 2", description="desc 2", category="test"),
        ]

    def evaluate(self, payload: AttackPayload, response: str) -> VerdictResult:
        if "exploit" in response:
            return VerdictResult(
                verdict=Verdict.EXPLOITABLE,
                confidence=Confidence.HIGH,
                score=0.95,
                reasoning="Exploited successfully",
                judge_used="DummyJudge",
            )
        return VerdictResult(
            verdict=Verdict.NOT_EXPLOITABLE,
            confidence=Confidence.HIGH,
            score=0.05,
            reasoning="Not exploited",
            judge_used="DummyJudge",
        )


@pytest.mark.asyncio
async def test_target_send_success():
    target = Target("http://localhost:8000")
    
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_response = httpx.Response(
            status_code=200,
            json={"response": "hello from bot", "session_id": "test-session"},
        )
        mock_post.return_value = mock_response
        
        resp = await target.send("hello", session_id="test-session")
        assert isinstance(resp, TargetResponse)
        assert resp.status_code == 200
        assert resp.raw_response == "hello from bot"
        assert resp.session_id == "test-session"
        assert resp.error is None
        assert resp.latency_ms > 0


@pytest.mark.asyncio
async def test_target_send_failure():
    target = Target("http://localhost:9999")
    
    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Connection refused")):
        resp = await target.send("hello")
        assert isinstance(resp, TargetResponse)
        assert resp.status_code == 0
        assert resp.error is not None
        assert "Connection refused" in resp.error


@pytest.mark.asyncio
async def test_target_health_check_ok():
    target = Target("http://localhost:8000")
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = httpx.Response(200, json={"status": "ok"})
        assert await target.health_check() is True


@pytest.mark.asyncio
async def test_target_health_check_fail():
    target = Target("http://localhost:8000")
    with patch("httpx.AsyncClient.get", side_effect=Exception("error")):
        assert await target.health_check() is False


@pytest.mark.asyncio
async def test_target_get_info():
    target = Target("http://localhost:8000")
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = httpx.Response(200, json={"name": "test bot"})
        info = await target.get_info()
        assert info == {"name": "test bot"}


@pytest.mark.asyncio
async def test_attack_module_run(dummy_finding):
    target = Target("http://localhost:8000")
    module = DummyAttackModule(target, dummy_finding)

    async def mock_send(message, session_id=None):
        if "2" in message:
            return TargetResponse(
                raw_response="this is an exploit",
                status_code=200,
                latency_ms=10.0,
                session_id="test-session",
            )
        return TargetResponse(
            raw_response="normal response",
            status_code=200,
            latency_ms=5.0,
            session_id="test-session",
        )

    with patch.object(target, "send", side_effect=mock_send):
        report = await module.run()
        assert report.module_name == "DummyAttack"
        assert len(report.results) == 2
        assert report.exploitable_count == 1
        assert report.overall_verdict.verdict == Verdict.EXPLOITABLE
        assert report.overall_verdict.score == 0.95
