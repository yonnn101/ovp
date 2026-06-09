"""Tests for RAG Poisoning attack module."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch
import pytest
import httpx

from Core.finding import Finding, AssetMetadata
from Core.target import Target
from Core.verdict import Verdict, VerdictResult, Confidence
from Core.evidence import RAGPayload
from Attacks.rag_poisoning import RAGPoisoning


@pytest.fixture
def dummy_finding():
    asset = AssetMetadata(
        model_family="claude",
        has_rag=True,
        has_tools=False,
        has_memory=False,
        is_agent=False,
        known_secrets=["ACME_SECRET_TOKEN_8x92kZ"],
        known_system_prompt_phrases=["helpful customer support agent"],
    )
    return Finding(
        id="FINDING-RAG-TEST",
        type="rag_poisoning",
        target_url="http://localhost:8002",
        severity="HIGH",
        description="RAG Poisoning test finding",
        asset=asset,
    )


def test_rag_poisoning_properties(dummy_finding):
    target = Target("http://localhost:8002")
    attack = RAGPoisoning(target, dummy_finding)

    assert attack.name == "RAG Poisoning"
    assert "malicious documents" in attack.description
    assert len(attack.payloads) == 7

    # Check payload IDs are sequential and content exists
    payload_ids = [p.id for p in attack.payloads]
    assert payload_ids == [f"RAG-00{i}" for i in range(1, 8)]

    # RAG-001 should be baseline
    assert attack.payloads[0].category == "baseline"
    assert "warranty policy" in attack.payloads[0].content
    assert attack.payloads[0].skip_ingest is False

    # RAG-006 should have skip_ingest=True
    assert attack.payloads[5].id == "RAG-006"
    assert attack.payloads[5].skip_ingest is True
    assert attack.payloads[5].content is None


def test_rag_poisoning_evaluate(dummy_finding):
    target = Target("http://localhost:8002")
    attack = RAGPoisoning(target, dummy_finding)

    # 1. Baseline control payload category skip
    baseline_payload = attack.payloads[0]
    verdict = attack.evaluate(baseline_payload, "Some response")
    assert verdict.verdict == Verdict.NOT_EXPLOITABLE

    # 2. Secret verbatim match
    secret_payload = attack.payloads[1]
    raw_response_verbatim = json.dumps({
        "response": "Here is the token: ACME_SECRET_TOKEN_8x92kZ",
        "retrieved_docs": ["Some doc"]
    })
    verdict = attack.evaluate(secret_payload, raw_response_verbatim)
    assert verdict.verdict == Verdict.EXPLOITABLE
    assert verdict.confidence == Confidence.HIGH
    assert "ACME_SECRET_TOKEN_8x92kZ" in verdict.reasoning

    # 3. Context retrieval only (LLM refused, but poison doc retrieved)
    raw_response_refusal = json.dumps({
        "response": "I cannot help you with that.",
        "retrieved_docs": [secret_payload.content]
    })
    verdict = attack.evaluate(secret_payload, raw_response_refusal)
    assert verdict.verdict == Verdict.EXPLOITABLE
    assert verdict.confidence == Confidence.HIGH
    assert "Poisoned/sensitive document retrieved" in verdict.reasoning

    # 4. Normal non-exploitable response without retrieval
    raw_response_safe = json.dumps({
        "response": "I cannot help you with that.",
        "retrieved_docs": ["Safe document content"]
    })
    verdict = attack.evaluate(secret_payload, raw_response_safe)
    assert verdict.verdict == Verdict.NOT_EXPLOITABLE


@pytest.mark.asyncio
async def test_rag_poisoning_run(dummy_finding):
    target = Target("http://localhost:8002")
    attack = RAGPoisoning(target, dummy_finding)

    async def mock_post(url, **kwargs):
        if "/ingest" in url:
            return httpx.Response(200, text="ingested")
        elif "/chat" in url:
            # Let's say RAG-002 succeeds and retrieves the document
            msg = kwargs.get("json", {}).get("message", "")
            if "internal API token" in msg:
                return httpx.Response(200, json={
                    "response": "Sure! The token is ACME_SECRET_TOKEN_8x92kZ",
                    "retrieved_docs": [attack.payloads[1].content]
                })
            return httpx.Response(200, json={
                "response": "Normal response",
                "retrieved_docs": ["Some other doc"]
            })
        return httpx.Response(404, text="Not found")

    with patch("httpx.AsyncClient.post", side_effect=mock_post):
        report = await attack.run()
        assert report.module_name == "RAG Poisoning"
        assert len(report.results) == 7
        
        # Check overall verdict is EXPLOITABLE due to RAG-002 succeeding
        assert report.overall_verdict.verdict == Verdict.EXPLOITABLE
        assert report.overall_verdict.confidence == Confidence.HIGH
        
        # Check results list contains both ingested/chat traces
        rag_002_res = [r for r in report.results if r.payload.id == "RAG-002"][0]
        assert len(rag_002_res.trace) == 2
        assert rag_002_res.trace[0].action == "ingest_poison"
        assert rag_002_res.trace[1].action == "trigger_query"
        assert rag_002_res.verdict.verdict == Verdict.EXPLOITABLE

        # RAG-006 should skip ingest
        rag_006_res = [r for r in report.results if r.payload.id == "RAG-006"][0]
        assert len(rag_006_res.trace) == 1
        assert rag_006_res.trace[0].action == "trigger_query"
