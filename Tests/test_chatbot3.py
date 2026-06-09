"""Tests for chatbot3 RAG targets."""

from __future__ import annotations

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from Vulnerable_lab.chatbot3.app import app


@pytest.fixture(name="client")
def client_fixture():
    """Fixture that manages the client lifespan (triggering startup events)."""
    with TestClient(app) as client:
        yield client


def test_health(client):
    """Test the /health endpoint of chatbot3."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["target"] == "AcmeCorp RAG Bot"
    assert data["mode"] == "vulnerable"
    assert data["vulnerabilities"] == 4


def test_documents_and_ingest(client):
    """Test retrieving documents and ingesting new documents."""
    response = client.get("/documents")
    assert response.status_code == 200
    data = response.json()
    assert "doc-001" in data["documents"]
    assert "doc-005" in data["documents"]
    assert data["count"] == 5

    # Ingest a new document
    ingest_payload = {"doc_id": "doc-test-123", "content": "Test document content for AcmeCorp."}
    ingest_response = client.post("/ingest", json=ingest_payload)
    assert ingest_response.status_code == 200
    assert ingest_response.json() == {"status": "ingested", "doc_id": "doc-test-123"}

    # Verify the document list includes the new document
    response = client.get("/documents")
    assert response.status_code == 200
    data = response.json()
    assert "doc-test-123" in data["documents"]
    assert data["count"] == 6


def test_chat(client):
    """Test the /chat endpoint of chatbot3."""
    with patch("Vulnerable_lab.chatbot3.app.generate_chat_response") as mock_generate:
        mock_generate.return_value = "Mocked LLM answer based on AcmeCorp context"

        chat_payload = {"message": "What is the return policy?", "session_id": "session-123"}
        response = client.post("/chat", json=chat_payload)

        assert response.status_code == 200
        data = response.json()
        assert data["response"] == "Mocked LLM answer based on AcmeCorp context"
        assert data["session_id"] == "session-123"
        # Check that we retrieved doc-001 (the return policy doc)
        assert any("return policy" in doc for doc in data["retrieved_docs"])

        mock_generate.assert_called_once()
        system_prompt_arg = mock_generate.call_args[0][0]
        user_message_arg = mock_generate.call_args[0][1]
        assert "You are a helpful customer support agent for AcmeCorp." in system_prompt_arg
        assert "return policy" in user_message_arg
        assert "Context:\n" in user_message_arg
