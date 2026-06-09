from fastapi.testclient import TestClient
from Vulnerable_lab.chatbot1.app import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["llm_provider"] == "github"

def test_info():
    response = client.get("/info")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "YonnnCorp Support Bot"
    assert data["llm_provider"] == "github"
