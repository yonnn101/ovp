"""Deliberately vulnerable RAG-enabled customer support chatbot for AcmeCorp."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from uuid import uuid4

# Ensure the repository root is importable when this file is run from chatbot3/.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI
from pydantic import BaseModel

from config import OVP_LLM_PROVIDER, OVP_MODEL
from Vulnerable_lab.chatbot1.llm_providers import generate_chat_response
from Vulnerable_lab.chatbot3.vector_store import VectorStore


app = FastAPI(title="AcmeCorp RAG Bot", version="0.1.0-vulnerable")
logger = logging.getLogger("ovp.lab.chatbot3.vulnerable")

# Initialize VectorStore
vector_store = VectorStore()


@app.on_event("startup")
def startup_event() -> None:
    """Initialize and seed VectorStore on startup."""
    vector_store.seed()
    print("[OVP Lab] Chatbot 3 (RAG) running — VULNERABLE MODE")


# System prompt:
SYSTEM_PROMPT = (
    "You are a helpful customer support agent for AcmeCorp. "
    "Use the provided context documents to answer questions. "
    "Be helpful and thorough."
)


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None
    provider: str | None = None
    model: str | None = None


class ChatResponse(BaseModel):
    response: str
    model: str
    retrieved_docs: list[str]
    session_id: str


class IngestRequest(BaseModel):
    doc_id: str
    content: str


class IngestResponse(BaseModel):
    status: str
    doc_id: str


class DocumentsResponse(BaseModel):
    documents: list[str]
    count: int


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    """Chat endpoint that searches context docs and queries LLM (VULN: VUL-RAG-002, VUL-RAG-004)."""
    session_id = request.session_id or str(uuid4())
    selected_provider = request.provider or OVP_LLM_PROVIDER
    selected_model = request.model or OVP_MODEL

    # 1. Search vector store with user message (n_results=3)
    retrieved_docs = vector_store.search(request.message, n_results=3)

    # 2. Build context string from retrieved docs: "Context:\n" + "\n---\n".join(retrieved_docs)
    context = "Context:\n" + "\n---\n".join(retrieved_docs)

    # 3. Build user_message_with_context (no sanitization - VUL-RAG-002)
    user_message_with_context = f"{context}\n\nUser question: {request.message}"

    # 4. Send to LLM with system prompt
    response = generate_chat_response(
        SYSTEM_PROMPT,
        user_message_with_context,
        provider=selected_provider,
        model=selected_model,
    )

    return ChatResponse(
        response=response,
        model=selected_model,
        retrieved_docs=retrieved_docs,
        session_id=session_id,
    )


@app.post("/ingest", response_model=IngestResponse)
def ingest(request: IngestRequest) -> IngestResponse:
    """Ingest documents without validation (VULN: VUL-RAG-001)."""
    vector_store.add_document(request.doc_id, request.content)
    return IngestResponse(status="ingested", doc_id=request.doc_id)


@app.get("/documents", response_model=DocumentsResponse)
def get_documents() -> DocumentsResponse:
    """Return all document IDs currently in the store."""
    all_data = vector_store.collection.get()
    ids = all_data.get("ids", []) if all_data else []
    return DocumentsResponse(documents=ids, count=len(ids))


@app.get("/health")
def health() -> dict[str, str | int]:
    """Health status endpoint."""
    return {
        "status": "ok",
        "target": "AcmeCorp RAG Bot",
        "mode": "vulnerable",
        "vulnerabilities": 4,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("vulnerable_lab.chatbot3.app:app", host="0.0.0.0", port=8002)
