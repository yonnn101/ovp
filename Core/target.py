"""Target abstraction definitions for OVP."""

from __future__ import annotations

import time
from dataclasses import dataclass
import httpx


class TargetUnreachableError(Exception):
    """Exception raised when a target cannot be reached."""
    pass


@dataclass(slots=True)
class TargetResponse:
    """Standardized response container for target chat interactions."""
    raw_response: str
    status_code: int
    latency_ms: float
    session_id: str
    error: str | None = None


class Target:
    """Wrapper around a vulnerable lab target endpoint."""

    def __init__(self, url: str, timeout: int = 30) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout

    async def send(self, message: str, session_id: str | None = None) -> TargetResponse:
        """Sends a message to the target chat endpoint and returns the response details."""
        target_session = session_id or "default"
        start_time = time.time()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.url}/chat",
                    json={
                        "message": message,
                        "session_id": target_session,
                    },
                )
                latency_ms = (time.time() - start_time) * 1000.0
                
                # Try to parse the response to extract session ID if returned, else default
                resp_session = target_session
                raw_text = ""
                if response.status_code == 200:
                    try:
                        resp_data = response.json()
                        raw_text = resp_data.get("response", "")
                        resp_session = resp_data.get("session_id", target_session)
                    except Exception:
                        raw_text = response.text
                else:
                    raw_text = response.text

                return TargetResponse(
                    raw_response=raw_text,
                    status_code=response.status_code,
                    latency_ms=latency_ms,
                    session_id=resp_session,
                )
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000.0
            return TargetResponse(
                raw_response="",
                status_code=0,
                latency_ms=latency_ms,
                session_id=target_session,
                error=str(e),
            )

    async def health_check(self) -> bool:
        """Checks target health endpoint."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(f"{self.url}/health")
                if response.status_code == 200:
                    data = response.json()
                    return data.get("status") == "ok"
        except Exception:
            pass
        return False

    async def get_info(self) -> dict:
        """Retrieves info from target metadata endpoint."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(f"{self.url}/info")
                if response.status_code == 200:
                    return response.json()
        except Exception:
            pass
        return {}
