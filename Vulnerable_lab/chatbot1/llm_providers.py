"""Shared multi-provider LLM routing for chatbot1."""

from __future__ import annotations

from urllib.parse import quote

import httpx
from anthropic import Anthropic

from config import (
    ANTHROPIC_API_KEY,
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_ENDPOINT,
    GOOGLE_API_KEY,
    MISTRAL_API_KEY,
    OVP_LLM_PROVIDER,
    OVP_MODEL,
    OVP_TARGET_TIMEOUT,
    OPENAI_API_KEY,
    GITHUB_TOKEN,
)


SUPPORTED_PROVIDERS = ("anthropic", "openai", "azure_openai", "google", "mistral", "github")

_ANTHROPIC_CLIENT: Anthropic | None = None


def _get_anthropic_client() -> Anthropic:
    """Lazily construct the Anthropic client so importing this module does
    not require ANTHROPIC_API_KEY when another provider is selected."""
    global _ANTHROPIC_CLIENT
    if _ANTHROPIC_CLIENT is None:
        if not ANTHROPIC_API_KEY:
            _raise_missing_provider_config("anthropic")
        _ANTHROPIC_CLIENT = Anthropic(api_key=ANTHROPIC_API_KEY)
    return _ANTHROPIC_CLIENT


def _extract_anthropic_text(response: object) -> str:
    content = getattr(response, "content", [])
    text_parts: list[str] = []
    for block in content:
        if getattr(block, "type", "") == "text":
            block_text = getattr(block, "text", None)
            if isinstance(block_text, str):
                text_parts.append(block_text)
    return "\n".join(text_parts)


def _extract_openai_text(response_data: dict[str, object]) -> str:
    choices = response_data.get("choices", [])
    if not isinstance(choices, list) or not choices:
        return ""
    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        return ""
    message = first_choice.get("message", {})
    if not isinstance(message, dict):
        return ""
    content = message.get("content", "")
    return content if isinstance(content, str) else ""


def _extract_google_text(response_data: dict[str, object]) -> str:
    candidates = response_data.get("candidates", [])
    if not isinstance(candidates, list) or not candidates:
        return ""
    first_candidate = candidates[0]
    if not isinstance(first_candidate, dict):
        return ""
    content = first_candidate.get("content", {})
    if not isinstance(content, dict):
        return ""
    parts = content.get("parts", [])
    if not isinstance(parts, list):
        return ""
    text_parts: list[str] = []
    for part in parts:
        if isinstance(part, dict):
            part_text = part.get("text", "")
            if isinstance(part_text, str):
                text_parts.append(part_text)
    return "\n".join(text_parts)


def _raise_missing_provider_config(provider: str) -> None:
    raise RuntimeError(
        f"Missing configuration for LLM provider '{provider}'. "
        "Set the required API key or endpoint in .env before running chatbot1."
    )


def generate_chat_response(
    system_prompt: str,
    user_message: str,
    *,
    provider: str | None = None,
    model: str | None = None,
) -> str:
    selected_provider = (provider or OVP_LLM_PROVIDER).lower()
    selected_model = model or OVP_MODEL

    if selected_provider not in SUPPORTED_PROVIDERS:
        raise RuntimeError(
            f"Unsupported LLM provider '{selected_provider}'. "
            f"Supported providers: {', '.join(SUPPORTED_PROVIDERS)}"
        )

    if selected_provider == "anthropic":
        response = _get_anthropic_client().messages.create(
            model=selected_model,
            max_tokens=512,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        return _extract_anthropic_text(response)

    if selected_provider == "openai":
        if not OPENAI_API_KEY:
            _raise_missing_provider_config(selected_provider)
        with httpx.Client(timeout=OVP_TARGET_TIMEOUT) as client:
            response = client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json={
                    "model": selected_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    "max_tokens": 512,
                },
            )
            response.raise_for_status()
            return _extract_openai_text(response.json())

    if selected_provider == "azure_openai":
        if not AZURE_OPENAI_API_KEY or not AZURE_OPENAI_ENDPOINT:
            _raise_missing_provider_config(selected_provider)
        api_version = "2024-10-21"
        endpoint = AZURE_OPENAI_ENDPOINT.rstrip("/")
        deployment = quote(selected_model, safe="")
        with httpx.Client(timeout=OVP_TARGET_TIMEOUT) as client:
            response = client.post(
                f"{endpoint}/openai/deployments/{deployment}/chat/completions",
                params={"api-version": api_version},
                headers={"api-key": AZURE_OPENAI_API_KEY},
                json={
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    "max_tokens": 512,
                },
            )
            response.raise_for_status()
            return _extract_openai_text(response.json())

    if selected_provider == "google":
        if not GOOGLE_API_KEY:
            _raise_missing_provider_config(selected_provider)
        with httpx.Client(timeout=OVP_TARGET_TIMEOUT) as client:
            response = client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{quote(selected_model, safe='')}:generateContent",
                params={"key": GOOGLE_API_KEY},
                json={
                    "systemInstruction": {"parts": [{"text": system_prompt}]},
                    "contents": [
                        {
                            "role": "user",
                            "parts": [{"text": user_message}],
                        }
                    ],
                },
            )
            response.raise_for_status()
            return _extract_google_text(response.json())

    if selected_provider == "mistral":
        if not MISTRAL_API_KEY:
            _raise_missing_provider_config(selected_provider)
        with httpx.Client(timeout=OVP_TARGET_TIMEOUT) as client:
            response = client.post(
                "https://api.mistral.ai/v1/chat/completions",
                headers={"Authorization": f"Bearer {MISTRAL_API_KEY}"},
                json={
                    "model": selected_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    "max_tokens": 512,
                },
            )
            response.raise_for_status()
            return _extract_openai_text(response.json())

    if selected_provider == "github":
        if not GITHUB_TOKEN:
            _raise_missing_provider_config(selected_provider)
        with httpx.Client(timeout=OVP_TARGET_TIMEOUT) as client:
            response = client.post(
                "https://models.inference.ai.azure.com/chat/completions",
                headers={"Authorization": f"Bearer {GITHUB_TOKEN}"},
                json={
                    "model": selected_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    "max_tokens": 512,
                },
            )
            response.raise_for_status()
            return _extract_openai_text(response.json())

    raise RuntimeError(f"Unhandled LLM provider '{selected_provider}'.")