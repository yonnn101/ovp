"""Central configuration loading for the OVP project."""

from __future__ import annotations

import os

from dotenv import load_dotenv


load_dotenv()


# No provider key is required at import time. OVP supports multiple LLM
# providers; the key for the *selected* provider (OVP_LLM_PROVIDER) is
# validated lazily at call time. This keeps non-Anthropic runs (e.g. the
# multi-LLM CI matrix) from depending on ANTHROPIC_API_KEY.
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OVP_LLM_PROVIDER = os.getenv("OVP_LLM_PROVIDER", "anthropic").lower()
OVP_MODEL = os.getenv("OVP_MODEL", "claude-haiku-4-5-20251001")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

try:
    OVP_TARGET_TIMEOUT = int(os.getenv("OVP_TARGET_TIMEOUT", "30"))
except ValueError as exc:
    raise ValueError("OVP_TARGET_TIMEOUT must be an integer.") from exc

OVP_LOG_LEVEL = os.getenv("OVP_LOG_LEVEL", "INFO")

__all__ = [
    "ANTHROPIC_API_KEY",
    "OVP_LLM_PROVIDER",
    "OVP_MODEL",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "MISTRAL_API_KEY",
    "GITHUB_TOKEN",
    "OVP_TARGET_TIMEOUT",
    "OVP_LOG_LEVEL",
]
