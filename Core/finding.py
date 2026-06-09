"""Finding data contracts for OVP."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class AssetMetadata:
	"""Static metadata describing the assessed target asset."""

	model_family: str
	has_rag: bool
	has_tools: bool
	has_memory: bool
	is_agent: bool
	known_secrets: list[str]
	known_system_prompt_phrases: list[str]


@dataclass(slots=True)
class Finding:
	"""Top-level finding contract used throughout OVP."""

	id: str
	type: str
	target_url: str
	severity: str
	description: str
	asset: AssetMetadata
	created_at: datetime = field(default_factory=datetime.now)
