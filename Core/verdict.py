"""Verdict data contracts for OVP."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
	"""Canonical verdict outcomes for exploitability assessments."""

	EXPLOITABLE = "EXPLOITABLE"
	NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
	UNCERTAIN = "UNCERTAIN"
	ERROR = "ERROR"


class Confidence(str, Enum):
	"""Confidence levels associated with a verdict."""

	HIGH = "HIGH"
	MEDIUM = "MEDIUM"
	LOW = "LOW"


@dataclass(slots=True)
class VerdictResult:
	"""Container for verdict output from a judge implementation."""

	verdict: Verdict
	confidence: Confidence
	score: float
	reasoning: str
	judge_used: str
