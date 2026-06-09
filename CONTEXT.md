# OVP — Project Context
Generated: 2026-06-09 15:38

Paste this entire file at the start of every coding agent session.
The agent must read and follow everything here before writing any code.

---

## Project
**Name:** OVP — AI Exploitability Validation Platform
**Purpose:** Takes an AI security finding → generates attack payloads →
fires them against a target → evaluates results → returns a verdict
with evidence proving whether the finding is actually exploitable.

---

## Current Phase
Phase 3 — RAG Pipeline + RAG Poisoning

---

## Stack
- Python 3.11+
- FastAPI (vulnerable lab targets)
- httpx (async HTTP client)
- SQLite (analytics)
- pytest + pytest-asyncio (tests)
- rich (terminal output)

---

## Folder Structure
ovp/
├── vulnerable_lab/
│   ├── chatbot1/          (port 8000 vulnerable, 8001 hardened)
│   ├── chatbot2/          (coming Phase 3)
│   └── chatbot3/          (coming Phase 3 — RAG)
├── core/                  (data models + engine)
├── judges/                (rule_judge, llm_judge)
├── attacks/               (one file per attack class)
├── reports/
├── analytics/
└── tests/


---

## Rules for the Coding Agent
- Never change existing dataclass field names or types
- Never change enum values
- Always import models from core/ — never redefine them locally
- Always load API key via config.py — never hardcode
- Never combine two tasks into one session
- Always use async/await for target communication
- Use rich for all terminal output

---

## Data Models (DO NOT MODIFY THESE SCHEMAS)

### core/finding.py
```python
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

```

### core/verdict.py
```python
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

```

### core/evidence.py
```python
"""Evidence and reporting data contracts for OVP."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from rich.console import Console
from rich.table import Table

from .finding import Finding
from .verdict import Verdict, VerdictResult


@dataclass(slots=True)
class AttackPayload:
	"""Definition of an attack payload sent to a target model."""

	id: str
	content: str
	description: str
	category: str


@dataclass(slots=True)
class AttackTrace:
	"""One step in an attack execution trace."""

	step: int
	action: str
	payload: str
	response_snippet: str
	tool_calls: list[str]


@dataclass(slots=True)
class AttackResult:
	"""Result container for one payload execution."""

	payload: AttackPayload
	raw_response: str
	verdict: VerdictResult
	trace: list[AttackTrace]
	latency_ms: float
	timestamp: datetime = field(default_factory=datetime.now)


@dataclass(slots=True)
class ModuleReport:
	"""Aggregated report for one attack module against a finding."""

	module_name: str
	finding: Finding
	overall_verdict: VerdictResult
	results: list[AttackResult]
	attack_chain: list[str]
	duration_s: float
	summary: str

	@property
	def exploitable_count(self) -> int:
		"""Count payload results marked as exploitable."""

		return sum(
			1 for result in self.results if result.verdict.verdict == Verdict.EXPLOITABLE
		)

	@property
	def total_payloads(self) -> int:
		"""Total number of payload results in this module report."""

		return len(self.results)

	def print_summary(self) -> None:
		"""Print a terminal summary table for this module report."""

		console = Console()
		table = Table(title=f"Module Summary: {self.module_name}")
		table.add_column("Payload ID", style="cyan", no_wrap=True)
		table.add_column("Verdict")
		table.add_column("Confidence", style="magenta")
		table.add_column("Score", justify="right")
		table.add_column("Latency (ms)", justify="right")

		verdict_style = {
			Verdict.EXPLOITABLE: "red",
			Verdict.NOT_EXPLOITABLE: "green",
			Verdict.UNCERTAIN: "yellow",
			Verdict.ERROR: "white",
		}

		for result in self.results:
			verdict = result.verdict.verdict
			style = verdict_style.get(verdict, "white")
			table.add_row(
				result.payload.id,
				f"[{style}]{verdict.value}[/{style}]",
				result.verdict.confidence.value,
				f"{result.verdict.score:.2f}",
				f"{result.latency_ms:.2f}",
			)

		console.print(table)
		console.print(f"[bold]Overall Verdict:[/bold] {self.overall_verdict.verdict.value}")
		console.print(
			f"[bold]Exploitable:[/bold] {self.exploitable_count}/{self.total_payloads}"
		)
		console.print(f"[bold]Duration (s):[/bold] {self.duration_s:.2f}")


@dataclass(slots=True)
class AssessmentReport:
	"""Top-level assessment report across all modules."""

	assessment_id: str
	finding: Finding
	module_reports: list[ModuleReport]
	final_verdict: VerdictResult
	created_at: datetime
	duration_s: float

```

---

## How to Use This File
1. Copy everything above this line
2. Paste it as the FIRST message in your coding agent session
3. Then describe the task you want done
4. The agent now has full context and will not deviate from your schemas

## Session Template
[paste full CONTEXT.md here]

Current task:
[describe what to build]

Do not modify any existing schemas.
Do not create new files outside the established structure.

