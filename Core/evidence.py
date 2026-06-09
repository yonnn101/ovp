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
