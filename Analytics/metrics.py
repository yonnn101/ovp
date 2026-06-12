"""Rich terminal rendering for OVP cumulative analytics."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from Analytics.store import AnalyticsStore


class MetricsPrinter:
    """Render the cumulative analytics summary as a rich table."""

    def __init__(self, store: AnalyticsStore) -> None:
        self.store = store
        self.console = Console()

    def _rate_markup(self, rate: float) -> str:
        """Color an exploit rate: red if > 50%, green if < 20%."""
        text = f"{rate:.1f}%"
        if rate > 50:
            return f"[red]{text}[/red]"
        if rate < 20:
            return f"[green]{text}[/green]"
        return f"[yellow]{text}[/yellow]"

    def print_summary(self) -> None:
        summary = self.store.get_summary()

        table = Table(title="OVP Analytics — Cumulative Dataset")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value")

        table.add_row("Total Assessments", str(summary["total_assessments"]))
        table.add_row("Total Payloads", str(summary["total_payloads"]))
        table.add_row("Exploitable Count", str(summary["exploitable_count"]))
        table.add_row("Exploit Rate", self._rate_markup(summary["exploit_rate"]))
        table.add_row("Most Effective Payload", summary["most_effective_payload"])
        table.add_row("Most Vulnerable Target", summary["most_vulnerable_target"])

        for module_name, stats in summary["by_module"].items():
            table.add_row(
                f"  {module_name}",
                f"{stats['exploitable']}/{stats['total']} "
                f"({self._rate_markup(stats['rate'])})",
            )

        self.console.print(table)
