"""PDF report generation for OVP assessments."""

from __future__ import annotations

from rich.console import Console

from Core.evidence import AssessmentReport
from Reports.html_report import HTMLReport

console = Console()


class PDFReport:
    """Render an AssessmentReport as a PDF via weasyprint (optional)."""

    def __init__(self, report: AssessmentReport) -> None:
        self.report = report

    def generate(self, output_path: str) -> None:
        try:
            from weasyprint import HTML as WeasyprintHTML
        except ImportError:
            console.print(
                "[yellow]weasyprint not installed — PDF skipped.\n"
                "Run: pip install weasyprint[/yellow]"
            )
            return
        except OSError as exc:
            # weasyprint is installed but its native GTK/Pango libraries
            # (e.g. libgobject-2.0-0) are missing — common on Windows.
            console.print(
                "[yellow]weasyprint native libraries missing — PDF skipped.\n"
                f"  ({exc})\n"
                "  Install the GTK runtime, then retry. See:\n"
                "  https://doc.courtbouillon.org/weasyprint/stable/first_steps.html"
                "[/yellow]"
            )
            return

        try:
            html_content = HTMLReport(self.report).generate()
            WeasyprintHTML(string=html_content).write_pdf(output_path)
        except OSError as exc:
            console.print(
                "[yellow]weasyprint failed to render PDF — skipped.\n"
                f"  ({exc})[/yellow]"
            )
