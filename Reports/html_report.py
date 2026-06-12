"""HTML report generation for OVP assessments."""

from __future__ import annotations

import markdown

from Core.evidence import AssessmentReport
from Reports.markdown_report import MarkdownReport

_CSS = """
:root {
    color-scheme: light;
}
body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    color: #0f172a;
    background: #f1f5f9;
    margin: 0;
    padding: 0 0 3rem 0;
    line-height: 1.6;
}
.banner {
    background: #1e293b;
    color: #f8fafc;
    padding: 1.5rem 2rem;
    font-size: 1.25rem;
    font-weight: 600;
    text-align: center;
}
.container {
    max-width: 900px;
    margin: 2rem auto;
    padding: 0 1.5rem;
}
h1, h2, h3, h4 {
    color: #1e293b;
}
h2 {
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 0.3rem;
    margin-top: 2rem;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin: 1rem 0;
}
th, td {
    border: 1px solid #cbd5e1;
    padding: 0.5rem 0.75rem;
    text-align: left;
}
th {
    background: #1e293b;
    color: #f8fafc;
}
tr:nth-child(even) td {
    background: #f1f5f9;
}
tr:nth-child(odd) td {
    background: #ffffff;
}
blockquote {
    background: #f1f5f9;
    border-left: 4px solid #94a3b8;
    color: #334155;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    font-size: 0.85rem;
    margin: 0.5rem 0;
    padding: 0.75rem 1rem;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
}
.verdict-exploitable { color: #dc2626; font-weight: 700; }
.verdict-not_exploitable { color: #16a34a; font-weight: 700; }
.verdict-uncertain { color: #d97706; font-weight: 700; }
"""

_VERDICT_CLASS = {
    "EXPLOITABLE": "verdict-exploitable",
    "NOT_EXPLOITABLE": "verdict-not_exploitable",
    "UNCERTAIN": "verdict-uncertain",
    "ERROR": "verdict-uncertain",
}


class HTMLReport:
    """Render an AssessmentReport as a styled, standalone HTML document."""

    def __init__(self, report: AssessmentReport) -> None:
        self.report = report

    def generate(self) -> str:
        md_text = MarkdownReport(self.report).generate()
        body_html = markdown.markdown(
            md_text, extensions=["tables", "fenced_code"]
        )

        # Colorize the final verdict line.
        verdict_value = self.report.final_verdict.verdict.value
        css_class = _VERDICT_CLASS.get(verdict_value, "verdict-uncertain")
        body_html = body_html.replace(
            f"<strong>{verdict_value}</strong>",
            f'<strong class="{css_class}">{verdict_value}</strong>',
            1,
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OVP Assessment Report — {self.report.assessment_id}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="banner">OVP — AI Exploitability Validation Platform</div>
<div class="container">
{body_html}
</div>
</body>
</html>
"""

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.generate())
