"""Attack-graph JSON export for OVP assessments."""

from __future__ import annotations

import json
import re

from Core.evidence import AssessmentReport
from Core.verdict import Verdict


def _module_label(name: str) -> str:
    """Split a CamelCase module name onto two lines for graph display."""
    spaced = re.sub(r"(?<!^)(?=[A-Z])", " ", name).strip()
    words = spaced.split()
    if len(words) <= 1:
        return name
    mid = (len(words) + 1) // 2
    return " ".join(words[:mid]) + "\n" + " ".join(words[mid:])


def _evidence_summary(report: AssessmentReport) -> str:
    """Derive a short description of what leaked across exploitable results."""
    known = report.finding.asset.known_secrets or []
    leaked: list[str] = []
    for module in report.module_reports:
        for result in module.results:
            if result.verdict.verdict != Verdict.EXPLOITABLE:
                continue
            response = result.raw_response or ""
            for secret in known:
                if secret and secret in response and secret not in leaked:
                    leaked.append(secret)

    if leaked:
        shown = leaked[0]
        if len(leaked) > 1:
            return f"Secret Leaked\n{shown} (+{len(leaked) - 1})"
        return f"Secret Leaked\n{shown}"
    return "Evidence\nExploitable behavior observed"


def build_graph(report: AssessmentReport) -> dict:
    """Build the attack-graph node/edge structure from an AssessmentReport."""
    finding = report.finding
    final = report.final_verdict

    nodes: list[dict] = []
    edges: list[dict] = []

    # Finding node (always present)
    nodes.append(
        {
            "id": "finding",
            "label": f"Finding\n{finding.type}",
            "type": "finding",
        }
    )

    hit_index = 0
    has_hit = False
    for m_index, module in enumerate(report.module_reports):
        module_id = f"module_{m_index}"
        nodes.append(
            {
                "id": module_id,
                "label": _module_label(module.module_name),
                "type": "module",
            }
        )
        edges.append({"from": "finding", "to": module_id})

        for result in module.results:
            if result.verdict.verdict != Verdict.EXPLOITABLE:
                continue
            hit_id = f"hit_{hit_index}"
            nodes.append(
                {
                    "id": hit_id,
                    "label": f"{result.payload.id}\nExploitable",
                    "type": "hit",
                }
            )
            edges.append({"from": module_id, "to": hit_id})
            hit_index += 1
            has_hit = True

    # Evidence node summarizing what leaked
    nodes.append(
        {
            "id": "evidence",
            "label": _evidence_summary(report),
            "type": "evidence",
        }
    )
    if has_hit:
        for i in range(hit_index):
            edges.append({"from": f"hit_{i}", "to": "evidence"})
    else:
        # No exploitable hits — connect modules directly to evidence.
        for m_index in range(len(report.module_reports)):
            edges.append({"from": f"module_{m_index}", "to": "evidence"})
        if not report.module_reports:
            edges.append({"from": "finding", "to": "evidence"})

    # Verdict node
    nodes.append(
        {
            "id": "verdict",
            "label": (
                f"{final.verdict.value}\n"
                f"{final.confidence.value} {final.score:.0%}"
            ),
            "type": "verdict",
        }
    )
    edges.append({"from": "evidence", "to": "verdict"})

    return {
        "assessment_id": report.assessment_id,
        "finding_type": finding.type,
        "verdict": final.verdict.value,
        "nodes": nodes,
        "edges": edges,
    }


def save_graph(report: AssessmentReport, path: str) -> None:
    """Write the attack-graph JSON for a report to disk."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_graph(report), fh, indent=2)
