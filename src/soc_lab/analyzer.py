from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .detections import run_detections
from .models import Finding, SecurityEvent


def load_events(path: str | Path) -> list[SecurityEvent]:
    source = Path(path)
    events: list[SecurityEvent] = []
    with source.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                events.append(SecurityEvent.from_mapping(json.loads(line)))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
                raise ValueError(f"Invalid event at line {line_number}: {error}") from error
    return sorted(events, key=lambda event: event.timestamp)


def build_result(events: list[SecurityEvent], findings: list[Finding]) -> dict:
    severity_counts = Counter(finding.severity for finding in findings)
    return {
        "case_id": "SOC-LAB-2026-001",
        "classification": "true_positive" if findings else "no_findings",
        "event_count": len(events),
        "finding_count": len(findings),
        "severity_counts": dict(sorted(severity_counts.items())),
        "hosts": sorted({event.host for event in events if event.host}),
        "users": sorted({event.username for event in events if event.username}),
        "findings": [finding.to_dict() for finding in findings],
    }


def render_markdown(result: dict) -> str:
    lines = [
        "# Automated SOC Findings",
        "",
        f"- **Case:** `{result['case_id']}`",
        f"- **Classification:** `{result['classification']}`",
        f"- **Events analyzed:** {result['event_count']}",
        f"- **Findings:** {result['finding_count']}",
        "",
    ]
    for finding in result["findings"]:
        lines.extend(
            [
                f"## {finding['title']}",
                "",
                f"**Severity:** {finding['severity'].upper()}  ",
                f"**Rule:** `{finding['rule_id']}`  ",
                f"**Window:** {finding['first_seen']} to {finding['last_seen']}",
                "",
                finding["description"],
                "",
                "### Evidence",
                "",
                *[f"- {item}" for item in finding["evidence"]],
                "",
                "### MITRE ATT&CK",
                "",
                *[f"- {item}" for item in finding["mitre_attack"]],
                "",
                "### Recommended actions",
                "",
                *[f"- {item}" for item in finding["recommended_actions"]],
                "",
            ]
        )
    return "\n".join(lines)


def analyze(path: str | Path) -> dict:
    events = load_events(path)
    return build_result(events, run_detections(events))

