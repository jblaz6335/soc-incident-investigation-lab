from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from .detections import run_detections
from .models import Finding, SecurityEvent


def load_jsonl_events(path: str | Path) -> list[SecurityEvent]:
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


def load_events(path: str | Path) -> list[SecurityEvent]:
    source = Path(path)
    suffix = source.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        return load_jsonl_events(source)
    if suffix == ".evtx":
        from .evtx_loader import load_evtx_events

        return load_evtx_events(source)
    raise ValueError(f"Unsupported input format: {suffix or 'no extension'}")


def build_result(events: list[SecurityEvent], findings: list[Finding]) -> dict:
    severity_counts = Counter(finding.severity for finding in findings)
    severity_weight = {"critical": 40, "high": 20, "medium": 10, "low": 5}
    risk_score = min(100, sum(severity_weight[item.severity] for item in findings))
    mitre_attack = sorted({technique for finding in findings for technique in finding.mitre_attack})
    rule_ids = {finding.rule_id for finding in findings}
    chain_complete = "SOC-AUTH-001" in rule_ids and bool(
        rule_ids & {"SOC-EXEC-001", "SOC-NET-001", "SOC-DATA-001", "SOC-DATA-002"}
    )
    classification = "true_positive" if chain_complete else ("requires_review" if findings else "no_findings")
    first_event = events[0].timestamp if events else None
    last_event = events[-1].timestamp if events else None
    duration_seconds = int((last_event - first_event).total_seconds()) if first_event and last_event else 0
    return {
        "case_id": "SOC-LAB-2026-001",
        "classification": classification,
        "confidence": "high" if chain_complete else ("medium" if findings else "none"),
        "attack_chain_complete": chain_complete,
        "event_count": len(events),
        "finding_count": len(findings),
        "risk_score": risk_score,
        "severity_counts": dict(sorted(severity_counts.items())),
        "hosts": sorted({event.host for event in events if event.host}),
        "users": sorted({event.username for event in events if event.username}),
        "incident_window": {
            "first_event": _format_timestamp(first_event),
            "last_event": _format_timestamp(last_event),
            "duration_seconds": duration_seconds,
        },
        "mitre_attack": mitre_attack,
        "event_timeline": [
            {
                "timestamp": _format_timestamp(event.timestamp),
                "event_id": event.event_id,
                "host": event.host,
                "channel": event.channel,
                "username": event.username,
                "summary": _event_summary(event),
            }
            for event in events
        ],
        "findings": [finding.to_dict() for finding in findings],
    }


def _format_timestamp(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _event_summary(event: SecurityEvent) -> str:
    if event.event_id in {"4624", "4625"}:
        return f"Authentication {event.outcome} from {event.source_ip}"
    if event.event_id in {"1", "4104"}:
        return f"Process or script activity: {event.image or 'PowerShell'}"
    if event.event_id == "3":
        return f"Network connection to {event.destination_ip}:{event.destination_port}"
    if event.event_id in {"11", "4663"}:
        return f"File activity: {event.target_path}"
    return event.action or "Security telemetry event"


def render_markdown(result: dict) -> str:
    lines = [
        "# Automated SOC Findings",
        "",
        f"- **Case:** `{result['case_id']}`",
        f"- **Classification:** `{result['classification']}`",
        f"- **Events analyzed:** {result['event_count']}",
        f"- **Findings:** {result['finding_count']}",
        f"- **Risk score:** {result['risk_score']}/100",
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
