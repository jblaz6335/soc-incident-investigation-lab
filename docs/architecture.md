# Architecture and Design

## Pipeline

1. JSONL telemetry or EVTX records are parsed into normalized `SecurityEvent` objects.
2. Deterministic detection functions evaluate authentication, execution, network, and file-access behavior.
3. Findings are enriched with severity, evidence, MITRE ATT&CK techniques, and response actions.
4. The CLI writes machine-readable JSON, analyst-readable Markdown, and an interactive HTML dashboard.
5. A read-only PowerShell collector can export selected local Windows telemetry to JSONL.
6. Unit tests verify parsing, intended detections, reporting, and false-positive behavior.

## Why dependency-free Python

The primary analysis and reporting path uses the standard library so a reviewer can clone and run it without maintaining a SIEM, database, or container stack. EVTX ingestion uses the stable `python-evtx` parser. The included Sigma rules show how the logic can be translated into a production detection platform.

## Production improvements

- Replace the in-memory parser with streaming ingestion.
- Normalize against ECS or OCSF.
- Add allowlists and asset/identity criticality.
- Convert the sequence rule into the target SIEM's correlation language.
- Validate Sigma rules with Sigma CLI in continuous integration.
- Add case-management integration and analyst feedback tracking.
