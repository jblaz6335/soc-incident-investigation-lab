# Architecture and Design

## Pipeline

1. JSONL telemetry is parsed into normalized `SecurityEvent` objects.
2. Deterministic detection functions evaluate authentication, execution, network, and file-access behavior.
3. Findings are enriched with severity, evidence, MITRE ATT&CK techniques, and response actions.
4. The CLI writes machine-readable JSON and analyst-readable Markdown.
5. Unit tests verify the intended incident chain and basic false-positive behavior.

## Why dependency-free Python

The lab intentionally uses the standard library so a reviewer can clone and run it without maintaining a SIEM, database, or container stack. The included Sigma rules show how the same logic can be translated into a production detection platform.

## Production improvements

- Replace the in-memory parser with streaming ingestion.
- Normalize against ECS or OCSF.
- Add allowlists and asset/identity criticality.
- Convert the sequence rule into the target SIEM's correlation language.
- Validate Sigma rules with Sigma CLI in continuous integration.
- Add case-management integration and analyst feedback tracking.

