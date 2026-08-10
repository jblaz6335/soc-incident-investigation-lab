# SOC Incident Investigation Lab

A lightweight, reproducible Security Operations Center (SOC) portfolio project that detects and investigates a simulated Windows account compromise. The lab correlates authentication failures, a successful logon, suspicious PowerShell execution, an outbound network connection, and access to a sensitive file.

The project is designed to demonstrate practical alert triage and incident-response skills without running malware, attacking an external system, or requiring a resource-heavy SIEM.

## Investigation scenario

An external source performs repeated failed logons against a workstation account. The same source then authenticates successfully. Minutes later, PowerShell runs an encoded download command, connects to an external documentation-range address, and accesses a file marked confidential.

```mermaid
flowchart LR
    A["Repeated Event 4625 failures"] --> B["Event 4624 successful logon"]
    B --> C["Sysmon Event 1 / PowerShell 4104"]
    C --> D["Sysmon Event 3 outbound connection"]
    D --> E["Event 4663 sensitive file access"]
    E --> F["Containment and remediation"]
```

## What this demonstrates

- Windows Security Event and Sysmon analysis
- Multi-event correlation and alert triage
- Brute-force and suspicious PowerShell detection
- Network and sensitive-file-access investigation
- MITRE ATT&CK mapping
- Sigma detection engineering
- Incident timeline and report writing
- Automated testing and repeatable evidence generation

## Repository map

| Path | Purpose |
| --- | --- |
| `src/soc_lab/` | Dependency-free Python analyzer and CLI |
| `data/sample_events.jsonl` | Clearly labeled synthetic Windows/Sysmon telemetry |
| `detections/sigma/` | Portable Sigma detection rules |
| `docs/investigation-timeline.md` | Analyst timeline with evidence |
| `docs/incident-report.md` | Executive and technical incident report |
| `docs/architecture.md` | Detection pipeline and design decisions |
| `tests/` | Automated detection and false-positive tests |

## Quick start

Requires Python 3.11 or newer. The analyzer uses only the Python standard library.

```powershell
python -m pip install -e .
python -m soc_lab data/sample_events.jsonl --json output/findings.json --markdown output/findings.md
python -m unittest discover -s tests -v
```

Expected result: four correlated findings, with the account-compromise chain rated **critical**.

## Detection coverage

| Detection | Primary evidence | MITRE ATT&CK |
| --- | --- | --- |
| Brute force followed by success | 4625 → 4624 | T1110, T1078 |
| Suspicious PowerShell | 4104 / Sysmon 1 | T1059.001, T1105 |
| Suspicious outbound connection | Sysmon 3 | T1071.001 |
| Sensitive file access | 4663 | T1005 |

## Analyst conclusion

The evidence supports a **true positive** account compromise with post-authentication execution and probable collection activity. Recommended immediate actions are to isolate the workstation, disable and reset the affected account, revoke active sessions, block the observed infrastructure, preserve volatile evidence, and scope the environment for related indicators.

See the full [incident report](docs/incident-report.md) and [investigation timeline](docs/investigation-timeline.md).

## Data and safety statement

All telemetry is synthetic. Names, hosts, hashes, addresses, and paths were created for this lab. The IP addresses use RFC 5737 documentation ranges and do not represent real infrastructure. No malware is included or executed.

