# Portfolio and Interview Guide

## Thirty-second explanation

I built a lightweight SOC investigation lab that accepts normalized Windows telemetry or EVTX files, correlates authentication and endpoint behavior, and produces analyst-ready findings. The included case detects brute force followed by a successful logon, suspicious PowerShell, an external connection, sensitive-file access, and archive staging. I also wrote Sigma rules, an incident-response playbook, automated tests, and a visual case dashboard.

## Resume entry

**SOC Incident Investigation Lab | Python, Windows Events, Sysmon, Sigma**

- Built a Python detection pipeline that ingests JSONL telemetry and Windows EVTX evidence, then correlates authentication, process, network, and file activity.
- Developed five detections and four Sigma rules mapped to MITRE ATT&CK techniques including T1110, T1078, T1059.001, T1105, T1005, and T1560.001.
- Produced an interactive analyst dashboard, incident timeline, response playbook, and executive incident report for a simulated account compromise.
- Added automated tests and GitHub Actions verification to make detection behavior repeatable and reviewable.

## Questions to expect

### Why correlate failed and successful logons?

Failure volume alone can be noisy. A success from the same source, user, and host after repeated failures is stronger evidence that password guessing may have worked.

### How did you reduce false positives?

The authentication rule groups on host, username, and source address within a fixed time window. The network rule ignores RFC 1918, loopback, and link-local destinations. Production use would add VPN, service-account, scanner, and administrative allowlists.

### Why use synthetic evidence?

Synthetic evidence keeps the repository safe and shareable. The EVTX parser and Windows collector show how the same pipeline can process authorized real telemetry without publishing sensitive logs.

### What would you improve in production?

I would normalize to ECS or OCSF, add asset and identity context, validate Sigma rules for the target SIEM, stream events instead of loading them into memory, and track analyst feedback to improve detection quality.

## Safe sharing rule

Keep this repository private until personal details, commit metadata, and portfolio text are reviewed. Never add real passwords, tokens, client logs, employer telemetry, or confidential incident evidence.
