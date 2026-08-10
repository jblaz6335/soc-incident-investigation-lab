# Lab Guide

## Run the included case

```powershell
python -m pip install -e ".[dev]"
.\scripts\verify.ps1
start output\dashboard.html
```

The verification script runs the complete automated test suite and creates JSON, Markdown, and HTML reports from the included synthetic evidence.

## Analyze exported Windows telemetry

Open PowerShell as an administrator when Security log access requires it, then run:

```powershell
.\collectors\Export-SocTelemetry.ps1 -Hours 24 -OutputPath .\output\windows_events.jsonl
python -m soc_lab .\output\windows_events.jsonl --html .\output\windows_dashboard.html
```

The collector reads selected local logs. It does not enable logging, change audit policy, alter services, or modify security controls.

## Analyze a real EVTX file

```powershell
python -m pip install -e ".[evtx]"
python -m soc_lab C:\Evidence\Security.evtx --json output\security_findings.json --html output\security_dashboard.html
```

Only use event logs that you own or are authorized to analyze. Keep real client, employer, and personal telemetry out of the portfolio repository.

## Review sequence

1. Open the HTML dashboard and inspect the risk score and attack chain.
2. Filter critical and high findings.
3. Expand each finding to review evidence and response guidance.
4. Walk through the event timeline in UTC order.
5. Compare the automated output with the written incident report.
6. Explain false-positive possibilities and production improvements.
