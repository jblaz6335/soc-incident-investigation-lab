# SOC Incident Investigation Lab

## Fiverr portfolio title

SOC Incident Investigation and Detection Pipeline

## Short description

I built a lightweight Python SOC investigation pipeline that analyzes synthetic Windows Security, PowerShell, and Sysmon telemetry. It correlates a full account-compromise chain, maps findings to MITRE ATT&CK, and generates JSON, Markdown, and interactive HTML reports. The project also includes Sigma rules, an analyst playbook, a read-only Windows event collector, and automated validation.

## Problem

Analysts need a repeatable way to connect isolated authentication, process, network, and file events into a defensible incident story. Full SIEM deployments are often too heavy for a portable portfolio demonstration.

## Solution

I created a dependency-light Python analyzer that accepts JSONL or authorized EVTX evidence and normalizes it into a common event model. Deterministic detections identify brute force followed by successful authentication, suspicious PowerShell, external connections, sensitive file access, and archive staging. The reporting layer produces analyst-ready findings, an investigation timeline, response actions, and an interactive case dashboard.

## Results

- Five correlated findings across authentication, execution, network, and data activity
- Four portable Sigma detection rules
- MITRE ATT&CK mapping for seven techniques
- Interactive dashboard plus JSON and Markdown reporting
- Automated tests for intended detections and false-positive controls
- Read-only Windows event collection workflow

## Safety note

All names, hosts, addresses, paths, and events are synthetic. No client information, real credentials, malware, or private incident data is included.
