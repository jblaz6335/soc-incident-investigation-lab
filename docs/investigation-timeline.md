# Investigation Timeline

**Case:** SOC-LAB-2026-001  
**Analyst:** Joshua Hernandez  
**Classification:** True Positive  
**Scope:** `WS-FIN-07`, account `j.smith`

All timestamps are UTC. This timeline is based on synthetic Windows Security, PowerShell, and Sysmon telemetry.

| Time | Evidence | Analyst interpretation |
| --- | --- | --- |
| 09:00:11–09:03:18 | Six Event 4625 failures from `203.0.113.77` | Repeated remote authentication attempts indicate password guessing. |
| 09:04:02 | Event 4624 success from the same address | The failure-to-success sequence raises the incident to a likely account compromise. |
| 09:04:51 | Sysmon Event 1 starts encoded PowerShell | Execution is inconsistent with the user's expected finance workflow. |
| 09:05:07 | PowerShell Event 4104 contains `DownloadString` and `IEX` | The command attempts to retrieve and execute remote content. |
| 09:05:19 | Sysmon Event 3 connects to `198.51.100.25:443` | Network behavior corroborates the PowerShell evidence. |
| 09:06:42 | Event 4663 reads `client_list_Q3.xlsx` | The compromised identity accesses sensitive business data. |
| 09:07:10 | Sysmon Event 11 creates `client_list_Q3.zip` in Temp | File creation is consistent with staging for possible exfiltration. |

## Key investigative pivots

1. Search all authentication telemetry for `203.0.113.77` and `j.smith`.
2. Identify the parent of PowerShell process ID 4820 and any child processes.
3. Hunt for `198.51.100.25`, `update.ps1`, and matching command-line fragments.
4. Determine whether `client_list_Q3.zip` was transferred off the endpoint.
5. Scope other hosts for the same indicators and account activity.

