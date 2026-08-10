# Incident Report: Simulated Windows Account Compromise

## Executive summary

On July 15, 2026, monitoring identified six failed remote logons against `j.smith` on `WS-FIN-07`, followed by a successful logon from the same external source. The authenticated session launched encoded PowerShell, retrieved remote content, established an outbound connection, and accessed a confidential client file. The event chain is assessed as a **true-positive account compromise** with probable data staging.

**Severity:** Critical  
**Confidence:** High  
**Affected assets:** `WS-FIN-07`, `j.smith`  
**Business risk:** Unauthorized access to confidential client information

## Detection and analysis

The authentication sequence exceeded the lab threshold of five failures within ten minutes and ended in a successful logon. That alone may reflect password guessing with valid-account use. The subsequent PowerShell and file-access telemetry substantially increases confidence and demonstrates post-authentication activity.

The external addresses are RFC 5737 documentation values used solely for this simulation.

## MITRE ATT&CK mapping

| Technique | Evidence |
| --- | --- |
| T1110 – Brute Force | Six failed logons from one source |
| T1078 – Valid Accounts | Successful logon after failures |
| T1059.001 – PowerShell | Encoded and script-block execution |
| T1105 – Ingress Tool Transfer | `DownloadString` retrieves remote content |
| T1071.001 – Web Protocols | Outbound TCP/443 connection |
| T1005 – Data from Local System | Confidential file access and staging |

## Containment priorities

1. Isolate `WS-FIN-07` from the network while preserving evidence.
2. Disable `j.smith`, reset credentials, and revoke active sessions and tokens.
3. Block the observed network indicators at applicable controls.
4. Preserve memory, PowerShell logs, Sysmon data, and relevant Security logs.
5. Validate whether the confidential file was exfiltrated and notify its owner.

## Eradication and recovery

- Remove unauthorized persistence or payloads discovered during forensic review.
- Patch the endpoint and verify endpoint-protection health.
- Require multifactor authentication for remote access.
- Restore the workstation from a trusted baseline if integrity cannot be established.
- Return the account and asset to service only after validation and monitoring.

## Lessons learned

- Alert on authentication failure-to-success correlation rather than failure volume alone.
- Retain PowerShell script-block logging and Sysmon process/network telemetry.
- Restrict unnecessary remote logon paths and apply MFA.
- Monitor sensitive-file access and archive creation during confirmed incidents.

## Limitations

This portfolio case uses synthetic telemetry and does not claim forensic certainty beyond the supplied evidence. A production investigation would require endpoint acquisition, identity-provider telemetry, firewall/proxy logs, asset context, and legal or privacy coordination where appropriate.

