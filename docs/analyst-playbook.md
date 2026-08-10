# Account Compromise Response Playbook

## Purpose

This playbook provides a repeatable SOC process for investigating repeated authentication failures followed by a successful logon and suspicious endpoint activity.

## Trigger conditions

- Five or more failed logons for the same user, host, and source within ten minutes
- A successful logon from the same source after those failures
- Supporting process, network, or sensitive-file telemetry

## Triage checklist

1. Confirm the log source, timestamps, host, identity, and source address.
2. Validate whether the source is expected, internal, VPN, or approved administration infrastructure.
3. Review authentication history for the identity and source across other hosts.
4. Check endpoint telemetry for processes started after the successful logon.
5. Review PowerShell script-block logging and parent-child process relationships.
6. Examine outbound network, DNS, proxy, and firewall telemetry.
7. Identify sensitive files accessed, copied, or archived during the session.
8. Record evidence and assign a confidence-based disposition.

## Severity guide

| Evidence | Suggested severity |
| --- | --- |
| Failures only, expected source | Low or informational |
| Failures followed by success, no supporting telemetry | Medium or high |
| Success followed by suspicious execution | High |
| Execution plus external connection or sensitive data activity | Critical |

## Containment decision

Contain immediately when the evidence supports unauthorized access and active post-authentication behavior. Recommended actions include endpoint isolation, account disablement, session revocation, password reset, indicator blocking, and evidence preservation.

## Evidence preservation

- Windows Security, PowerShell, and Sysmon logs
- Endpoint process tree and active network state
- Identity-provider authentication and session records
- DNS, proxy, VPN, and firewall records
- Hashes and metadata for created or accessed files
- Analyst notes with UTC timestamps and source references

## Closure requirements

- Root cause and initial-access path documented
- Affected identities and systems scoped
- Malicious persistence or payloads removed
- Credentials reset and active sessions revoked
- Monitoring performed after recovery
- Detection gaps and hardening actions assigned owners

