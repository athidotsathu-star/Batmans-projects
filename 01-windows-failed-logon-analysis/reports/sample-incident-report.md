# Example SOC Triage Note — Synthetic Training Data

> **Training example only.** The records below are synthetic and use documentation-only IP addresses. This is not a real incident and must not be represented as production experience.

## Alert

Repeated Windows authentication failures — Event ID 4625.

## Evidence reviewed

- Five failed logon records for `lab-user` from `192.0.2.25` between 09:00:00 and 09:00:48.
- Two failed logon records for `administrator` from `192.0.2.40` between 10:15:00 and 10:15:18.
- The sample records show Logon Type 3 for the first source and Logon Type 10 for the second.
- Sample status/substatus values indicate a failed authentication and an incorrect password in this illustrative dataset.

## Initial assessment

**192.0.2.25 — REVIEW:** Five failures in under one minute meet the lab threshold. The pattern is consistent with repeated authentication attempts, but the evidence does not establish intent or compromise.

**192.0.2.40 — MONITOR / VALIDATE:** Two failures do not meet the configured threshold. Validate whether the RDP-related logon context is expected.

## Recommended next steps

1. Identify the host that recorded the events and confirm its time zone.
2. Confirm whether the named accounts and source systems are legitimate.
3. Search for Event ID 4624 for the same account/source after the failures.
4. Review account lockout events, VPN/firewall telemetry, and endpoint alerts.
5. Escalate if a successful logon follows suspicious failures or other evidence supports malicious activity.

## Disposition

**Inconclusive — further validation required.** No claim of successful access or compromise can be made from these sample 4625 records alone.
