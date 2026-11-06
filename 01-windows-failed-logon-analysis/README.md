# Project 01 — Windows Failed Logon Analysis & Brute-Force Triage

## Objective

Build a small SOC-style workflow to investigate repeated Windows logon failures (Security Event ID **4625**), identify source addresses with repeated failures, and document a defensible triage decision.

This is a controlled learning lab. Run it only on a Windows VM and accounts you own or are authorised to test.

## Scenario

A workstation records repeated failed logons. As a junior analyst, you must answer:

1. Which account was targeted?
2. When did failures occur?
3. What source IP or workstation was recorded?
4. Which logon type was used?
5. Is the activity suspicious, explainable, or inconclusive?
6. What additional evidence is needed before escalation?

## Lab requirements

- Windows 10/11 or Windows Server VM
- Local administrator access for audit-policy configuration and Security log access
- PowerShell
- Optional: a second test VM on a private lab network

Do not generate a large volume of failed logons. A few controlled attempts against a test account are enough.

## Step 1 — Confirm logon auditing

Open PowerShell as Administrator and inspect the audit policy:

```powershell
auditpol /get /subcategory:"Logon"
```

If failure auditing is disabled, enable it:

```powershell
auditpol /set /subcategory:"Logon" /failure:enable
```

Re-run the first command to confirm the setting. On a domain-joined machine, domain policy may override local settings.

## Step 2 — Generate safe test events

Use a dedicated local test account in your own VM. At the Windows sign-in screen, enter an incorrect password for that test account two or three times, then stop. Do not repeatedly guess passwords or test accounts you do not own.

You can also inspect existing events without generating new ones:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10 |
  Select-Object TimeCreated, Id, ProviderName, Message
```

If no events appear, check that failure auditing is enabled and that you are looking at the correct VM.

## Step 3 — Inspect Event ID 4625 in Event Viewer

1. Open **Event Viewer**.
2. Go to **Windows Logs → Security**.
3. Select **Filter Current Log…**.
4. Enter event ID **4625**.
5. Open an event and inspect its **General** and **Details → XML View** tabs.

Useful fields include:

| Field | Why it matters |
|---|---|
| TargetUserName | Account name associated with the failed attempt |
| IpAddress | Reported source address; may be blank or local |
| WorkstationName | Reported source workstation |
| LogonType | Context of the attempted logon |
| Status / SubStatus | Failure reason codes |
| TimeCreated | Timeline and burst analysis |

Common logon types include 2 (interactive), 3 (network), 10 (remote interactive/RDP). Interpret them in context; do not assume every network logon is malicious.

## Step 4 — Run the detection script

Download or clone this repository, then run PowerShell as an account permitted to read the Security log.

For live Security log data:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\Find-FailedLogonBursts.ps1 -Hours 24 -Threshold 5
```

From the project folder, the relative path above assumes you are inside `01-windows-failed-logon-analysis`.

To analyse the included synthetic CSV:

```powershell
.\scripts\Find-FailedLogonBursts.ps1 -CsvPath .\data\sample-failed-logons.csv -Threshold 5
```

To analyse an exported EVTX file:

```powershell
.\scripts\Find-FailedLogonBursts.ps1 -EvtxPath .\data\security-events.evtx -Threshold 5
```

The EVTX example requires you to place your own authorised export at that path. No EVTX file is included.

The script writes timestamped CSV outputs under an `output` directory:
- `failed-logons-*.csv` — parsed event records
- `source-summary-*.csv` — counts grouped by source IP

## Step 5 — Triage the result

A source with five or more failures is flagged for review by default. This is a deliberately simple threshold for a lab, not a production-grade detection.

Before escalating, check:
- Whether the account exists and is expected to authenticate from that source
- Whether failures are tightly clustered in time
- Whether multiple accounts are targeted from one source
- Whether one account is targeted from multiple sources
- Whether successful logon Event ID **4624** follows the failures
- Whether the source belongs to a known VPN, jump host, scanner, or management system
- Whether endpoint, firewall, VPN, and identity-provider logs corroborate the activity

Correlate by account, source, and time window. Event ID 4625 alone does not prove brute force or compromise.

## Step 6 — Write an analyst note

Use the template below:

- **Alert:** Repeated Windows logon failures
- **Host:** [hostname]
- **Time window:** [start–end, timezone]
- **Target account(s):** [account]
- **Source(s):** [IP / workstation]
- **Evidence:** [event IDs, counts, logon type, status/substatus]
- **Assessment:** [benign / suspicious / inconclusive]
- **Reasoning:** [evidence-based explanation]
- **Next action:** [monitor / validate with user or owner / escalate]

Do not include real passwords, personal data, or sensitive production logs in a public repository.

## Expected learning outcomes

After completing the lab, you should be able to:
- Locate and filter Windows authentication failure events
- Explain the main fields in Event ID 4625
- Parse event data with PowerShell
- Identify repeated failures by source
- State why a threshold alert needs human validation
- Produce a concise SOC-style triage note

## MITRE ATT&CK mapping

- **T1110 — Brute Force:** repeated authentication attempts may be consistent with this technique. Mapping is a hypothesis to investigate, not a conclusion from one event.

## References

- Microsoft Learn — [Event 4625: An account failed to log on](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- Microsoft Learn — [Audit Logon](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon)
- MITRE ATT&CK — [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
