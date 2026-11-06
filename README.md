# Security Projects Portfolio

Hands-on cybersecurity labs focused on defensive security, Windows security monitoring, network analysis, and incident response.

## Projects

### 01 — Windows Failed Logon Detection
Analyse Windows Security Event ID **4625**, identify repeated failed sign-in attempts, and produce a triage summary with PowerShell.

- [Project guide](01-windows-failed-logon-analysis/README.md)
- [PowerShell detection script](01-windows-failed-logon-analysis/scripts/Find-FailedLogonBursts.ps1)
- [Synthetic sample data](01-windows-failed-logon-analysis/data/sample-failed-logons.csv)
- [Example training incident report](01-windows-failed-logon-analysis/reports/sample-incident-report.md)

### 02 — Batman Bug Hunter

A passive-first web security scanner with a Python CLI and local Flask dashboard. Checks security headers, cookies, TLS validation, technology disclosure, password forms and a small set of commonly exposed paths. Only for explicitly authorized targets.

- [Batman Bug Hunter project guide](02-batman-bug-hunter/README.md)
- [Python scanning engine](02-batman-bug-hunter/batman_hunter/core.py)
- [CLI interface](02-batman-bug-hunter/batman_hunter/cli.py)
- [Browser dashboard](02-batman-bug-hunter/batman_hunter/web.py)

## About this portfolio

These are controlled lab exercises for learning and demonstration. Sample data is synthetic. No production systems, real user accounts, or third-party networks are targeted.

## Skills demonstrated

- Windows Security Event Log investigation
- Authentication failure triage
- PowerShell log parsing and CSV reporting
- Basic detection logic and false-positive awareness
- Incident documentation and evidence handling

**Important:** A detection threshold is an investigation lead, not proof of a successful attack or account compromise.
