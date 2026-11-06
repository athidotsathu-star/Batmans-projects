# Batman Bug Hunter

A cross-platform web security assessment tool for **Kali Linux, Linux, macOS and Windows**. It provides a Python CLI and a localhost-only Flask dashboard.

## Capabilities

### Passive checks (default)
- HTTP response security headers (CSP, HSTS, frame protection, content-type protection, Referrer-Policy, Permissions-Policy)
- Cookie flags (Secure, HttpOnly, SameSite)
- TLS certificate validation through the platform trust store
- Server and technology disclosure headers
- HTML forms that may submit credentials over plain HTTP
- A small fixed list of common exposed paths

### Safe-active checks (opt-in)
- HTTP OPTIONS method advertisement
- CORS behavior using a harmless controlled Origin value
- A small fixed set of directory-index checks
- No exploit payloads, authentication attempts, brute force, state-changing requests, destructive tests or denial-of-service behavior

These checks are indicators, not proof of exploitability. They do not constitute a full penetration test and do not currently test SQL injection, XSS, authentication bypass, business logic or authenticated application paths.

## Authorization and safety

Use only systems you own or are explicitly authorized to assess, within written scope.
- Every scan requires an authorization confirmation.
- Only HTTP and HTTPS targets are accepted.
- Private, loopback, link-local, multicast, reserved and otherwise non-public destinations are blocked by default.
- The private-lab option is only for isolated systems you control.
- Redirects are followed manually and each destination is revalidated.
- Requests are sequential, rate-limited, bounded and use short timeouts.
- The dashboard binds to 127.0.0.1; do not expose it to an untrusted network.
- Findings require manual validation.

## Requirements
- Python 3.10+
- pip

## Kali / Linux / macOS install
```bash
cd 02-batman-bug-hunter
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m batman_hunter.web
```
Open http://127.0.0.1:5000.

CLI passive scan:
```bash
python -m batman_hunter.cli http://127.0.0.1:3000 --i-am-authorized --allow-private
```

CLI safe-active scan with JSON report:
```bash
python -m batman_hunter.cli http://127.0.0.1:3000 --i-am-authorized --allow-private --active --json report.json
```

## Windows install

Open PowerShell in this folder:
```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m batman_hunter.web
```
If script activation is blocked, use:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
```
Or skip activation and run the interpreter directly:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m batman_hunter.web
```
Then open http://127.0.0.1:5000. Windows quick-start launchers are included: `start_windows.bat` and `start_windows.ps1`.

## Limitations

This is a learning and portfolio tool, not a replacement for a professional DAST platform or manual penetration test. It does not crawl, authenticate, exploit vulnerabilities, test SQL injection or XSS payloads, bypass authentication, or inspect application business logic. Expand deeper testing only in a controlled lab with documented scope.

## Portfolio evidence

Document the lab target, authorization, date, mode, checks performed, findings, evidence, impact, remediation and limitations. Use an intentionally vulnerable local application such as OWASP Juice Shop running on your own machine.

## License
MIT. See the repository license if one is added.
