# BATCOMPUTER — Batman Bug Hunter X

A tactical black-and-industrial-gold security console for Kali Linux, Linux, macOS and Windows. Version 3.0 adds a local cryptography lab alongside the existing authorized web assessment engine.

A cross-platform web security assessment tool for **Kali Linux, Linux, macOS and Windows**. It provides a Python CLI and a localhost-only Flask dashboard.

## Version 3.0 capabilities

### Crypto Lab (`/crypto`)
- Authenticated AES-256-GCM text encryption and decryption.
- PBKDF2-HMAC-SHA256 passphrase key derivation (600,000 iterations), random 16-byte salt and 12-byte nonce.
- SHA-256 text hashing and secure random password generation.
- Encryption keys are derived in memory; passphrases are not persisted.
- Encrypted payloads use the `BBH1.` format. Keep the passphrase safe: it cannot be recovered.

### Existing web assessment capabilities

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


## Version 2.0 — Security Operations Suite

The v2.0 feature branch adds five workflows while preserving the original web scanner and Crypto Lab:

- **Advanced Web Vulnerability Scanner:** retains the existing passive HTTP/TLS/cookie/security-header checks and bounded safe-active OPTIONS/CORS/directory-index probes. It does not send SQL injection or XSS exploit payloads, brute-force credentials, bypass authentication, or test destructive/state-changing paths. Do not describe it as a full OWASP Top 10 penetration scanner.
- **Network Reconnaissance:** bounded TCP connect checks for up to 32 user-selected ports on one explicitly authorized host. Results marked `closed_or_filtered` are ambiguous.
- **Digital Forensics:** SHA-256/SHA-1/MD5 evidence fingerprints and keyword-based review of uploaded text logs. Uploads are processed in memory, limited to 2 MB, and not persisted by the app.
- **Blue Team Security:** analyzes an exported Windows Security Event CSV for Event ID 4625 failed-logon bursts. It does not directly collect Windows event logs. Repeated failures are leads, not proof of compromise.
- **Professional Reporting:** generates a PDF with summary metrics, evidence observations and analyst notes.

### Run the operations suite

Install dependencies as described above, then start the local dashboard. Open:
- Command Center: http://127.0.0.1:5000/
- Crypto Lab: http://127.0.0.1:5000/crypto
- Operations Suite: http://127.0.0.1:5000/modules

The dashboard binds to loopback only. Reports are generated from the latest operation in the running process; they are not a durable case-management database. Do not upload sensitive production evidence to an unapproved environment.

### Windows failed-logon CSV

Export a narrowly scoped Windows Security log query to CSV, including Event ID, TargetUserName and IpAddress fields where available. Upload that export to the Blue Team module. The tool only analyzes the supplied file.

### Validation

Run the unit tests from this directory:
```bash
python -m unittest discover -s tests -v
```

The network reconnaissance test uses loopback and a single port. Test other targets only with explicit authorization.
