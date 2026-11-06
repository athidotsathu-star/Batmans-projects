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


## Windows one-click updater

The Windows installer includes `BatmanBugHunterUpdater.exe` and a Start Menu/Desktop shortcut. Double-click the updater to:
1. Query the latest published GitHub Release.
2. Compare its version with the installed version.
3. Download `BatmanBugHunter-Setup.exe` and `SHA256SUMS.txt`.
4. Verify the installer SHA-256 before executing it.
5. Run the Inno Setup installer quietly as the current Windows user.

The updater requires internet access and a published GitHub Release containing both assets. The repository Actions workflow publishes a new latest release after a successful Windows build on `main`. Feature-branch builds do not publish releases. An existing installation must first be upgraded/reinstalled with a setup package that contains the updater; older installations do not gain the updater automatically. The updater is not code-signed, so Windows SmartScreen may display a reputation warning. SHA-256 verifies download integrity against the release checksum but does not establish publisher identity; use the official repository release page.


## Version 3.0 — Investigation Suite

V3 adds the following workflows while retaining the original web scanner and Crypto Lab:

- **Controlled SQL injection / XSS indicators:** quote-only error behavior and harmless HTML reflection marker checks. This module accepts loopback-only lab URLs (localhost/127.0.0.0/8), query parameters only, up to 8 parameters and bounded response bodies. It does not execute JavaScript, submit forms, exploit SQL injection, authenticate, or modify application state. Indicators require manual validation.
- **Windows Event Log investigation:** on Windows, optionally collects recent Security Event IDs 4624 and 4625 using PowerShell Get-WinEvent. CSV upload remains available on Windows, Kali and Linux. Local collection requires permission to read the Security log.
- **Brute-force correlation:** groups failed logons by source IP, counts distinct targeted accounts and correlates same-IP successful logons in the supplied time window. This is a triage signal, not proof of account compromise.
- **Nmap integration:** optional Nmap TCP connect scanning (-sT) with a maximum of 64 ports, restricted to private, loopback or link-local IP addresses. Install Nmap separately and ensure it is on PATH. The built-in bounded TCP scanner remains available.
- **Risk prioritization:** transparent BBH heuristic scoring with confidence weighting and P1–P4 triage. It is not CVSS and must not be represented as a formal vulnerability score.
- **HTML and PDF reports:** downloadable reports include summary, findings, risk priorities and analyst notes. Reports reflect the latest operation in the running process; they are not durable multi-user case management.
- **Version and update metadata:** /api/version displays the installed version and official release URL; /api/version/check checks the latest public GitHub Release. The Windows setup includes the separate updater application, which verifies SHA-256 checksums before launching an update. Release publishing occurs only from successful builds on main.

### V3 endpoints

- Operations dashboard: http://127.0.0.1:5000/modules
- Version metadata: http://127.0.0.1:5000/api/version
- Check latest release: http://127.0.0.1:5000/api/version/check
- HTML report: http://127.0.0.1:5000/modules/report/html (after preparing a report)
- PDF report: http://127.0.0.1:5000/modules/report/download (after preparing a report)

### Nmap dependency

Install Nmap from its official package for your operating system. Verify nmap --version in the same terminal used to start Batman Bug Hunter. The integration does not install Nmap automatically.

### Safe lab setup

Run an intentionally vulnerable training app on your own machine, bind it to 127.0.0.1, and use a URL containing a query parameter, such as http://127.0.0.1:3000/search?q=test. The V3 lab module rejects public and LAN targets. Use only applications and test data you control.

### Versioning and releases

The CI workflow stamps the build number into the Python package and Windows installer as 3.0.<GitHub Actions run number>. Feature-branch builds produce testable artifacts only. A public release is published only when the required Windows and Linux jobs pass on main. The updater requires an existing installation that already includes the updater binary.
