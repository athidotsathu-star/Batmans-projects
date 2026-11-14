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


## Detailed Kali Linux — Step-by-Step User Guide

This guide walks beginners through downloading, installing, testing and launching Batman Bug Hunter on Kali Linux.

### 1. Requirements

Before starting, make sure you have:

- Kali Linux (updated)
- Python 3
- Git
- An internet connection
- At least 2 GB of available storage
- Basic Linux terminal knowledge

### 2. Update Kali Linux

Open the terminal and run:

```bash
sudo apt update && sudo apt upgrade -y
```

### 3. Install required packages

```bash
sudo apt install -y git python3 python3-pip python3-venv
```

### 4. Download Batman Bug Hunter

Clone the official repository:

```bash
git clone https://github.com/athidotsathu-star/Batmans-projects.git
```

Enter the project directory:

```bash
cd Batmans-projects/02-batman-bug-hunter
```

### 5. Create and activate a Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

You should now see `(.venv)` at the beginning of your terminal prompt.

### 6. Install Python dependencies

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

Install the project requirements:

```bash
pip install -r requirements.txt
```

Wait until the installation finishes.

### 7. Run the automated tests

```bash
python -m unittest discover -s tests -v
```

Review the results. If a test fails, do not assume the application is working correctly. Record the complete error output and resolve it before relying on the affected feature.

### 8. Launch Batman Bug Hunter

```bash
python -m batman_hunter.web
```

Open your browser and visit:

**http://127.0.0.1:5000**

The application should now be available locally.

### 9. Basic reconnaissance target-policy checks

These commands demonstrate the lab-only restrictions for the network reconnaissance module.

**Test 1 — Localhost**

```bash
python -c "from batman_hunter.recon import scan_host; print(scan_host('127.0.0.1', [80, 443]))"
```

**Test 2 — Public IP rejection**

```bash
python -c "from batman_hunter.recon import scan_host; print(scan_host('8.8.8.8', [53]))"
```

A public IP should be rejected by the lab-only reconnaissance policy.

**Test 3 — Link-local IP rejection**

```bash
python -c "from batman_hunter.recon import scan_host; print(scan_host('169.254.1.1', [80]))"
```

A link-local address should also be rejected.

These are policy checks, not a complete security audit. Run tests only against systems you own or are explicitly authorized to assess.

### 10. Stop the application and exit the environment

To stop the application, press:

```text
CTRL + C
```

To leave the Python virtual environment:

```bash
deactivate
```

### 11. Update Batman Bug Hunter

From inside the project directory, return to the repository root:

```bash
cd ..
```

Pull the latest repository changes:

```bash
git pull
```

Return to the project directory:

```bash
cd 02-batman-bug-hunter
```

Activate the environment and update dependencies:

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Run the automated tests again before launching the application.

### Important security notice

Batman Bug Hunter is intended for authorized security testing and controlled lab environments.

- Only test systems you own or have explicit written permission to assess.
- Do not scan public IP addresses or third-party systems without authorization.
- Follow the scope and rules of any bug bounty program.
- Never attempt to access, modify or disrupt another person's data.
- A successful installation does not mean every security feature has been independently verified.

**Project repository:** [Batman Bug Hunter on GitHub](https://github.com/athidotsathu-star/Batmans-projects)

**Project folder:** `02-batman-bug-hunter`

**Local application:** http://127.0.0.1:5000
