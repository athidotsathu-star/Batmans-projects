# Batman Bug Hunter

A dual-interface, **passive-first** web security assessment tool. It provides a Python CLI and a Flask browser dashboard using the same scanning engine.

## What it checks

- HTTP response security headers (CSP, HSTS, frame protection, content-type protection, Referrer-Policy, Permissions-Policy)
- Cookie flags (Secure, HttpOnly, SameSite)
- TLS certificate validation through the platform trust store
- Server and technology disclosure headers
- HTML forms that submit credentials over plain HTTP
- Commonly exposed files/directories using small, non-invasive GET requests; response bodies are never saved or printed

## Safety model

Batman Bug Hunter is designed for **systems you own or are explicitly authorized to assess**.

- Every scan requires the operator to confirm authorization in the CLI or dashboard.
- Only HTTP and HTTPS targets are accepted.
- Loopback, private, link-local, multicast, reserved and otherwise non-public IP destinations are blocked by default.
- Redirects are followed manually and every destination is revalidated.
- Requests are sequential, rate-limited, have short timeouts and a strict request cap.
- No exploit payloads, brute force, authentication bypass, destructive requests, crawling, or denial-of-service tests are performed.
- Findings are indicators for manual validation, not proof of exploitability.

For an intentionally vulnerable practice target, use a local lab you control. Private targets require the explicit CLI flag \`--allow-private\` or the dashboard setting. Do not expose a lab service to the public internet.

## Requirements

- Python 3.10+
- pip
- Kali Linux, Linux, macOS or Windows

## Install

\`\`\`bash
cd 02-batman-bug-hunter
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
\`\`\`

## Run the CLI

\`\`\`bash
python -m batman_hunter.cli https://your-authorized-domain.example --i-am-authorized
\`\`\`

For a private lab target that you control:

\`\`\`bash
python -m batman_hunter.cli http://127.0.0.1:8000 --i-am-authorized --allow-private
\`\`\`

Save JSON output:

\`\`\`bash
python -m batman_hunter.cli https://your-authorized-domain.example --i-am-authorized --json report.json
\`\`\`

## Run the browser dashboard

\`\`\`bash
python -m batman_hunter.web
\`\`\`

Open http://127.0.0.1:5000. Keep the dashboard bound to localhost. Do not expose it to an untrusted network.

## Finding severity

- **High**: a meaningful security weakness with potentially serious impact (for example, a credential form submitted over HTTP).
- **Medium**: a missing or weak security control that should be reviewed.
- **Low**: information disclosure or hardening opportunity.
- **Info**: observations that are not necessarily vulnerabilities.

Severity is intentionally conservative. Missing headers alone do not prove a vulnerability.

## Project structure

\`\`\`text
02-batman-bug-hunter/
├── batman_hunter/
│   ├── __init__.py
│   ├── core.py
│   ├── cli.py
│   └── web.py
├── templates/
│   └── index.html
├── static/
│   └── style.css
├── requirements.txt
└── README.md
\`\`\`

## Limitations

This is a learning and portfolio project, not a replacement for a professional DAST platform or a penetration test. It does not test SQL injection or XSS by sending attack strings. It does not authenticate, crawl an application, inspect application logic, or prove that a finding is exploitable. Always validate results manually and document scope, evidence and impact.

## Suggested portfolio evidence

1. Run against a local test application you control.
2. Save the JSON report (remove secrets and personal data before publishing).
3. Write a short assessment summary: scope, date, checks performed, findings, limitations and remediation.
4. Include screenshots of the CLI and dashboard with a deliberately vulnerable lab—not a third-party target.

## License

MIT. See the repository license if one is added.
