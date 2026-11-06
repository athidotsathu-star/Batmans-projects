"""Safe, passive-first checks for explicitly authorized HTTP(S) targets."""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse

import requests

USER_AGENT = "BatmanBugHunter/1.0 (+authorized passive security assessment)"
TIMEOUT = 6
MAX_REQUESTS = 12
MAX_REDIRECTS = 3
DELAY_SECONDS = 0.35
COMMON_PATHS = ("/.env", "/.git/HEAD", "/backup.zip", "/phpinfo.php", "/server-status")


class ScanError(ValueError):
    """Raised when a target is unsafe or cannot be scanned."""


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    evidence: str
    recommendation: str


def _is_public_host(host: str) -> bool:
    try:
        addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except (socket.gaierror, UnicodeError):
        raise ScanError("The hostname could not be resolved.")
    if not addresses:
        raise ScanError("The hostname did not resolve to an IP address.")
    return all(ip.is_global for ip in addresses)


def validate_target(url: str, allow_private: bool = False) -> str:
    """Normalize URL and block non-public destinations unless explicitly allowed."""
    raw = (url or "").strip()
    if not raw:
        raise ScanError("Enter a target URL.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ScanError("Only http:// and https:// targets are supported.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ScanError("Provide a valid hostname; credentials in URLs are not accepted.")
    if parsed.port not in (None, 80, 443) and not allow_private:
        # Non-standard ports are allowed only for explicitly scoped lab targets.
        raise ScanError("Non-standard ports require the private-lab option.")
    host = parsed.hostname.rstrip(".").lower()
    if not allow_private and not _is_public_host(host):
        raise ScanError("Private or non-public IP destinations are blocked. Use the private-lab option only for a system you control.")
    if allow_private:
        try:
            socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
        except socket.gaierror:
            raise ScanError("The hostname could not be resolved.")
    clean = parsed._replace(fragment="", netloc=parsed.netloc.lower())
    return urlunparse(clean)


def _request(url: str, allow_private: bool, method: str = "GET"):
    current = validate_target(url, allow_private)
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.5"}
    for _ in range(MAX_REDIRECTS + 1):
        # Resolve and validate each hop before making a request. Redirects are never automatic.
        current = validate_target(current, allow_private)
        response = requests.request(
            method, current, headers=headers, timeout=TIMEOUT,
            allow_redirects=False, verify=True, stream=True
        )
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                return None, current
            current = urljoin(current, location)
            continue
        return response, current
    raise ScanError("Redirect limit reached.")


def _add(findings, title, severity, category, evidence, recommendation):
    findings.append(Finding(title, severity, category, evidence, recommendation))


def scan_target(url: str, allow_private: bool = False) -> dict:
    """Perform a bounded set of low-impact GET checks; never stores response bodies."""
    target = validate_target(url, allow_private)
    findings: list[Finding] = []
    observations = []
    request_count = 0

    try:
        response, final_url = _request(target, allow_private)
        request_count += 1
    except requests.exceptions.SSLError as exc:
        _add(findings, "TLS certificate validation failed", "High", "TLS", str(exc)[:240],
             "Install a valid certificate for the hostname and maintain a complete trusted certificate chain.")
        return _report(target, findings, observations, request_count)
    except requests.RequestException as exc:
        raise ScanError(f"Connection failed: {exc.__class__.__name__}") from exc

    if response is None:
        raise ScanError("The target redirected too many times.")
    try:
        status = response.status_code
        headers = response.headers
        observations.append(f"HTTP status: {status}")
        observations.append(f"Final URL: {final_url}")
        observations.append(f"Content-Type: {headers.get('Content-Type', 'not supplied')}")
        if final_url.startswith("https://"):
            observations.append("TLS certificate: trusted by the local certificate store")
        else:
            _add(findings, "Target uses plain HTTP", "Medium", "Transport",
                 "The final page URL uses http://.", "Serve the application over HTTPS and redirect HTTP to HTTPS.")

        checks = [
            ("Content-Security-Policy", "Medium", "Define a restrictive Content-Security-Policy to reduce script injection impact."),
            ("Strict-Transport-Security", "Medium", "Enable HSTS on HTTPS after confirming all subdomains support HTTPS."),
            ("X-Content-Type-Options", "Low", "Set X-Content-Type-Options: nosniff."),
            ("Referrer-Policy", "Low", "Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin."),
            ("Permissions-Policy", "Low", "Restrict browser features that the application does not need."),
        ]
        for header, severity, recommendation in checks:
            if not headers.get(header):
                _add(findings, f"Missing {header}", severity, "HTTP headers",
                     f"The response did not include {header}.", recommendation)
        if not headers.get("X-Frame-Options") and "frame-ancestors" not in headers.get("Content-Security-Policy", "").lower():
            _add(findings, "No clear clickjacking protection", "Medium", "HTTP headers",
                 "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
                 "Set a suitable CSP frame-ancestors directive; use X-Frame-Options for legacy browser support.")
        for name in ("Server", "X-Powered-By"):
            if headers.get(name):
                _add(findings, f"Technology disclosure: {name}", "Info", "Information disclosure",
                     f"{name}: {headers.get(name)[:120]}", "Remove or minimize unnecessary server and framework version banners.")

        for cookie in response.cookies:
            rest = getattr(cookie, "_rest", {}) or {}
            flags = []
            if final_url.startswith("https://") and not cookie.secure:
                flags.append("Secure")
            if not rest.get("HttpOnly", rest.get("httponly", False)):
                flags.append("HttpOnly")
            if not rest.get("SameSite", rest.get("samesite")):
                flags.append("SameSite")
            if flags:
                _add(findings, f"Cookie missing {'/'.join(flags)}", "Low", "Cookies",
                     f"Cookie {cookie.name!r} is missing one or more recommended attributes.",
                     "Set Secure on HTTPS cookies, HttpOnly when JavaScript access is unnecessary, and an appropriate SameSite value.")
        content_type = headers.get("Content-Type", "").lower()
        body = ""
        if "text/html" in content_type:
            try:
                body = response.raw.read(256_000, decode_content=True).decode(
                    response.encoding or "utf-8", errors="replace"
                )
            except Exception:
                body = ""
            # Only inspect markup in memory; never include or persist page content in the report.
            import re
            forms = re.findall(r"<form\b[^>]*>.*?</form\s*>", body, flags=re.I | re.S)
            for form in forms:
                if re.search(r'type\s*=\s*["\']?password', form, flags=re.I):
                    action = re.search(r'action\s*=\s*["\']([^"\']*)', form, flags=re.I)
                    action_url = urljoin(final_url, action.group(1)) if action else final_url
                    if urlparse(action_url).scheme != "https":
                        _add(findings, "Password form may submit over HTTP", "High", "Forms",
                             "A password input was found in a form whose resolved action is not HTTPS.",
                             "Submit credentials only over HTTPS; set the form action to an HTTPS endpoint.")
                    break
    finally:
        response.close()

    # Small, fixed list of metadata/exposure paths. Do not read or store their response bodies.
    for path in COMMON_PATHS:
        if request_count >= MAX_REQUESTS:
            break
        time.sleep(DELAY_SECONDS)
        probe_url = urljoin(final_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            probe, checked_url = _request(probe_url, allow_private)
            request_count += 1
            if probe is None:
                continue
            code = probe.status_code
            length = probe.headers.get("Content-Length", "unknown")
            probe.close()
            if code == 200:
                _add(findings, f"Potentially exposed path: {path}", "Medium", "Exposure",
                     f"GET {path} returned HTTP 200 (declared length: {length}). Content was not downloaded or saved.",
                     "Verify whether this resource must be public. Remove it or restrict access if it contains secrets or operational data.")
            elif code in (401, 403):
                observations.append(f"{path}: access restricted (HTTP {code})")
        except (requests.RequestException, ScanError):
            continue

    return _report(target, findings, observations, request_count)


def _report(target, findings, observations, request_count):
    counts = {level: sum(1 for item in findings if item.severity == level)
              for level in ("High", "Medium", "Low", "Info")}
    return {
        "tool": "Batman Bug Hunter",
        "version": "1.0.0",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "requests_made": request_count,
        "summary": counts,
        "findings": [asdict(item) for item in findings],
        "observations": observations,
        "disclaimer": "Automated indicators only. Manually validate findings; this scan is not proof of exploitability."
    }


def report_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)
