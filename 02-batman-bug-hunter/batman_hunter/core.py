"""Bounded passive and safe-active checks for explicitly authorized HTTP(S) targets."""
from __future__ import annotations
import ipaddress, json, socket, time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse
import requests

USER_AGENT = "BatmanBugHunter/2.0 (+authorized security assessment)"
TIMEOUT, MAX_REQUESTS, MAX_REDIRECTS, DELAY_SECONDS = 6, 12, 3, 0.35
COMMON_PATHS = ("/.env", "/.git/HEAD", "/backup.zip", "/phpinfo.php", "/server-status")
DIRECTORY_PATHS = ("/uploads/", "/backup/", "/files/")
CORS_TEST_ORIGIN = "https://bbh-origin-check.invalid"

class ScanError(ValueError):
    """Raised when a target is unsafe or cannot be scanned."""

@dataclass
class Finding:
    title: str
    severity: str
    category: str
    evidence: str
    recommendation: str

class _Cookie:
    def __init__(self, name, morsel):
        self.name = name
        self.secure = bool(morsel["secure"])
        self._rest = {"HttpOnly": bool(morsel["httponly"]), "SameSite": morsel["samesite"] or None}

class _PinnedResponse:
    def __init__(self, status, headers, body):
        from requests.structures import CaseInsensitiveDict
        from http.cookies import SimpleCookie
        from io import BytesIO
        self.status_code = status
        self.headers = CaseInsensitiveDict(dict(headers))
        self.raw = BytesIO(body)
        parsed = SimpleCookie()
        for value in (headers.getlist("Set-Cookie") if hasattr(headers, "getlist") else []):
            try: parsed.load(value)
            except Exception: pass
        self.cookies = [_Cookie(name, morsel) for name, morsel in parsed.items()]
        self.is_redirect = status in (301, 302, 303, 307, 308)
        self.is_permanent_redirect = status in (301, 308)
    def close(self):
        self.raw.close()

def validate_target(url: str, allow_private: bool = False) -> str:
    from .target_policy import TargetPolicyError, resolve_target
    raw = (url or "").strip()
    if not raw:
        raise ScanError("Enter a target URL.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            raise ScanError("Only http:// and https:// targets are supported.")
        if not parsed.hostname or parsed.username or parsed.password:
            raise ScanError("Provide a valid hostname; credentials in URLs are not accepted.")
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ScanError("The target port is invalid.")
        if port not in (None, 80, 443) and not allow_private:
            raise ScanError("Non-standard ports require private-lab mode.")
        host = parsed.hostname.rstrip(".").lower()
        resolve_target(host, allow_private=allow_private)
    except TargetPolicyError as exc:
        raise ScanError(str(exc)) from exc
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, ScanError): raise
        raise ScanError("The target URL or port is invalid.") from exc
    return urlunparse(parsed._replace(fragment="", netloc=parsed.netloc.lower()))

def _request(url: str, allow_private: bool, method: str = "GET", extra_headers: dict | None = None, _redirects: int = 0, allowed_hosts: set[str] | None = None):
    """Make a single HTTP request pinned to an address validated immediately before connect.

    No proxy environment variables are honored. HTTPS keeps the original hostname
    for SNI and certificate verification while the TCP socket connects to the
    validated numeric IP. Redirects are returned to the caller for revalidation.
    """
    import ssl
    import urllib3
    from .target_policy import TargetPolicyError, resolve_target

    current = validate_target(url, allow_private)
    parsed = urlparse(current)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = resolve_target(host, allow_private=allow_private)
    except TargetPolicyError as exc:
        raise ScanError(str(exc)) from exc

    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.5"}
    if extra_headers:
        headers.update(extra_headers)
    host_header = f"[{host}]" if ":" in host else host
    if port not in (80, 443):
        host_header += f":{port}"
    headers["Host"] = host_header
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    last_error = None
    for address in addresses:
        pool = None
        try:
            if parsed.scheme == "https":
                pool = urllib3.HTTPSConnectionPool(
                    address, port=port, timeout=TIMEOUT, maxsize=1, block=True,
                    cert_reqs=ssl.CERT_REQUIRED, ca_certs=requests.certs.where(),
                    assert_hostname=host, server_hostname=host,
                )
            else:
                pool = urllib3.HTTPConnectionPool(address, port=port, timeout=TIMEOUT, maxsize=1, block=True)
            raw = pool.urlopen(method.upper(), path, headers=headers, redirect=False,
                               retries=False, preload_content=False)
            body = raw.read(256000)
            response = _PinnedResponse(raw.status, raw.headers, body)
            raw.close()
            if response.is_redirect:
                location = response.headers.get("Location")
                if location:
                    response.close()
                    if _redirects >= MAX_REDIRECTS:
                        raise ScanError("Redirect limit reached.")
                    next_url = urljoin(current, location)
                    next_host = (urlparse(next_url).hostname or "").lower().rstrip(".")
                    if allowed_hosts is not None and next_host not in allowed_hosts:
                        raise ScanError("Redirect leaves the verified target scope and was blocked.")
                    next_method = "GET" if response.status_code in (301, 302, 303) else method
                    return _request(next_url, allow_private, method=next_method,
                                    extra_headers=extra_headers, _redirects=_redirects + 1, allowed_hosts=allowed_hosts)
            return response, current
        except (urllib3.exceptions.HTTPError, OSError, ssl.SSLError) as exc:
            last_error = exc
        finally:
            if pool is not None:
                pool.close()
    raise ScanError(f"Connection failed: {type(last_error).__name__ if last_error else 'No permitted address'}")

def _add(findings, title, severity, category, evidence, recommendation):
    findings.append(Finding(title, severity, category, evidence, recommendation))

def _safe_active_checks(base_url: str, allow_private: bool, findings: list, observations: list, request_count: int) -> int:
    """Use only non-state-changing OPTIONS and GET requests with bounded paths."""
    if request_count < MAX_REQUESTS:
        time.sleep(DELAY_SECONDS)
        try:
            response, _ = _request(base_url, allow_private, method="OPTIONS")
            request_count += 1
            if response is not None:
                allow = response.headers.get("Allow", "")
                response.close()
                if allow:
                    observations.append(f"HTTP OPTIONS Allow: {allow[:180]}")
                    if "TRACE" in {part.strip().upper() for part in allow.split(",")}:
                        _add(findings, "HTTP TRACE is advertised", "Low", "HTTP methods",
                             f"OPTIONS response advertised: {allow[:180]}",
                             "Disable TRACE unless there is a documented operational requirement; verify server configuration.")
        except (requests.RequestException, ScanError):
            pass
    if request_count < MAX_REQUESTS:
        time.sleep(DELAY_SECONDS)
        try:
            response, _ = _request(base_url, allow_private, method="GET",
                                   extra_headers={"Origin": CORS_TEST_ORIGIN})
            request_count += 1
            if response is not None:
                allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
                allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower()
                response.close()
                if allow_origin == CORS_TEST_ORIGIN and allow_credentials == "true":
                    _add(findings, "CORS reflects an arbitrary origin with credentials", "High", "CORS",
                         "The controlled test Origin was reflected and Access-Control-Allow-Credentials was true.",
                         "Use an explicit allowlist of trusted origins. Never reflect arbitrary Origin values when credentials are allowed.")
                elif allow_origin == CORS_TEST_ORIGIN:
                    _add(findings, "CORS reflects the supplied Origin", "Medium", "CORS",
                         "The response reflected a controlled test origin; credentialed access was not confirmed.",
                         "Review the CORS allowlist and return only explicitly trusted origins.")
                elif allow_origin == "*":
                    observations.append("CORS: wildcard Access-Control-Allow-Origin observed; credentialed access is not implied.")
        except (requests.RequestException, ScanError):
            pass
    for path in DIRECTORY_PATHS:
        if request_count >= MAX_REQUESTS:
            break
        time.sleep(DELAY_SECONDS)
        try:
            response, _ = _request(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")), allow_private)
            request_count += 1
            if response is None:
                continue
            code = response.status_code
            content_type = response.headers.get("Content-Type", "").lower()
            sample = ""
            if code == 200 and ("text/html" in content_type or not content_type):
                try:
                    sample = response.raw.read(16000, decode_content=True).decode("utf-8", errors="replace")
                except Exception:
                    sample = ""
            response.close()
            if code == 200 and ("<title>index of" in sample.lower() or "directory listing for" in sample.lower()):
                _add(findings, f"Directory listing appears enabled: {path}", "Medium", "Directory listing",
                     f"GET {path} returned an HTML directory-index signature; response sample was not saved.",
                     "Disable automatic directory indexing and ensure uploaded or backup files are not publicly browsable.")
        except (requests.RequestException, ScanError):
            continue
    return request_count

def scan_target(url: str, allow_private: bool = False, active: bool = False, allowed_hosts: set[str] | None = None) -> dict:
    target = validate_target(url, allow_private)
    findings, observations, request_count = [], [], 0
    try:
        response, final_url = _request(target, allow_private, allowed_hosts=allowed_hosts)
        request_count += 1
    except requests.exceptions.SSLError as exc:
        _add(findings, "TLS certificate validation failed", "High", "TLS", str(exc)[:240],
             "Install a valid certificate and maintain a complete trusted certificate chain.")
        return _report(target, findings, observations, request_count, active)
    except requests.RequestException as exc:
        raise ScanError(f"Connection failed: {exc.__class__.__name__}") from exc
    if response is None:
        raise ScanError("The target redirected too many times.")
    try:
        headers = response.headers
        observations.extend([f"HTTP status: {response.status_code}", f"Final URL: {final_url}",
                             f"Content-Type: {headers.get('Content-Type', 'not supplied')}"])
        if final_url.startswith("https://"):
            observations.append("TLS certificate: trusted by the local certificate store")
        else:
            _add(findings, "Target uses plain HTTP", "Medium", "Transport", "The final page URL uses http://.",
                 "Serve the application over HTTPS and redirect HTTP to HTTPS.")
        checks = [
            ("Content-Security-Policy", "Medium", "Define a restrictive Content-Security-Policy to reduce script injection impact."),
            ("Strict-Transport-Security", "Medium", "Enable HSTS on HTTPS after confirming all subdomains support HTTPS."),
            ("X-Content-Type-Options", "Low", "Set X-Content-Type-Options: nosniff."),
            ("Referrer-Policy", "Low", "Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin."),
            ("Permissions-Policy", "Low", "Restrict browser features that the application does not need."),
        ]
        for header, severity, recommendation in checks:
            if not headers.get(header):
                _add(findings, f"Missing {header}", severity, "HTTP headers", f"The response did not include {header}.", recommendation)
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
        if "text/html" in content_type:
            try:
                body = response.raw.read(256000, decode_content=True).decode(response.encoding or "utf-8", errors="replace")
            except Exception:
                body = ""
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
    for path in COMMON_PATHS:
        if request_count >= MAX_REQUESTS:
            break
        time.sleep(DELAY_SECONDS)
        try:
            probe, _ = _request(urljoin(final_url.rstrip("/") + "/", path.lstrip("/")), allow_private, allowed_hosts=allowed_hosts)
            request_count += 1
            if probe is None:
                continue
            code, length = probe.status_code, probe.headers.get("Content-Length", "unknown")
            probe.close()
            if code == 200:
                _add(findings, f"Potentially exposed path: {path}", "Medium", "Exposure",
                     f"GET {path} returned HTTP 200 (declared length: {length}). Content was not downloaded or saved.",
                     "Verify whether this resource must be public. Remove it or restrict access if it contains secrets or operational data.")
            elif code in (401, 403):
                observations.append(f"{path}: access restricted (HTTP {code})")
        except (requests.RequestException, ScanError):
            continue
    if active:
        request_count = _safe_active_checks(final_url, allow_private, findings, observations, request_count)
    return _report(target, findings, observations, request_count, active)

def _report(target, findings, observations, request_count, active=False):
    counts = {level: sum(1 for item in findings if item.severity == level) for level in ("High", "Medium", "Low", "Info")}
    return {"tool": "Batman Bug Hunter", "version": "2.0.0",
            "mode": "passive + safe-active" if active else "passive",
            "scanned_at": datetime.now(timezone.utc).isoformat(), "target": target,
            "requests_made": request_count, "summary": counts,
            "findings": [asdict(item) for item in findings], "observations": observations,
            "disclaimer": "Automated indicators only. Manually validate findings; this scan is not proof of exploitability."}

def report_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)
