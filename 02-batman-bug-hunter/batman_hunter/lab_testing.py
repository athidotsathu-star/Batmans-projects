"""Non-destructive SQLi/XSS indicator checks for loopback-only training labs."""
from __future__ import annotations
import ipaddress, socket, html
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests

TIMEOUT = 5
MAX_RESPONSE = 300_000

def _validate_lab_url(url: str) -> str:
    p=urlparse((url or "").strip())
    if p.scheme not in ("http","https") or not p.hostname or p.username or p.password:
        raise ValueError("Enter a valid HTTP(S) lab URL.")
    host=p.hostname.lower().rstrip(".")
    if host != "localhost":
        try:
            addresses={ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(host,p.port or (443 if p.scheme=="https" else 80),type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise ValueError("Lab hostname could not be resolved.") from exc
        if not addresses or not all(a.is_loopback for a in addresses):
            raise ValueError("SQLi/XSS lab checks are restricted to localhost or 127.0.0.0/8. Public and LAN targets are blocked.")
    return url

def _get(url):
    r=requests.get(url,headers={"User-Agent":"BatmanBugHunter-Lab/3.0","Accept":"text/html,*/*"},timeout=TIMEOUT,
                   allow_redirects=False,verify=True,stream=True)
    body=r.raw.read(MAX_RESPONSE,decode_content=True).decode(r.encoding or "utf-8",errors="replace")
    result={"status":r.status_code,"body":body,"length":len(body)}
    r.close()
    return result

def run_lab_checks(url: str) -> dict:
    """Probe existing query parameters using GET only; never submit forms or mutate state."""
    target=_validate_lab_url(url)
    p=urlparse(target); pairs=parse_qsl(p.query,keep_blank_values=True)
    if not pairs:
        raise ValueError("Add at least one query parameter to the lab URL, for example ?q=test.")
    if len(pairs)>8:
        raise ValueError("For safety, test no more than 8 query parameters at once.")
    baseline=_get(target); findings=[]; tested=[]
    for index,(name,value) in enumerate(pairs):
        def make_url(v):
            changed=list(pairs); changed[index]=(name,v)
            return urlunparse(p._replace(query=urlencode(changed)))
        # A quote-only input is a low-impact error-behavior indicator, not an exploit.
        try:
            quote=_get(make_url(value+"'"))
            tested.append({"parameter":name,"test":"single-quote behavior","status":quote["status"]})
            if quote["status"]>=500 and baseline["status"]<500:
                findings.append({"type":"SQLi review","parameter":name,"severity":"Medium",
                    "evidence":"A quote-only input changed the response from non-5xx to HTTP 5xx.",
                    "confidence":"Low","recommendation":"Review server-side parameterized queries and application error handling; manually validate in the lab."})
        except requests.RequestException:
            tested.append({"parameter":name,"test":"single-quote behavior","error":"request failed"})
        marker="BBH_XSS_MARKER_73A91"
        try:
            reflected=_get(make_url("<bbh-probe>"+marker+"</bbh-probe>"))
            raw=marker in reflected["body"]
            encoded=html.escape("<bbh-probe>"+marker+"</bbh-probe>") in reflected["body"]
            tested.append({"parameter":name,"test":"HTML reflection","status":reflected["status"],"raw_reflection":raw,"encoded_reflection":encoded})
            if raw:
                findings.append({"type":"Reflected input review","parameter":name,"severity":"Medium",
                    "evidence":"Unique harmless marker was reflected without HTML encoding in the response.",
                    "confidence":"Medium","recommendation":"Review context-aware output encoding and Content-Security-Policy. This marker does not execute JavaScript and is not proof of XSS."})
        except requests.RequestException:
            tested.append({"parameter":name,"test":"HTML reflection","error":"request failed"})
    return {"target":target,"scope":"loopback-only training lab","requests":1+len(tested),"baseline_status":baseline["status"],
            "tests":tested,"findings":findings,"disclaimer":"Non-destructive indicators only. No JavaScript execution, form submission, authentication attempt, state change or exploit confirmation."}
