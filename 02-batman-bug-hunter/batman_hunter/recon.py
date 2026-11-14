"""Conservative TCP reconnaissance restricted to explicitly authorized lab ranges."""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from .target_policy import TargetPolicyError, resolve_target

COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443)
SERVICE = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",135:"MS-RPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",8080:"HTTP-alt",8443:"HTTPS-alt"}

def scan_host(host: str, ports=None, timeout: float = 0.5) -> dict:
    """Scan at most 32 TCP ports on a private/loopback/ULA lab target.

    Hostnames are resolved once and every returned address must be in an approved
    lab range. Connections use the validated numeric address, preventing a second
    DNS lookup from redirecting probes to a different destination.
    """
    raw_host = (host or "").strip()
    if not raw_host or any(ch in raw_host for ch in "/@?#"):
        raise ValueError("Enter a hostname or IP address only, not a URL.")
    try:
        addresses = resolve_target(raw_host, allow_private=True)
    except TargetPolicyError as exc:
        raise ValueError(str(exc)) from exc

    selected = tuple(COMMON_PORTS if ports is None else ports)
    if not selected or len(selected) > 32 or any(type(port) is not int or not 1 <= port <= 65535 for port in selected):
        raise ValueError("Choose between 1 and 32 valid TCP ports.")
    selected = tuple(dict.fromkeys(selected))
    try:
        bounded_timeout = max(0.2, min(float(timeout), 1.5))
    except (TypeError, ValueError) as exc:
        raise ValueError("Timeout must be a number between 0.2 and 1.5 seconds.") from exc

    results = []
    for address in addresses:
        def probe(port):
            try:
                with socket.create_connection((address, port), timeout=bounded_timeout):
                    return {"address": address, "port": port, "state": "open", "service": SERVICE.get(port, "unknown")}
            except (OSError, TimeoutError):
                return {"address": address, "port": port, "state": "closed_or_filtered", "service": SERVICE.get(port, "unknown")}
        with ThreadPoolExecutor(max_workers=8) as pool:
            results.extend(pool.map(probe, selected))

    open_ports = [item for item in results if item["state"] == "open"]
    return {
        "target": raw_host,
        "resolved_addresses": list(addresses),
        "method": "TCP connect (validated IP pinning)",
        "ports": results,
        "open_ports": open_ports,
        "disclaimer": "Restricted to RFC1918, loopback and IPv6 ULA lab ranges. A closed_or_filtered result cannot distinguish a closed port from firewall filtering.",
    }
