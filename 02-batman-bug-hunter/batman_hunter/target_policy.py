"""Shared target policy: public web scans or private isolated lab ranges only."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

LAB_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "::1/128", "fc00::/7",
))

class TargetPolicyError(ValueError):
    """Target is outside the permitted address policy."""

def is_lab_ip(address: str | ipaddress._BaseAddress) -> bool:
    ip = ipaddress.ip_address(address) if isinstance(address, str) else address
    return any(ip.version == net.version and ip in net for net in LAB_NETWORKS)

def resolve_target(host: str, *, allow_private: bool = False) -> tuple[str, ...]:
    """Resolve once, validate every answer, and return numeric IPs for pinned use."""
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
        addresses = {literal}
    except ValueError:
        try:
            records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError, OSError) as exc:
            raise TargetPolicyError("The hostname could not be resolved.") from exc
        addresses = {ipaddress.ip_address(record[4][0].split("%", 1)[0]) for record in records}

    if not addresses:
        raise TargetPolicyError("The hostname did not resolve to an IP address.")

    if allow_private:
        if not all(is_lab_ip(ip) for ip in addresses):
            raise TargetPolicyError(
                "Private-lab mode accepts only RFC1918, loopback and IPv6 ULA addresses. "
                "Public, mixed, link-local and reserved destinations are blocked."
            )
    elif not all(ip.is_global for ip in addresses):
        raise TargetPolicyError(
            "Non-public destinations are blocked. Enable private-lab mode only for an isolated lab you control."
        )

    # Deterministic ordering; callers must connect to these numeric addresses, not resolve host again.
    return tuple(sorted((str(ip) for ip in addresses), key=lambda item: (ipaddress.ip_address(item).version, item)))
