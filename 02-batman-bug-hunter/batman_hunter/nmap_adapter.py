"""Nmap XML integration for explicitly authorized single-host assessments.

Supports public internet assets and private lab assets. The caller must obtain
explicit authorization and define scope before invoking this adapter.
"""
from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET


def _resolve_target(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Resolve one unambiguous address and reject special-use destinations."""
    value = (host or "").strip().strip("[]")
    if not value or any(char.isspace() for char in value) or "/" in value:
        raise ValueError("Enter one valid IP address or hostname.")

    try:
        addresses = {ipaddress.ip_address(value)}
    except ValueError:
        try:
            records = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
            addresses = {ipaddress.ip_address(record[4][0].split("%", 1)[0]) for record in records}
        except (OSError, ValueError) as exc:
            raise ValueError("The target hostname could not be resolved.") from exc

    if not addresses:
        raise ValueError("The target did not resolve to an IP address.")
    if len(addresses) != 1:
        raise ValueError("The hostname resolves to multiple IP addresses. Select one in-scope IP address explicitly.")

    address = next(iter(addresses))
    if address.is_multicast or address.is_unspecified or address.is_reserved:
        raise ValueError("Multicast, unspecified and reserved IP destinations are not valid scan targets.")
    if not (address.is_global or address.is_private or address.is_loopback or address.is_link_local):
        raise ValueError("The target IP is not a supported public or private-unicast destination.")
    return address


def _parse_ports(ports: str) -> list[int]:
    raw = [item.strip() for item in str(ports).split(",") if item.strip()]
    if not raw or len(raw) > 64:
        raise ValueError("Choose between 1 and 64 TCP ports.")
    values: list[int] = []
    for item in raw:
        try:
            number = int(item)
        except ValueError as exc:
            raise ValueError("Ports must be comma-separated integers.") from exc
        if not 1 <= number <= 65535:
            raise ValueError("Port numbers must be between 1 and 65535.")
        if number not in values:
            values.append(number)
    return values


def run_nmap(host: str, ports: str = "22,80,443,445,3389,8080", timeout: int = 75) -> dict:
    """Run bounded Nmap TCP connect discovery against one authorized host.

    Public addresses are supported; authorization is enforced by the caller's
    UI/CLI workflow and must not be inferred from routability.
    """
    address = _resolve_target(host)
    values = _parse_ports(ports)
    binary = shutil.which("nmap")
    if not binary:
        raise RuntimeError("Nmap is not installed or not on PATH. Install Nmap, then restart Batman Bug Hunter.")

    cmd = [binary, "-sT", "-Pn", "-n", "-T3", "--reason", "--max-retries", "2",
           "--host-timeout", "90s", "-p", ",".join(map(str, values)), "-oX", "-"]
    if address.version == 6:
        cmd.append("-6")
    cmd.append(str(address))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=max(10, min(int(timeout), 90)), check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Nmap scan timed out; reduce the selected ports or increase the timeout within the allowed limit.") from exc

    if proc.returncode not in (0, 1):
        raise RuntimeError("Nmap failed: " + (proc.stderr or "unknown error")[:300])
    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError as exc:
        raise RuntimeError("Nmap returned invalid XML output.") from exc

    results = []
    for port in root.findall(".//port"):
        state = port.find("state")
        service = port.find("service")
        results.append({
            "port": int(port.get("portid")),
            "protocol": port.get("protocol"),
            "state": state.get("state") if state is not None else "unknown",
            "reason": state.get("reason", "") if state is not None else "",
            "service": service.get("name", "unknown") if service is not None else "unknown",
            "product": service.get("product", "") if service is not None else "",
            "version": service.get("version", "") if service is not None else "",
        })

    return {
        "target": str(address),
        "scope_type": "public" if address.is_global else "private/lab",
        "scanner": "Nmap TCP connect (-sT)",
        "ports": results,
        "open_ports": [item for item in results if item["state"] == "open"],
        "disclaimer": "Only scan assets you own or are explicitly authorized to assess. Public reachability is not permission. Service fingerprints can be inaccurate.",
    }
