"""Defensive wireless inventory and offline capture metadata analysis.

No monitor-mode changes, frame injection, deauthentication, credential recovery,
or password cracking are performed by this module.
"""
import hashlib
import os
import platform
import re
import shutil
import struct
import subprocess
from collections import Counter


def _run(command, timeout=12):
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout, check=False)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except (OSError, subprocess.TimeoutExpired):
        return "", "Command unavailable or timed out.", 1


def detect_wireless_environment():
    system = platform.system()
    tools = {name: bool(shutil.which(name)) for name in
             ("aircrack-ng", "airmon-ng", "airodump-ng", "nmcli", "iw", "tshark")}
    adapters = []
    networks = []
    notes = []

    if system == "Linux":
        out, err, code = _run(["iw", "dev"])
        if code == 0:
            adapters = re.findall(r"^\s*Interface\s+(\S+)", out, re.M)
        if not adapters and tools["nmcli"]:
            out, _, code = _run(["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"])
            if code == 0:
                adapters = [line.split(":")[0] for line in out.splitlines()
                            if ":wifi" in line or ":802-11-wireless" in line]
        if tools["nmcli"]:
            out, err, code = _run([
                "nmcli", "--mode", "multiline",
                "--fields", "SSID,BSSID,CHAN,RATE,SIGNAL,SECURITY",
                "device", "wifi", "list", "--rescan", "no"
            ])
            if code == 0:
                current = {}
                for line in out.splitlines() + [""]:
                    if not line.strip():
                        if current:
                            networks.append({
                                "ssid": current.get("SSID", "<hidden>") or "<hidden>",
                                "bssid": current.get("BSSID", ""),
                                "channel": current.get("CHAN", ""),
                                "rate": current.get("RATE", ""),
                                "signal": current.get("SIGNAL", ""),
                                "security": current.get("SECURITY", "Unknown") or "Open"
                            })
                            current = {}
                        continue
                    if ":" in line:
                        key, value = line.split(":", 1)
                        current[key.strip()] = value.strip()
            else:
                notes.append("NetworkManager could not provide its cached Wi-Fi list.")
        else:
            notes.append("Install NetworkManager (nmcli) to display the OS-provided nearby network list.")
    elif system == "Windows":
        out, err, code = _run(["netsh", "wlan", "show", "interfaces"])
        if code == 0:
            adapters = re.findall(r"^\s*Name\s*:\s*(.+)$", out, re.M | re.I)
        out, err, code = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
        if code == 0:
            current = {}
            for line in out.splitlines() + [""]:
                stripped = line.strip()
                if re.match(r"^SSID\s+\d+\s*:", stripped, re.I):
                    if current:
                        networks.append(current)
                    current = {"ssid": stripped.split(":", 1)[1].strip() or "<hidden>"}
                elif current and re.match(r"^BSSID\s+\d+\s*:", stripped, re.I):
                    current["bssid"] = stripped.split(":", 1)[1].strip()
                elif current and re.match(r"^Signal\s*:", stripped, re.I):
                    current["signal"] = stripped.split(":", 1)[1].strip().rstrip("%")
                elif current and re.match(r"^Channel\s*:", stripped, re.I):
                    current["channel"] = stripped.split(":", 1)[1].strip()
                elif current and re.match(r"^Authentication\s*:", stripped, re.I):
                    current["security"] = stripped.split(":", 1)[1].strip()
            if current:
                networks.append(current)
        else:
            notes.append("Windows WLAN scan results are unavailable. Check that a Wi-Fi adapter is enabled.")
    else:
        notes.append("This build currently supports adapter/network inventory on Linux and Windows.")

    return {
        "platform": system,
        "adapters": adapters,
        "networks": networks[:100],
        "aircrack_tools": tools,
        "notes": notes,
        "disclaimer": "Inventory uses operating-system supplied scan/cache data. It does not connect to networks or transmit wireless attack frames."
    }


def analyze_pcap(data):
    """Parse classic PCAP metadata only; never extract keys or credentials."""
    if len(data) < 24:
        raise ValueError("Capture is too small to be a valid classic PCAP file.")
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"
    }
    if magic not in formats:
        if data[:4] == b"\x0a\x0d\x0d\x0a":
            raise ValueError("PCAPNG detected. Convert to classic PCAP with Wireshark/tshark, then upload the .pcap file.")
        raise ValueError("Unsupported capture format. Upload a classic .pcap file.")
    endian = formats[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    offset = 24
    packets = 0
    eapol = 0
    beacons = 0
    probe_responses = 0
    ssids = set()
    frame_types = Counter()
    truncated = False

    while offset + 16 <= len(data):
        header = data[offset:offset + 16]
        captured = struct.unpack(endian + "I", header[8:12])[0]
        offset += 16
        if captured > 4 * 1024 * 1024 or offset + captured > len(data):
            truncated = True
            break
        packet = data[offset:offset + captured]
        offset += captured
        packets += 1
        frame = packet
        if linktype == 127:  # radiotap
            if len(frame) < 8:
                continue
            rt_len = struct.unpack("<H", frame[2:4])[0]
            frame = frame[rt_len:]
        elif linktype == 192:  # PPI
            if len(frame) < 8:
                continue
            ppi_len = struct.unpack("<H", frame[2:4])[0]
            frame = frame[ppi_len:]
        elif linktype == 1:  # Ethernet
            if len(frame) >= 14 and frame[12:14] == b"\x88\x8e":
                eapol += 1
            continue
        elif linktype != 105:
            continue

        if len(frame) < 24:
            continue
        fc = struct.unpack("<H", frame[:2])[0]
        frame_type = (fc >> 2) & 0x3
        subtype = (fc >> 4) & 0xf
        frame_types[str(frame_type)] += 1
        if frame_type == 0 and subtype in (8, 5):
            if subtype == 8:
                beacons += 1
            else:
                probe_responses += 1
            # Beacon/probe response fixed parameters are 12 bytes after the 24-byte header.
            tag_offset = 36
            while tag_offset + 2 <= len(frame):
                tag, length = frame[tag_offset], frame[tag_offset + 1]
                tag_offset += 2
                if tag_offset + length > len(frame):
                    break
                if tag == 0 and length:
                    try:
                        ssids.add(frame[tag_offset:tag_offset + length].decode("utf-8", "replace"))
                    except Exception:
                        pass
                tag_offset += length
        if frame_type == 2:
            header_len = 24
            to_ds, from_ds = (fc >> 8) & 1, (fc >> 9) & 1
            if to_ds and from_ds:
                header_len += 6
            if (subtype & 0x8):
                header_len += 2
            llc = frame[header_len:header_len + 8]
            if llc == b"\xaa\xaa\x03\x00\x00\x00\x88\x8e":
                eapol += 1

    if packets == 0:
        raise ValueError("No readable packets were found in the capture.")
    return {
        "format": "classic PCAP",
        "file_size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "packets": packets,
        "link_type": linktype,
        "beacon_frames": beacons,
        "probe_response_frames": probe_responses,
        "eapol_frames": eapol,
        "observed_ssids": sorted(ssids)[:100],
        "frame_type_counts": dict(frame_types),
        "truncated_or_malformed": truncated,
        "interpretation": (
            "EAPOL frames were observed; this is only a packet-presence indicator, "
            "not proof of a complete handshake or a successful authentication."
            if eapol else
            "No EAPOL frames were identified in the parsed packets. Capture scope and link type may limit visibility."
        ),
        "disclaimer": "Offline metadata analysis only. No passwords, PMKIDs, keys or credential material are recovered."
    }
