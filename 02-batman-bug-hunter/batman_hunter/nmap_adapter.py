"""Optional Nmap XML integration with strict single-host and port bounds."""
from __future__ import annotations
import ipaddress, shutil, subprocess, xml.etree.ElementTree as ET

def run_nmap(host: str, ports: str="22,80,443,445,3389,8080", timeout: int=75) -> dict:
    try: ip=ipaddress.ip_address(host.strip())
    except ValueError: raise ValueError("Nmap integration accepts a literal IP address only.")
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise ValueError("Nmap integration is restricted to private, loopback or link-local lab addresses.")
    raw=[x.strip() for x in ports.split(",") if x.strip()]
    if not raw or len(raw)>64: raise ValueError("Choose between 1 and 64 TCP ports.")
    values=[]
    for item in raw:
        try: n=int(item)
        except ValueError: raise ValueError("Ports must be comma-separated integers.")
        if not 1<=n<=65535: raise ValueError("Port numbers must be between 1 and 65535.")
        if n not in values: values.append(n)
    binary=shutil.which("nmap")
    if not binary: raise RuntimeError("Nmap is not installed or not on PATH. Install Nmap, then restart Batman Bug Hunter.")
    cmd=[binary,"-sT","-Pn","-n","-T3","--reason","-p",",".join(map(str,values)),"-oX","-",str(ip)]
    try:
        proc=subprocess.run(cmd,capture_output=True,text=True,timeout=max(10,min(timeout,90)),check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Nmap scan timed out; reduce the selected ports.") from exc
    if proc.returncode not in (0,1): raise RuntimeError("Nmap failed: "+(proc.stderr or "unknown error")[:300])
    try: root=ET.fromstring(proc.stdout)
    except ET.ParseError as exc: raise RuntimeError("Nmap returned invalid XML output.") from exc
    results=[]
    for port in root.findall(".//port"):
        state=port.find("state"); service=port.find("service")
        results.append({"port":int(port.get("portid")),"protocol":port.get("protocol"),
            "state":state.get("state") if state is not None else "unknown",
            "service":service.get("name","unknown") if service is not None else "unknown",
            "product":service.get("product","") if service is not None else ""})
    return {"target":str(ip),"scanner":"Nmap TCP connect (-sT)","ports":results,
            "open_ports":[x for x in results if x["state"]=="open"],
            "disclaimer":"Only scan assets you own or are explicitly authorized to test. Service fingerprints can be inaccurate."}
