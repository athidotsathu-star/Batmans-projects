"""Conservative TCP reconnaissance for explicitly authorized lab assets."""
from __future__ import annotations
import ipaddress, socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS=(21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,5900,8080,8443)
SERVICE={21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",135:"MS-RPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",8080:"HTTP-alt",8443:"HTTPS-alt"}

def scan_host(host: str, ports=None, timeout: float=0.5) -> dict:
    ports=tuple(ports or COMMON_PORTS)
    if len(ports)>32 or any(not isinstance(p,int) or p<1 or p>65535 for p in ports):
        raise ValueError("Choose up to 32 valid TCP ports.")
    try: ipaddress.ip_address(host)
    except ValueError: host=socket.gethostbyname(host)
    def probe(port):
        try:
            with socket.create_connection((host,port),timeout=max(.2,min(timeout,1.5))): return {"port":port,"state":"open","service":SERVICE.get(port,"unknown")}
        except (OSError,TimeoutError): return {"port":port,"state":"closed_or_filtered","service":SERVICE.get(port,"unknown")}
    with ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(probe,ports))
    return {"target":host,"method":"TCP connect","ports":results,"open_ports":[x for x in results if x["state"]=="open"],
            "disclaimer":"A closed_or_filtered result cannot distinguish a closed port from firewall filtering. Only scan authorized assets."}
