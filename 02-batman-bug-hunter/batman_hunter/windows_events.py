"""Windows Security Event Log collection and offline CSV investigation."""
from __future__ import annotations
import csv, io, json, platform, subprocess
from collections import Counter, defaultdict
from datetime import datetime

def analyze_auth_events_csv(content: str, threshold: int=5) -> dict:
    if not 3<=threshold<=100: raise ValueError("Threshold must be between 3 and 100.")
    rows=list(csv.DictReader(io.StringIO(content)))
    events=[]; failures=Counter(); success=Counter(); by_ip=defaultdict(list); users=defaultdict(set)
    for row in rows:
        r={str(k).strip().lower():str(v or "").strip() for k,v in row.items() if k}
        eid=r.get("eventid") or r.get("event id") or r.get("id","")
        if eid not in ("4624","4625"): continue
        user=r.get("targetusername") or r.get("account name") or r.get("username") or r.get("target user name") or "Unknown"
        ip=r.get("ipaddress") or r.get("source network address") or r.get("sourceip") or "Unknown"
        stamp=r.get("timecreated") or r.get("timestamp") or r.get("date and time") or r.get("time","")
        event={"event_id":eid,"user":user,"source_ip":ip,"timestamp":stamp}
        events.append(event)
        if eid=="4625":
            failures[ip]+=1; users[ip].add(user); by_ip[ip].append(event)
        else: success[(ip,user)]+=1
    alerts=[]
    for ip,count in failures.items():
        if count>=threshold:
            alerts.append({"source_ip":ip,"failed_attempts":count,"targeted_users":sorted(users[ip]),
                "distinct_users":len(users[ip]),"successful_logons_same_ip":sum(v for (src,_),v in success.items() if src==ip),
                "severity":"High" if count>=10 or len(users[ip])>=5 else "Medium"})
    alerts.sort(key=lambda x:x["failed_attempts"],reverse=True)
    return {"events_analyzed":len(events),"failed_logons":sum(failures.values()),"successful_logons":sum(success.values()),
        "alerts":alerts,"events":events[:1000],"threshold":threshold,
        "next_steps":["Correlate 4625 failures with 4624 successes by source IP and account.","Check MFA, VPN, identity-provider and endpoint telemetry.",
        "Validate whether source addresses belong to approved NAT, VPN or vulnerability scanners.","Do not treat failed logons alone as proof of compromise."]}

def collect_local_security_events(limit: int=2000) -> dict:
    if platform.system()!="Windows": raise RuntimeError("Live Windows Event Log collection is available only on Windows. Upload an exported CSV on other platforms.")
    limit=max(1,min(int(limit),5000))
    script=f"""$ErrorActionPreference='Stop'; $events=Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624,4625}} -MaxEvents {limit} | ForEach-Object {{ [xml]$x=$_.ToXml(); $d=@{{}}; foreach($v in $x.Event.EventData.Data){{$d[[string]$v.Name]=[string]$v.'#text'}}; [pscustomobject]@{{EventID=$_.Id;TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o');TargetUserName=$d['TargetUserName'];IpAddress=$d['IpAddress']}} }}; ConvertTo-Json -InputObject @($events) -Depth 4 -Compress"""
    proc=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",script],
        capture_output=True,text=True,timeout=45,check=False)
    if proc.returncode: raise RuntimeError(("Could not read Windows Security log: "+proc.stderr.strip())[:500])
    try: data=json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc: raise RuntimeError("PowerShell returned invalid event data.") from exc
    if isinstance(data,dict): data=[data]
    out=io.StringIO(); writer=csv.DictWriter(out,fieldnames=["EventID","TimeCreated","TargetUserName","IpAddress"]); writer.writeheader(); writer.writerows(data)
    result=analyze_auth_events_csv(out.getvalue())
    result["source"]="Local Windows Security log (Get-WinEvent)"
    result["records_collected"]=len(data)
    return result
