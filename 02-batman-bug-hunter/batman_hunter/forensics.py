"""File integrity and defensive log triage helpers."""
from __future__ import annotations
import csv, hashlib, io, json
from collections import Counter
from datetime import datetime, timezone

def hash_bytes(data: bytes) -> dict:
    return {"sha256": hashlib.sha256(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(), "size_bytes": len(data)}

def analyze_failed_logons_csv(content: str) -> dict:
    """Analyze exported Windows 4625 CSV data; never accesses the event log itself."""
    reader = csv.DictReader(io.StringIO(content))
    rows=list(reader); counts=Counter(); samples=[]
    for row in rows:
        norm={str(k).strip().lower():str(v).strip() for k,v in row.items() if k}
        event=norm.get("eventid") or norm.get("event id") or norm.get("id","")
        if event and event != "4625": continue
        user=norm.get("targetusername") or norm.get("account name") or norm.get("username") or "Unknown"
        ip=norm.get("ipaddress") or norm.get("source network address") or norm.get("sourceip") or "Unknown"
        counts[(user,ip)] += 1
        if len(samples)<500: samples.append({"user":user,"source_ip":ip,"event_id":event or "4625"})
    bursts=[{"user":u,"source_ip":ip,"failures":n,"severity":"High" if n>=10 else "Medium" if n>=5 else "Low"}
            for (u,ip),n in counts.items() if n>=3]
    bursts.sort(key=lambda x:x["failures"],reverse=True)
    return {"rows_analyzed":len(rows),"failed_logons":sum(counts.values()),"unique_user_source_pairs":len(counts),
            "bursts":bursts,"sample_events":samples[:100],
            "disclaimer":"Repeated failures are investigation leads, not proof of compromise. Correlate with successful logons, MFA, endpoint and identity telemetry."}

def analyze_text_log(content: str) -> dict:
    lines=content.splitlines()
    terms=("failed password","authentication failure","invalid user","account locked","sudo:","unauthorized")
    hits=[{"line":i+1,"text":line[:500]} for i,line in enumerate(lines) if any(t in line.lower() for t in terms)]
    return {"lines":len(lines),"suspicious_matches":len(hits),"matches":hits[:500]}
