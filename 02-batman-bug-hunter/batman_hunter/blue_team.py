"""Blue-team detections for exported Windows security event CSV files."""
from .forensics import analyze_failed_logons_csv

def triage_failed_logons(content: str, threshold: int=5) -> dict:
    if not 3 <= threshold <= 100: raise ValueError("Threshold must be between 3 and 100.")
    result=analyze_failed_logons_csv(content)
    result["alerts"]=[x for x in result["bursts"] if x["failures"]>=threshold]
    result["threshold"]=threshold
    result["next_steps"]=["Correlate Event ID 4625 with successful Event ID 4624 logons.",
      "Check source IP ownership, VPN/proxy context and geolocation cautiously.",
      "Review account status, MFA events, endpoint alerts and the time window.",
      "Escalate only after validating supporting evidence."]
    return result
