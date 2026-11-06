"""Transparent heuristic risk scoring; not a CVSS implementation."""
from __future__ import annotations
WEIGHTS={"Critical":10.0,"High":7.5,"Medium":5.0,"Low":2.5,"Info":0.5}
def score_findings(findings: list[dict]) -> dict:
    scored=[]; total=0.0
    for item in findings:
        severity=str(item.get("severity","Info")).title()
        base=WEIGHTS.get(severity,0.5)
        confidence=str(item.get("confidence","Medium")).title()
        multiplier={"High":1.0,"Medium":0.8,"Low":0.55}.get(confidence,0.8)
        score=round(base*multiplier,1); total+=score
        priority="P1" if score>=8 else "P2" if score>=5 else "P3" if score>=2 else "P4"
        scored.append({**item,"risk_score":score,"priority":priority})
    scored.sort(key=lambda x:(x["risk_score"],x.get("type","")),reverse=True)
    return {"risk_model":"BBH heuristic v1 (not CVSS)","total_risk_points":round(total,1),
        "highest_priority":scored[0]["priority"] if scored else "None","prioritized_findings":scored,
        "guidance":"Prioritize internet exposure, exploitability, business impact and asset criticality during analyst review. Scores are triage aids, not formal severity ratings."}
