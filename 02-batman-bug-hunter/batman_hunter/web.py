"""Local Flask dashboard. Keep bound to localhost."""
from io import BytesIO
from flask import Flask, render_template, request, send_file, jsonify, Response
from .crypto import CryptoError, encrypt_text, decrypt_text, sha256_text, generate_password
from .core import ScanError, scan_target
from .recon import scan_host
from .forensics import hash_bytes, analyze_text_log, analyze_failed_logons_csv
from .blue_team import triage_failed_logons
from .reporting import build_pdf
from .lab_testing import run_lab_checks
from .nmap_adapter import run_nmap
from .windows_events import analyze_auth_events_csv, collect_local_security_events
from .risk import score_findings
from .html_reporting import build_html
from .versioning import version_info, check_latest

app = Flask(__name__, template_folder="../templates", static_folder="../static")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
_latest_report = {"title":"Batman Bug Hunter X","summary":{"Status":"No operation completed yet"},"details":[],"notes":"Run a module to populate this report."}
_scan_history = []

def _remember(title, summary, details, notes=""):
    global _latest_report
    details = details or []
    risk = score_findings(details)
    summary = {**summary, "Risk points (BBH heuristic)":risk["total_risk_points"], "Highest priority":risk["highest_priority"]}
    _latest_report={"title":title,"summary":summary,"details":risk["prioritized_findings"],"notes":notes + "\n\n" + risk["guidance"]}
    _scan_history.insert(0, {"title":title, "time":__import__("datetime").datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"), "target":str(summary.get("Target", "")), "findings":len(risk["prioritized_findings"])})
    del _scan_history[20:]

@app.get("/")
def index():
    return render_template("index.html", report=None, error=None)

@app.post("/scan")
def scan():
    if request.form.get("authorized") != "yes":
        return render_template("index.html", report=None, error="Confirm that you own this target or have explicit permission.")
    try:
        report = scan_target(request.form.get("target", ""), allow_private=request.form.get("allow_private") == "yes", active=request.form.get("active") == "yes")
        _remember("Web security assessment",{"Target":report["target"],"Mode":report["mode"],"Requests":report["requests_made"],**report["summary"]},report["findings"] or [{"severity":"Info","Observation":x} for x in report["observations"]],report["disclaimer"])
        return render_template("index.html", report=report, error=None)
    except ScanError as exc:
        return render_template("index.html", report=None, error=str(exc))

@app.route("/crypto", methods=["GET", "POST"])
def crypto():
    result = error = digest = generated_password = None
    mode = request.form.get("mode", "encrypt")
    if request.method == "POST":
        try:
            if mode == "encrypt": result = encrypt_text(request.form.get("plaintext", ""), request.form.get("passphrase", ""))
            elif mode == "decrypt": result = decrypt_text(request.form.get("ciphertext", ""), request.form.get("passphrase", ""))
            elif mode == "hash": digest = sha256_text(request.form.get("hash_input", ""))
            elif mode == "password": generated_password = generate_password(int(request.form.get("length", "20")))
            else: raise CryptoError("Unknown crypto operation.")
        except (CryptoError, ValueError) as exc: error = str(exc) or "Invalid input."
    return render_template("crypto.html", result=result, error=error, mode=mode, digest=digest, generated_password=generated_password)

@app.get("/modules")
def modules():
    return render_template("modules.html",error=None,recon=None,forensic=None,blue=None,lab=None,nmap=None,report_ready=False,version=version_info())

@app.post("/modules/recon")
def module_recon():
    try:
        if request.form.get("authorized")!="yes": raise ValueError("Confirm authorization before scanning.")
        host=request.form.get("host","").strip()
        ports=[int(x.strip()) for x in request.form.get("ports","").split(",") if x.strip()]
        if not ports: raise ValueError("Enter at least one TCP port.")
        result=scan_host(host,ports)
        _remember("Network reconnaissance",{"Target":result["target"],"Open ports":len(result["open_ports"])},[{"severity":"Info",**x} for x in result["ports"]],result["disclaimer"])
        return render_template("modules.html",error=None,recon=result,forensic=None,blue=None,lab=None,nmap=None,report_ready=False,version=version_info())
    except (ValueError,OSError) as exc:
        return render_template("modules.html",error=str(exc),recon=None,forensic=None,blue=None,lab=None,nmap=None,report_ready=False,version=version_info())

@app.post("/modules/nmap")
def module_nmap():
    try:
        if request.form.get("authorized")!="yes": raise ValueError("Confirm authorization before scanning.")
        result=run_nmap(request.form.get("host",""),request.form.get("ports","22,80,443,445,3389,8080"))
        _remember("Nmap network reconnaissance",{"Target":result["target"],"Open ports":len(result["open_ports"])},[{"severity":"Info",**x} for x in result["ports"]],result["disclaimer"])
        return render_template("modules.html",error=None,recon=None,forensic=None,blue=None,lab=None,nmap=result,report_ready=False,version=version_info())
    except (ValueError,OSError,RuntimeError) as exc:
        return render_template("modules.html",error=str(exc),recon=None,forensic=None,blue=None,lab=None,nmap=None,report_ready=False,version=version_info())

@app.post("/modules/lab")
def module_lab():
    try:
        if request.form.get("authorized")!="yes": raise ValueError("Confirm this is your isolated local training lab.")
        result=run_lab_checks(request.form.get("url",""))
        _remember("Controlled SQLi and XSS indicator checks",{"Target":result["target"],"Checks":len(result["tests"]),"Indicators":len(result["findings"])},result["findings"],result["disclaimer"])
        return render_template("modules.html",error=None,recon=None,forensic=None,blue=None,lab=result,nmap=None,report_ready=False,version=version_info())
    except (ValueError,OSError) as exc:
        return render_template("modules.html",error=str(exc),recon=None,forensic=None,blue=None,lab=None,nmap=None,report_ready=False,version=version_info())

@app.post("/modules/forensics")
def module_forensics():
    f=request.files.get("evidence")
    try:
        if not f or not f.filename: raise ValueError("Choose an evidence file.")
        data=f.read(2*1024*1024+1)
        if len(data)>2*1024*1024: raise ValueError("File exceeds the 2 MB limit.")
        result=hash_bytes(data)
        if f.filename.lower().endswith((".log",".txt")):
            try: result["log_analysis"]=analyze_text_log(data.decode("utf-8-sig"))
            except UnicodeDecodeError: result["log_analysis"]={"error":"Text log is not UTF-8; hash was still calculated."}
        _remember("Digital forensics evidence",{"Filename":f.filename,"Size bytes":result["size_bytes"],"SHA-256":result["sha256"]},[{"severity":"Info","Filename":f.filename,**result}],"Hashing establishes an integrity reference; it does not prove authenticity or chain of custody.")
        return render_template("modules.html",error=None,recon=None,forensic=result,blue=None,lab=None,nmap=None,report_ready=False,version=version_info())
    except ValueError as exc:
        return render_template("modules.html",error=str(exc),recon=None,forensic=None,blue=None,lab=None,nmap=None,report_ready=False,version=version_info())

@app.post("/modules/blue")
def module_blue():
    f=request.files.get("logfile")
    try:
        if not f or not f.filename: raise ValueError("Choose a CSV export of Windows Security events.")
        data=f.read(2*1024*1024+1)
        if len(data)>2*1024*1024: raise ValueError("CSV exceeds the 2 MB limit.")
        result=triage_failed_logons(data.decode("utf-8-sig"),int(request.form.get("threshold","5")))
        _remember("Blue Team failed-logon triage",{"Rows":result["rows_analyzed"],"Failed logons":result["failed_logons"],"Alerts":len(result["alerts"])},[{"severity":x["severity"],**x} for x in result["alerts"]],result["disclaimer"])
        return render_template("modules.html",error=None,recon=None,forensic=None,blue=result,lab=None,nmap=None,report_ready=False,version=version_info())
    except (ValueError,UnicodeDecodeError) as exc:
        return render_template("modules.html",error=str(exc),recon=None,forensic=None,blue=None,lab=None,nmap=None,report_ready=False,version=version_info())

@app.post("/modules/windows/live")
def module_windows_live():
    try:
        if request.form.get("authorized")!="yes": raise ValueError("Confirm you are authorized to read this Windows Security log.")
        result=collect_local_security_events(int(request.form.get("limit","2000")))
        _remember("Local Windows Security Event investigation",{"Records":result["records_collected"],"Failed logons":result["failed_logons"],"Alerts":len(result["alerts"])},[{"severity":x["severity"],**x} for x in result["alerts"]], "Collected from local Security log using Get-WinEvent. "+ " ".join(result["next_steps"]))
        return render_template("modules.html",error=None,recon=None,forensic=None,blue=result,lab=None,nmap=None,report_ready=False,version=version_info())
    except (ValueError,RuntimeError,OSError) as exc:
        return render_template("modules.html",error=str(exc),recon=None,forensic=None,blue=None,lab=None,nmap=None,report_ready=False,version=version_info())

@app.post("/modules/report")
def module_report():
    title=request.form.get("title","Batman Bug Hunter X Security Assessment")[:150]
    _latest_report["title"]=title
    _latest_report["notes"]=request.form.get("notes","")[:5000] or _latest_report.get("notes","")
    return render_template("modules.html",error=None,recon=None,forensic=None,blue=None,lab=None,nmap=None,report_ready=True,version=version_info())

@app.get("/modules/report/download")
def download_report():
    pdf=build_pdf(_latest_report["title"],_latest_report["summary"],_latest_report["details"],_latest_report["notes"])
    return send_file(BytesIO(pdf),mimetype="application/pdf",as_attachment=True,download_name="Batman-Bug-Hunter-Security-Report.pdf")

@app.get("/modules/report/html")
def download_html_report():
    content=build_html(_latest_report["title"],_latest_report["summary"],_latest_report["details"],_latest_report["notes"])
    return Response(content,mimetype="text/html",headers={"Content-Disposition":"attachment; filename=Batman-Bug-Hunter-Investigation.html"})

@app.get("/api/dashboard")
def api_dashboard():
    """Return real application health and latest in-memory assessment telemetry."""
    details = _latest_report.get("details", [])
    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in details:
        level = str(item.get("severity", "info")).lower()
        if level in severity:
            severity[level] += 1
    summary = _latest_report.get("summary", {})
    title = _latest_report.get("title", "")
    is_network = "network" in title.lower() or "nmap" in title.lower()
    open_ports = summary.get("Open ports") if is_network else None
    return jsonify({
        "engine": "online",
        "has_assessment": bool(_scan_history),
        "total_findings": sum(severity.values()),
        "severity": severity,
        "network": {
            "target": str(summary.get("Target", "")) if is_network else "",
            "open_ports": open_ports,
            "operation": title if is_network else ""
        },
        "history": list(_scan_history)
    })

@app.get("/api/version")
def api_version():
    return jsonify(version_info())

@app.get("/api/version/check")
def api_version_check():
    return jsonify(check_latest())

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
