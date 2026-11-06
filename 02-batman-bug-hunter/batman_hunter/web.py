"""Local Flask dashboard. Keep bound to localhost."""
from io import BytesIO
from flask import Flask, render_template, request, send_file
from .crypto import CryptoError, encrypt_text, decrypt_text, sha256_text, generate_password
from .core import ScanError, scan_target
from .recon import scan_host
from .forensics import hash_bytes, analyze_text_log, analyze_failed_logons_csv
from .blue_team import triage_failed_logons
from .reporting import build_pdf

app = Flask(__name__, template_folder="../templates", static_folder="../static")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
_latest_report = {"title":"Batman Bug Hunter X","summary":{"Status":"No operation completed yet"},"details":[],"notes":"Run a module to populate this report."}

def _remember(title, summary, details, notes=""):
    global _latest_report
    _latest_report={"title":title,"summary":summary,"details":details,"notes":notes}

@app.get("/")
def index():
    return render_template("index.html", report=None, error=None)

@app.post("/scan")
def scan():
    if request.form.get("authorized") != "yes":
        return render_template("index.html", report=None, error="Confirm that you own this target or have explicit permission.")
    try:
        report = scan_target(request.form.get("target", ""), allow_private=request.form.get("allow_private") == "yes", active=request.form.get("active") == "yes")
        _remember("Web security assessment",{"Target":report["target"],"Mode":report["mode"],"Requests":report["requests_made"],**report["summary"]},report["findings"] or [{"Observation":x} for x in report["observations"]],report["disclaimer"])
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
    return render_template("modules.html",error=None,recon=None,forensic=None,blue=None,report_ready=False)

@app.post("/modules/recon")
def module_recon():
    try:
        if request.form.get("authorized")!="yes": raise ValueError("Confirm authorization before scanning.")
        host=request.form.get("host","").strip()
        ports=[int(x.strip()) for x in request.form.get("ports","").split(",") if x.strip()]
        if not ports: raise ValueError("Enter at least one TCP port.")
        result=scan_host(host,ports)
        _remember("Network reconnaissance",{"Target":result["target"],"Open ports":len(result["open_ports"])},result["ports"],result["disclaimer"])
        return render_template("modules.html",error=None,recon=result,forensic=None,blue=None,report_ready=False)
    except (ValueError,OSError) as exc:
        return render_template("modules.html",error=str(exc),recon=None,forensic=None,blue=None,report_ready=False)

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
        _remember("Digital forensics evidence",{"Filename":f.filename,"Size bytes":result["size_bytes"],"SHA-256":result["sha256"]},[{"Filename":f.filename,**result}],"Hashing establishes an integrity reference; it does not prove authenticity or chain of custody.")
        return render_template("modules.html",error=None,recon=None,forensic=result,blue=None,report_ready=False)
    except ValueError as exc:
        return render_template("modules.html",error=str(exc),recon=None,forensic=None,blue=None,report_ready=False)

@app.post("/modules/blue")
def module_blue():
    f=request.files.get("logfile")
    try:
        if not f or not f.filename: raise ValueError("Choose a CSV export of Windows Security events.")
        data=f.read(2*1024*1024+1)
        if len(data)>2*1024*1024: raise ValueError("CSV exceeds the 2 MB limit.")
        result=triage_failed_logons(data.decode("utf-8-sig"),int(request.form.get("threshold","5")))
        _remember("Blue Team failed-logon triage",{"Rows":result["rows_analyzed"],"Failed logons":result["failed_logons"],"Alerts":len(result["alerts"])},result["alerts"],"Event ID 4625 repeated failures are leads, not proof of compromise. Correlate with Event ID 4624 and other telemetry.")
        return render_template("modules.html",error=None,recon=None,forensic=None,blue=result,report_ready=False)
    except (ValueError,UnicodeDecodeError) as exc:
        return render_template("modules.html",error=str(exc),recon=None,forensic=None,blue=None,report_ready=False)

@app.post("/modules/report")
def module_report():
    title=request.form.get("title","Batman Bug Hunter X Security Assessment")[:150]
    _latest_report["title"]=title
    _latest_report["notes"]=request.form.get("notes","")[:5000] or _latest_report.get("notes","")
    return render_template("modules.html",error=None,recon=None,forensic=None,blue=None,report_ready=True)

@app.get("/modules/report/download")
def download_report():
    pdf=build_pdf(_latest_report["title"],_latest_report["summary"],_latest_report["details"],_latest_report["notes"])
    return send_file(BytesIO(pdf),mimetype="application/pdf",as_attachment=True,download_name="Batman-Bug-Hunter-Security-Report.pdf")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
