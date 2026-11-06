"""Local Flask dashboard. Keep bound to localhost."""
from flask import Flask, render_template, request
from .core import ScanError, scan_target

app = Flask(__name__, template_folder="../templates", static_folder="../static")


@app.get("/")
def index():
    return render_template("index.html", report=None, error=None)


@app.post("/scan")
def scan():
    if request.form.get("authorized") != "yes":
        return render_template("index.html", report=None,
                               error="Confirm that you own this target or have explicit permission.")
    allow_private = request.form.get("allow_private") == "yes"
    try:
        report = scan_target(request.form.get("target", ""), allow_private=allow_private)
        return render_template("index.html", report=report, error=None)
    except ScanError as exc:
        return render_template("index.html", report=None, error=str(exc))


if __name__ == "__main__":
    # Intentionally localhost-only; do not change to 0.0.0.0 for public exposure.
    app.run(host="127.0.0.1", port=5000, debug=False)
