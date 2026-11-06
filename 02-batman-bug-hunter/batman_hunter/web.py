"""Local Flask dashboard. Keep bound to localhost."""
from flask import Flask, render_template, request
from .crypto import CryptoError, encrypt_text, decrypt_text, sha256_text, generate_password
from .core import ScanError, scan_target

app = Flask(__name__, template_folder="../templates", static_folder="../static")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

@app.get("/")
def index():
    return render_template("index.html", report=None, error=None)

@app.post("/scan")
def scan():
    if request.form.get("authorized") != "yes":
        return render_template("index.html", report=None, error="Confirm that you own this target or have explicit permission.")
    allow_private = request.form.get("allow_private") == "yes"
    active = request.form.get("active") == "yes"
    try:
        report = scan_target(request.form.get("target", ""), allow_private=allow_private, active=active)
        return render_template("index.html", report=report, error=None)
    except ScanError as exc:
        return render_template("index.html", report=None, error=str(exc))


@app.route("/crypto", methods=["GET", "POST"])
def crypto():
    result = error = digest = generated_password = None
    mode = request.form.get("mode", "encrypt")
    if request.method == "POST":
        try:
            if mode == "encrypt":
                result = encrypt_text(request.form.get("plaintext", ""), request.form.get("passphrase", ""))
            elif mode == "decrypt":
                result = decrypt_text(request.form.get("ciphertext", ""), request.form.get("passphrase", ""))
            elif mode == "hash":
                digest = sha256_text(request.form.get("hash_input", ""))
            elif mode == "password":
                generated_password = generate_password(int(request.form.get("length", "20")))
            else:
                raise CryptoError("Unknown crypto operation.")
        except (CryptoError, ValueError) as exc:
            error = str(exc) or "Invalid input."
    return render_template("crypto.html", result=result, error=error, mode=mode,
                           digest=digest, generated_password=generated_password)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
