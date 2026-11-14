"""Hosted API for Batman Bug Hunter. Public scans require DNS TXT ownership proof."""
from __future__ import annotations
import hashlib, os, secrets, sqlite3, time
from functools import wraps
from urllib.parse import urlparse

import dns.resolver
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash

from .core import ScanError, scan_target

APP = Flask(__name__)
APP.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
APP.config["JSON_SORT_KEYS"] = False
ORIGIN = os.environ.get("FRONTEND_ORIGIN", "https://batman-bug-hunter.pages.dev").rstrip("/")
DB_PATH = os.environ.get("DATABASE_PATH", "/var/data/bbh.sqlite3")
if not os.path.isdir(os.path.dirname(DB_PATH)):
    DB_PATH = os.environ.get("DATABASE_PATH", "/tmp/bbh.sqlite3")
CORS(APP, resources={r"/api/*": {"origins": [ORIGIN]}}, supports_credentials=False,
     allow_headers=["Authorization", "Content-Type"], methods=["GET", "POST", "DELETE"])
limiter = Limiter(get_remote_address, app=APP, default_limits=["120 per hour"],
                  storage_uri=os.environ.get("REDIS_URL", "memory://"))

def db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@APP.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS targets(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, hostname TEXT NOT NULL, verified_at INTEGER NOT NULL, UNIQUE(user_id, hostname));
        CREATE TABLE IF NOT EXISTS challenges(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, hostname TEXT NOT NULL, token TEXT NOT NULL, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, target TEXT NOT NULL, created_at INTEGER NOT NULL, result_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS report_user_idx ON reports(user_id, created_at DESC);
        """)
        c.commit()

def fail(message, status=400):
    return jsonify({"error": message}), status

def auth_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        raw = request.headers.get("Authorization", "")
        if not raw.startswith("Bearer "):
            return fail("Sign in to continue.", 401)
        digest = hashlib.sha256(raw[7:].encode()).hexdigest()
        row = db().execute("SELECT users.id, users.email FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?",
                           (digest, int(time.time()))).fetchone()
        if not row:
            return fail("Session expired. Sign in again.", 401)
        g.user = row
        g.token_hash = digest
        return fn(*args, **kwargs)
    return wrapped

@APP.get("/api/health")
@limiter.limit("30 per minute")
def health():
    return jsonify({"status":"ok","service":"Batman Bug Hunter API","version":"1.0.0",
                    "scan_policy":"DNS-verified public HTTPS targets only; lab network tools remain local-only"})

@APP.post("/api/auth/register")
@limiter.limit("5 per hour")
def register():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email","")).strip().lower()
    password = str(data.get("password",""))
    if len(email)>254 or "@" not in email or len(password)<12 or len(password)>256:
        return fail("Enter a valid email and a password of at least 12 characters.")
    try:
        cur = db().execute("INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)",
                           (email, generate_password_hash(password), int(time.time())))
        db().commit()
        return jsonify({"created":True,"user_id":cur.lastrowid,"message":"Account created. Sign in to start."}), 201
    except sqlite3.IntegrityError:
        return fail("An account with that email already exists.", 409)

@APP.post("/api/auth/login")
@limiter.limit("10 per 15 minutes")
def login():
    data=request.get_json(silent=True) or {}
    email=str(data.get("email","")).strip().lower()
    password=str(data.get("password",""))
    row=db().execute("SELECT id,email,password_hash FROM users WHERE email=?",(email,)).fetchone()
    if not row or not check_password_hash(row["password_hash"],password):
        return fail("Email or password is incorrect.",401)
    token=secrets.token_urlsafe(40)
    db().execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                 (hashlib.sha256(token.encode()).hexdigest(),row["id"],int(time.time())+86400*7))
    db().commit()
    return jsonify({"token":token,"expires_in":604800,"user":{"id":row["id"],"email":row["email"]}})

@APP.post("/api/auth/logout")
@auth_required
def logout():
    db().execute("DELETE FROM sessions WHERE token_hash=?",(g.token_hash,))
    db().commit()
    return jsonify({"logged_out":True})

@APP.get("/api/me")
@auth_required
def me():
    return jsonify({"id":g.user["id"],"email":g.user["email"]})

@APP.post("/api/targets/challenge")
@auth_required
@limiter.limit("10 per hour")
def create_challenge():
    data=request.get_json(silent=True) or {}
    host=str(data.get("hostname","")).strip().lower().rstrip(".")
    if len(host)>253 or not host or "/" in host or ":" in host or "@" in host:
        return fail("Enter a domain name only, such as example.com.")
    try:
        parsed=urlparse("https://"+host)
        if not parsed.hostname or parsed.hostname != host or "." not in host:
            return fail("Enter a valid fully-qualified domain.")
    except ValueError:
        return fail("Invalid domain.")
    token="bbh-verify="+secrets.token_urlsafe(24)
    now=int(time.time())
    db().execute("DELETE FROM challenges WHERE user_id=? AND hostname=?",(g.user["id"],host))
    db().execute("INSERT INTO challenges(user_id,hostname,token,expires_at) VALUES(?,?,?,?)",
                 (g.user["id"],host,token,now+3600))
    db().commit()
    return jsonify({"hostname":host,"record_type":"TXT","record_name":"_batman-bug-hunter."+host,
                    "record_value":token,"expires_in":3600,
                    "instructions":"Add this DNS TXT record, wait for DNS propagation, then submit the hostname to /api/targets/verify."})

@APP.post("/api/targets/verify")
@auth_required
@limiter.limit("10 per hour")
def verify_target():
    data=request.get_json(silent=True) or {}
    host=str(data.get("hostname","")).strip().lower().rstrip(".")
    row=db().execute("SELECT token,expires_at FROM challenges WHERE user_id=? AND hostname=?",(g.user["id"],host)).fetchone()
    if not row or row["expires_at"]<int(time.time()):
        return fail("No active verification challenge. Create a new one.",400)
    try:
        answers=dns.resolver.resolve("_batman-bug-hunter."+host,"TXT",lifetime=5)
        values={b"".join(x.strings).decode("utf-8","replace") for x in answers}
    except Exception:
        values=set()
    if row["token"] not in values:
        return fail("DNS TXT record not found yet. Check the record name and value, then retry.",409)
    db().execute("INSERT INTO targets(user_id,hostname,verified_at) VALUES(?,?,?) ON CONFLICT(user_id,hostname) DO UPDATE SET verified_at=excluded.verified_at",
                 (g.user["id"],host,int(time.time())))
    db().execute("DELETE FROM challenges WHERE user_id=? AND hostname=?",(g.user["id"],host))
    db().commit()
    return jsonify({"verified":True,"hostname":host})

@APP.get("/api/targets")
@auth_required
def targets():
    rows=db().execute("SELECT hostname,verified_at FROM targets WHERE user_id=? ORDER BY hostname",(g.user["id"],)).fetchall()
    return jsonify({"targets":[dict(x) for x in rows]})

@APP.post("/api/scan")
@auth_required
@limiter.limit("3 per hour")
def scan():
    data=request.get_json(silent=True) or {}
    target=str(data.get("target","")).strip()
    try:
        parsed=urlparse(target if "://" in target else "https://"+target)
        port=parsed.port
    except ValueError:
        return fail("Invalid target URL or port.",400)
    host=(parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not host or port not in (None,443):
        return fail("Hosted scans accept HTTPS on the standard port only.",400)
    row=db().execute("SELECT 1 FROM targets WHERE user_id=? AND hostname=?",(g.user["id"],host)).fetchone()
    if not row:
        return fail("Verify ownership of this domain before scanning.",403)
    try:
        result=scan_target(target,allow_private=False,active=False,allowed_hosts={host})
    except (ScanError,ValueError) as exc:
        return fail(str(exc),422)
    import json
    cur=db().execute("INSERT INTO reports(user_id,target,created_at,result_json) VALUES(?,?,?,?)",
                     (g.user["id"],result["target"],int(time.time()),json.dumps(result)))
    db().commit()
    return jsonify({"report_id":cur.lastrowid,"result":result}),201

@APP.get("/api/reports")
@auth_required
def reports():
    rows=db().execute("SELECT id,target,created_at,result_json FROM reports WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
                      (g.user["id"],)).fetchall()
    import json
    return jsonify({"reports":[{"id":r["id"],"target":r["target"],"created_at":r["created_at"],
                                "result":json.loads(r["result_json"])} for r in rows]})

@APP.errorhandler(413)
def too_large(_e):
    return fail("Request body exceeds the 2 MB limit.",413)

@APP.errorhandler(429)
def too_many(_e):
    return fail("Rate limit reached. Wait before trying again.",429)

init_db()
