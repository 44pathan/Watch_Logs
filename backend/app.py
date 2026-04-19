from flask import Flask, jsonify, request
from elasticsearch import Elasticsearch
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
import threading
import os
import json
import time
import hashlib
import secrets
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from rule_engine import RuleEngine
from correlator import Correlator
import requests as http_requests
import re
import ipaddress

app = Flask(__name__)

# Allow all origins — covers file://, http://localhost, http://localhost:80
CORS(app, resources={r"/api/*": {
    "origins": ["http://127.0.0.1:8080", "http://localhost:8080",
                 "http://localhost", "http://127.0.0.1", "*"],
    "methods": ["GET", "POST", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"]
}})

# Belt-and-suspenders: manually inject CORS + security headers on every response
@app.after_request
def add_headers(response):
    # CORS
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


# ── Elasticsearch client ──────────────────────────────────
es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", "Watchlogs@69"),
    verify_certs=False
)

ABUSEIPDB_API_KEY = "97d8c48e152c3d01c523c68c276e888cb83f8c053c35f6992cce047427712ca9b7716ea23a29a8d2"

# ── Rule engine globals ────────────────────────────────────
RULES_PATH = os.path.join(os.path.dirname(__file__), "../rules/rules.json")
rule_engine = RuleEngine(RULES_PATH)

fired_alerts = []
FIRED_ALERTS_MAX = 500
fired_alerts_lock = threading.Lock()

# ── Correlation engine globals ─────────────────────────────────────────────
CORR_RULES_PATH = os.path.join(os.path.dirname(__file__), "../rules/correlation_rules.json")
correlator = Correlator(CORR_RULES_PATH)

correlated_alerts = []
CORRELATED_ALERTS_MAX = 200
correlated_alerts_lock = threading.Lock()

# ─────────────────────────────────────────────────────────

# ── Authentication system ──────────────────────────────────
JWT_SECRET = secrets.token_hex(32)   # Random per-restart; change to fixed for persistence
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 8

USERS_PATH = os.path.join(os.path.dirname(__file__), "users.json")

# Rate limiting state (IP -> {attempts, lockout_until})
login_attempts = {}
login_attempts_lock = threading.Lock()
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 900   # 15 minutes

# Token blacklist (for logout)
token_blacklist = set()
token_blacklist_lock = threading.Lock()


def load_users():
    """Load users from JSON file."""
    try:
        with open(USERS_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_users(users):
    """Persist users to JSON file."""
    with open(USERS_PATH, "w") as f:
        json.dump(users, f, indent=4)


def find_user(username):
    """Find user by username (case-insensitive)."""
    users = load_users()
    for u in users:
        if u["username"].lower() == username.lower():
            return u
    return None


def create_jwt(username, role="user"):
    """Create a signed JWT token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
        "jti": secrets.token_hex(16),  # unique token ID for blacklisting
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token):
    """Decode and validate a JWT token. Returns payload or None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        # Check blacklist
        with token_blacklist_lock:
            if payload.get("jti") in token_blacklist:
                return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def get_client_ip():
    """Get client IP, respecting X-Forwarded-For."""
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def check_rate_limit(ip):
    """Check if IP is rate-limited. Returns (allowed, message)."""
    with login_attempts_lock:
        if ip not in login_attempts:
            return True, ""

        entry = login_attempts[ip]

        # Check lockout
        if entry.get("lockout_until", 0) > time.time():
            remaining = int(entry["lockout_until"] - time.time())
            return False, f"Account locked. Try again in {remaining}s."

        # Reset if lockout expired
        if entry.get("lockout_until", 0) <= time.time() and entry.get("lockout_until", 0) > 0:
            login_attempts[ip] = {"attempts": 0, "lockout_until": 0}

        return True, ""


def record_failed_attempt(ip):
    """Record a failed login attempt and possibly trigger lockout."""
    with login_attempts_lock:
        if ip not in login_attempts:
            login_attempts[ip] = {"attempts": 0, "lockout_until": 0}

        login_attempts[ip]["attempts"] += 1
        attempts = login_attempts[ip]["attempts"]

        if attempts >= MAX_LOGIN_ATTEMPTS:
            # Progressive lockout: 15min base, doubles each time past threshold
            multiplier = max(1, attempts - MAX_LOGIN_ATTEMPTS + 1)
            lockout_time = min(LOCKOUT_SECONDS * multiplier, 3600)  # Cap at 1 hour
            login_attempts[ip]["lockout_until"] = time.time() + lockout_time
            return attempts, lockout_time

        return attempts, 0


def clear_failed_attempts(ip):
    """Clear failed login record on successful auth."""
    with login_attempts_lock:
        login_attempts.pop(ip, None)


def require_auth(f):
    """Decorator to protect API routes with JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"status": "error", "message": "Authentication required"}), 401

        token = auth_header[7:]  # Strip "Bearer "
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"status": "error", "message": "Invalid or expired token"}), 401

        # Attach user info to request context
        request.auth_user = payload.get("sub", "")
        request.auth_role = payload.get("role", "")
        return f(*args, **kwargs)
    return decorated


# ── Auth endpoints ─────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Authenticate user and return JWT."""
    client_ip = get_client_ip()

    # Rate limit check
    allowed, msg = check_rate_limit(client_ip)
    if not allowed:
        return jsonify({"status": "error", "message": msg}), 429

    # Parse request
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    username = (data.get("username") or "").strip()[:64]
    password = data.get("password") or ""

    # Input validation
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400

    if len(password) > 128:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    # Sanitize username (alphanumeric, underscores, hyphens only)
    import re as re_mod
    if not re_mod.match(r'^[a-zA-Z0-9_\-\.]+$', username):
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    # Find user
    user = find_user(username)

    # Constant-time comparison even if user doesn't exist
    # (prevents username enumeration via timing)
    if not user:
        # Hash a dummy password to keep timing consistent
        check_password_hash(
            "pbkdf2:sha256:1000000$dummy$" + "0" * 64,
            password
        )
        attempts, lockout = record_failed_attempt(client_ip)
        app.logger.warning(f"[AUTH] Failed login for '{username}' from {client_ip} (attempt {attempts})")
        if lockout > 0:
            return jsonify({"status": "error", "message": f"Too many attempts. Locked for {lockout}s."}), 429
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    # Verify password (werkzeug uses constant-time comparison internally)
    if not check_password_hash(user["password_hash"], password):
        attempts, lockout = record_failed_attempt(client_ip)
        app.logger.warning(f"[AUTH] Failed login for '{username}' from {client_ip} (attempt {attempts})")
        if lockout > 0:
            return jsonify({"status": "error", "message": f"Too many attempts. Locked for {lockout}s."}), 429
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    # Success
    clear_failed_attempts(client_ip)
    token = create_jwt(username, user.get("role", "user"))
    app.logger.info(f"[AUTH] Successful login for '{username}' from {client_ip}")

    return jsonify({
        "status": "ok",
        "token": token,
        "username": username,
        "role": user.get("role", "user"),
        "expires_in": JWT_EXPIRY_HOURS * 3600
    })


@app.route("/api/auth/verify", methods=["GET"])
def auth_verify():
    """Verify a JWT token is still valid."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"status": "error", "message": "No token"}), 401

    token = auth_header[7:]
    payload = decode_jwt(token)
    if not payload:
        return jsonify({"status": "error", "message": "Invalid or expired token"}), 401

    return jsonify({
        "status": "ok",
        "username": payload.get("sub"),
        "role": payload.get("role"),
        "expires_at": payload.get("exp")
    })


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    """Blacklist the current token."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        payload = decode_jwt(token)
        if payload and payload.get("jti"):
            with token_blacklist_lock:
                token_blacklist.add(payload["jti"])

    return jsonify({"status": "ok", "message": "Logged out"})


@app.route("/api/auth/change-password", methods=["POST"])
@require_auth
def auth_change_password():
    """Change password for the authenticated user."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not current_password or not new_password:
        return jsonify({"status": "error", "message": "Both passwords required"}), 400

    if len(new_password) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters"}), 400

    if len(new_password) > 128:
        return jsonify({"status": "error", "message": "Password too long"}), 400

    users = load_users()
    user = None
    for u in users:
        if u["username"].lower() == request.auth_user.lower():
            user = u
            break

    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if not check_password_hash(user["password_hash"], current_password):
        return jsonify({"status": "error", "message": "Current password is incorrect"}), 401

    user["password_hash"] = generate_password_hash(new_password, method="pbkdf2:sha256", salt_length=16)
    save_users(users)

    app.logger.info(f"[AUTH] Password changed for '{request.auth_user}'")
    return jsonify({"status": "ok", "message": "Password updated"})


INDEX = "siem-logs-*"

# ── Base filter: exclude Filebeat/Logstash internal logs ──
ISOLATED_HOSTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "isolated_hosts.json")

def get_isolated_hosts():
    """Returns a dict: {hostname: iso_timestamp_string, ...}"""
    if not os.path.exists(ISOLATED_HOSTS_FILE):
        return {}
    try:
        with open(ISOLATED_HOSTS_FILE, 'r') as f:
            data = json.load(f)
            # Migrate legacy list format to dict
            if isinstance(data, list):
                return {h: datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ") for h in data}
            return data if isinstance(data, dict) else {}
    except:
        return {}

def set_isolated_hosts(hosts_dict):
    """Persist a dict: {hostname: iso_timestamp_string, ...}"""
    try:
        with open(ISOLATED_HOSTS_FILE, 'w') as f:
            json.dump(hosts_dict, f, indent=2)
    except Exception as e:
        print(f"Error saving isolated hosts: {e}")

# Apply a global filter for fetching alerts/logs if desired, although keeping it pure for the injector is safer
BASE_FILTER = {
    "bool": {
        "must_not": [
            {"match": {"process.name": "filebeat"}},
            {"match": {"process.name": "logstash"}},
            {"match": {"process.name": "java"}},
            {"match": {"message": "pipeline"}},
            {"match": {"message": "harvester"}},
            {"match": {"message": "Registry file"}},
        ]
    }
}


# ── Severity classifier based on message content ──────────
def classify_severity(message, process_name=""):
    message = message.lower()
    process_name = process_name.lower()

    # ── CRITICAL: Authentication failures across all services ──
    if any(k in message for k in [
        # SSH
        "failed password", "authentication failure",
        "invalid user", "failed login", "sudo:auth",
        # FTP
        "fail login", "login incorrect", "530 login",
        # Telnet
        "login failure",
        # HTTP
        "401 unauthorized",
        # SMTP
        "relay denied", "smtp auth failure",
        # MySQL / Databases
        "access denied for user",
        # SMB
        "nt_status_logon_failure", "logon failure",
        # RDP
        "rdp login failed",
        # SNMP
        "authenticationfailure", "bad community string",
        # Generic
        "brute force", "break-in attempt",
        # Nmap / Port Scanning
        "nmap_null", "nmap_xmas", "nmap_synfin", "nmap_synrst", "nmap_rst", "nmap_udp",
        "port scan detected", "scan detected",
    ]):
        return "critical"

    # ── HIGH: Privilege escalation, web attacks, suspicious activity ──
    if any(k in message for k in [
        # SSH / Privilege
        "session opened for user root", "sudo:",
        "su:", "privilege", "cap_sys_admin",
        # HTTP attacks
        "403 forbidden", "directory traversal", "sql injection",
        "xss", "../", "command injection", "webshell",
        # DNS
        "zone transfer", "axfr",
        # SMTP
        "rejected", "relay access denied",
        # Network
        "reverse mapping", "buffer overflow", "segfault",
        "port scan", "nmap",
    ]):
        return "high"

    # ── MEDIUM: Successful logins, sessions, informational ──
    if any(k in message for k in [
        # SSH
        "session opened", "session closed",
        "accepted password", "new session",
        # FTP
        "ftp session opened", "ftp session closed",
        "230 login successful", "ftp connection from",
        # Telnet
        "login on",
        # HTTP
        "200 ok",
        # SMTP
        "warning:",
        # DNS
        "query denied",
        # Network
        "connection from", "connection closed",
        # Nmap
        "nmap_", "iptables",
    ]):
        return "medium"

    return "low"


# ── Format a raw ES hit into alert format ─────────────────
def format_alert(hit):
    src = hit["_source"]
    message = src.get("message", "")
    host = src.get("host", {})
    process = src.get("process", {})
    log = src.get("log", {})
    user = src.get("user", {})

    process_name = log.get("syslog", {}).get("appname",
                   process.get("args", [""])[0] if process.get("args") else "")

    severity = classify_severity(message, process_name)

    return {
        "id": hit["_id"],
        "timestamp": src.get("@timestamp", ""),
        "message": message,
        "hostname": host.get("hostname", host.get("name", "unknown")),
        "host_ip": host.get("ip", [""])[0] if host.get("ip") else "",
        "process": process_name,
        "command": process.get("command_line", ""),
        "user_id": user.get("id", ""),
        "severity": severity,
        "os": host.get("os", {}).get("name", ""),
        "pid": process.get("pid", ""),
    }


# ── GET /api/logs — recent logs with optional filters ─────
@app.route("/api/logs")
@require_auth
def get_logs():
    size = int(request.args.get("size", 10))
    offset = int(request.args.get("from", 0))
    date = request.args.get("date", "")
    severity = request.args.get("severity", "")
    hostname = request.args.get("hostname", "")
    process = request.args.get("process", "")

    must_clauses = [BASE_FILTER]

    if date:
        must_clauses.append({"range": {"@timestamp": {"gte": f"{date}T00:00:00.000Z", "lte": f"{date}T23:59:59.999Z"}}})

    if severity:
        sev_map = {
            "critical": [
                "Failed password", "BREAK-IN", "attack",
                "FAIL LOGIN", "Login incorrect", "530 Login",
                "LOGIN FAILURE", "401 Unauthorized",
                "relay denied", "Access denied for user",
                "NT_STATUS_LOGON_FAILURE", "authenticationFailure",
                "bad community string", "brute force",
            ],
            "high": [
                "sudo", "session opened for user root", "authentication failure",
                "403 Forbidden", "directory traversal", "SQL injection",
                "zone transfer", "AXFR", "rejected",
                "buffer overflow", "segfault", "port scan",
            ],
            "medium": [
                "session opened", "session closed", "Accepted",
                "FTP session opened", "230 Login successful",
                "LOGIN ON", "connection from", "warning:",
                "query denied",
            ],
        }
        if severity in sev_map:
            should_q = [{"match_phrase": {"message": p}} for p in sev_map[severity]]
            must_clauses.append({"bool": {"should": should_q, "minimum_should_match": 1}})

    if hostname:
        must_clauses.append({"term": {"host.hostname.keyword": hostname}})

    if process:
        must_clauses.append({"term": {"log.syslog.appname.keyword": process}})

    query = {"bool": {"must": must_clauses}}

    result = es.search(index=INDEX, body={
        "size": size,
        "from": offset,
        "sort": [{"@timestamp": "desc"}],
        "query": query
    })

    alerts = [format_alert(h) for h in result["hits"]["hits"]]
    total = result["hits"]["total"]["value"]
    return jsonify({"logs": alerts, "total": total})


# ── GET /api/logs/filters — distinct filter values ───────
@app.route("/api/logs/filters")
@require_auth
def get_log_filters():
    result = es.search(index=INDEX, body={
        "size": 0,
        "query": BASE_FILTER,
        "aggs": {
            "hostnames": {
                "terms": {"field": "host.hostname.keyword", "size": 50}
            },
            "processes": {
                "terms": {"field": "log.syslog.appname.keyword", "size": 50}
            }
        }
    })

    hostnames = [b["key"] for b in result["aggregations"]["hostnames"]["buckets"]]
    processes = [b["key"] for b in result["aggregations"]["processes"]["buckets"]]

    return jsonify({"hostnames": hostnames, "processes": processes})


# ── GET /api/logs/search — search logs ───────────────────
@app.route("/api/logs/search")
@require_auth
def search_logs():
    q = request.args.get("q", "")
    size = int(request.args.get("size", 50))
    date = request.args.get("date", "")
    severity = request.args.get("severity", "")
    hostname = request.args.get("hostname", "")
    process = request.args.get("process", "")

    must_clauses = []

    if date:
        must_clauses.append({"range": {"@timestamp": {"gte": f"{date}T00:00:00.000Z", "lte": f"{date}T23:59:59.999Z"}}})

    if q.strip():
        must_clauses.append({
            "simple_query_string": {
                "query": q.strip(),
                "fields": ["*"]
            }
        })

    if severity:
        sev_map = {
            "critical": [
                "Failed password", "BREAK-IN", "attack",
                "FAIL LOGIN", "Login incorrect", "530 Login",
                "LOGIN FAILURE", "401 Unauthorized",
                "relay denied", "Access denied for user",
                "NT_STATUS_LOGON_FAILURE", "authenticationFailure",
                "bad community string", "brute force",
            ],
            "high": [
                "sudo", "session opened for user root", "authentication failure",
                "403 Forbidden", "directory traversal", "SQL injection",
                "zone transfer", "AXFR", "rejected",
                "buffer overflow", "segfault", "port scan",
            ],
            "medium": [
                "session opened", "session closed", "Accepted",
                "FTP session opened", "230 Login successful",
                "LOGIN ON", "connection from", "warning:",
                "query denied",
            ],
        }
        if severity in sev_map:
            should_q = [{"match_phrase": {"message": p}} for p in sev_map[severity]]
            must_clauses.append({"bool": {"should": should_q, "minimum_should_match": 1}})

    if hostname:
        must_clauses.append({"term": {"host.hostname.keyword": hostname}})

    if process:
        must_clauses.append({"term": {"log.syslog.appname.keyword": process}})

    query = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}

    result = es.search(index=INDEX, body={
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "query": query
    })

    alerts = [format_alert(h) for h in result["hits"]["hits"]]
    total = result["hits"]["total"]["value"]
    return jsonify({"logs": alerts, "total": total})


# ── GET /api/stats — dashboard stats ─────────────────────
@app.route("/api/stats")
@require_auth
def get_stats():
    total = es.count(index=INDEX)["count"]

    ssh_fail = es.count(index=INDEX, body={
        "query": {"match": {"message": "Failed password"}}
    })["count"]

    sudo = es.count(index=INDEX, body={
        "query": {"match": {"message": "sudo"}}
    })["count"]

    root = es.count(index=INDEX, body={
        "query": {"match": {"message": "session opened for user root"}}
    })["count"]
    
    nmap_scans = es.count(index=INDEX, body={
        "query": {"bool": {"should": [
            {"match_phrase": {"message": "NMAP_NULL"}},
            {"match_phrase": {"message": "NMAP_XMAS"}},
            {"match_phrase": {"message": "NMAP_SYNFIN"}},
            {"match_phrase": {"message": "NMAP_RST"}},
            {"match_phrase": {"message": "NMAP_UDP"}},
        ], "minimum_should_match": 1}}
    })["count"]

    proc_agg = es.search(index=INDEX, body={
        "size": 0,
        "aggs": {
            "top_processes": {
                "terms": {
                    "field": "log.syslog.appname.keyword",
                    "size": 5
                }
            }
        }
    })

    top_processes = [
        {"name": b["key"], "count": b["doc_count"]}
        for b in proc_agg["aggregations"]["top_processes"]["buckets"]
    ]

    return jsonify({
        "total_logs": total,
        "ssh_failures": ssh_fail,
        "sudo_usage": sudo,
        "root_sessions": root,
        "nmap_scans": nmap_scans,
        "top_processes": top_processes
    })


# ── GET /api/alerts — only critical/high events ──────────
@app.route("/api/alerts")
@require_auth
def get_alerts():
    result = es.search(index=INDEX, body={
        "size": 100,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "should": [
                    # SSH
                    {"match": {"message": "Failed password"}},
                    {"match": {"message": "authentication failure"}},
                    {"match": {"message": "invalid user"}},
                    {"match": {"message": "session opened for user root"}},
                    {"match": {"message": "sudo"}},
                    # FTP
                    {"match_phrase": {"message": "FAIL LOGIN"}},
                    {"match_phrase": {"message": "Login incorrect"}},
                    {"match_phrase": {"message": "530 Login"}},
                    # Telnet
                    {"match_phrase": {"message": "LOGIN FAILURE"}},
                    # HTTP
                    {"match_phrase": {"message": "401 Unauthorized"}},
                    {"match_phrase": {"message": "403 Forbidden"}},
                    {"match_phrase": {"message": "SQL injection"}},
                    {"match_phrase": {"message": "directory traversal"}},
                    # SMTP
                    {"match_phrase": {"message": "relay denied"}},
                    {"match_phrase": {"message": "rejected"}},
                    # DNS
                    {"match_phrase": {"message": "zone transfer"}},
                    {"match_phrase": {"message": "AXFR"}},
                    # MySQL
                    {"match_phrase": {"message": "Access denied for user"}},
                    # SMB
                    {"match_phrase": {"message": "NT_STATUS_LOGON_FAILURE"}},
                    # SNMP
                    {"match_phrase": {"message": "authenticationFailure"}},
                    # Nmap / Port Scanning
                    {"match_phrase": {"message": "NMAP_NULL"}},
                    {"match_phrase": {"message": "NMAP_XMAS"}},
                    {"match_phrase": {"message": "NMAP_SYNFIN"}},
                    {"match_phrase": {"message": "NMAP_SYNRST"}},
                    {"match_phrase": {"message": "NMAP_RST"}},
                    {"match_phrase": {"message": "NMAP_UDP"}},
                ],
                "minimum_should_match": 1,
                "must_not": BASE_FILTER["bool"]["must_not"]
            }
        }
    })
    alerts = [format_alert(h) for h in result["hits"]["hits"]]
    return jsonify(alerts)


# ── GET /api/alerts/rules — rule-engine fired alerts ─────
@app.route("/api/alerts/rules", methods=["GET"])
@require_auth
def get_rule_alerts():
    with fired_alerts_lock:
        snapshot = list(fired_alerts)
    return jsonify({
        "status": "ok",
        "total": len(snapshot),
        "alerts": [a.to_dict() for a in snapshot]
    })


# ── GET /api/rules — list active rule definitions ─────────
@app.route("/api/rules", methods=["GET"])
@require_auth
def get_rules():
    return jsonify({
        "status": "ok",
        "rules": rule_engine.get_rules()
    })


# ── POST /api/rules/reload — hot-reload rules from disk ──
@app.route("/api/rules/reload", methods=["POST"])
@require_auth
def reload_rules():
    rule_engine.reload_rules()
    return jsonify({"status": "ok", "count": len(rule_engine.rules)})


# ── GET /api/alerts/correlated — correlation engine results ───────────────
@app.route("/api/alerts/correlated", methods=["GET"])
@require_auth
def get_correlated_alerts():
    with correlated_alerts_lock:
        snapshot = list(correlated_alerts)
    return jsonify({
        "status": "ok",
        "total": len(snapshot),
        "alerts": [a.to_dict() for a in snapshot]
    })


# ── GET /api/correlations — list active correlation rule definitions ───────
@app.route("/api/correlations", methods=["GET"])
@require_auth
def get_correlation_rules():
    return jsonify({
        "status": "ok",
        "rules": correlator.get_rules()
    })


# ── POST /api/correlations/reload — hot-reload correlation rules ──────────
@app.route("/api/correlations/reload", methods=["POST"])
@require_auth
def reload_correlation_rules():
    correlator.reload_rules()
    return jsonify({"status": "ok", "count": len(correlator.rules)})


# ── POST /api/correlations/run — immediately evaluate all correlation rules ─
@app.route("/api/correlations/run", methods=["POST"])
@require_auth
def run_correlations_now():
    """
    Manually triggers the correlation engine and stores results.
    Useful for testing without waiting for the 60s background loop.
    """
    global correlated_alerts
    try:
        new_alerts = correlator.evaluate_all_rules(es)
        if new_alerts:
            with correlated_alerts_lock:
                correlated_alerts = new_alerts + correlated_alerts
                correlated_alerts = correlated_alerts[:CORRELATED_ALERTS_MAX]
        return jsonify({
            "status": "ok",
            "fired": len(new_alerts),
            "total_stored": len(correlated_alerts),
            "alerts": [a.to_dict() for a in new_alerts]
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/correlations/debug/<rule_id> — inspect per-step ES hits ───────
@app.route("/api/correlations/debug/<rule_id>", methods=["GET"])
@require_auth
def debug_correlation_rule(rule_id):
    """
    Shows how many ES events match each sequence step for a given rule,
    broken down by host — so you can see how close a rule is to firing.
    """
    rule = next((r for r in correlator.get_rules() if r["id"] == rule_id), None)
    if not rule:
        return jsonify({"status": "error", "message": f"Rule '{rule_id}' not found"}), 404

    index         = rule.get("index", "siem-logs-*")
    group_by      = rule.get("group_by", "host.hostname")
    keyword_field = group_by if group_by.endswith(".keyword") else f"{group_by}.keyword"
    time_window_s = rule["time_window_seconds"]
    field         = rule.get("field", "message")
    time_range    = f"now-{time_window_s}s"

    steps_debug = []
    for i, step in enumerate(rule.get("sequence", [])):
        pattern  = step["pattern"]
        patterns = [p.strip() for p in pattern.split("|") if p.strip()]
        should   = [{"match_phrase": {field: p}} for p in patterns]

        try:
            resp = es.search(index=index, body={
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": time_range, "lt": "now"}}},
                            {"bool": {"should": should, "minimum_should_match": 1}}
                        ]
                    }
                },
                "aggs": {
                    "by_group": {
                        "terms": {"field": keyword_field, "size": 50, "min_doc_count": 1}
                    }
                }
            })
            buckets = resp.get("aggregations", {}).get("by_group", {}).get("buckets", [])
            steps_debug.append({
                "step":      i + 1,
                "pattern":   pattern,
                "min_count": step.get("min_count", 1),
                "total_hits": resp["hits"]["total"]["value"],
                "hosts": [
                    {"host": b["key"], "count": b["doc_count"], "qualifies": b["doc_count"] >= step.get("min_count", 1)}
                    for b in buckets
                ]
            })
        except Exception as e:
            steps_debug.append({"step": i + 1, "pattern": pattern, "error": str(e)})

    return jsonify({
        "status":           "ok",
        "rule_id":          rule_id,
        "rule_name":        rule["name"],
        "time_window_s":    time_window_s,
        "group_by":         group_by,
        "steps":            steps_debug
    })


# ── Cross-host correlation: score hosts that appear as attackers ──────────
def get_attacker_bonus_scores(es_client):
    """
    Searches all logs for source IPs that appear in attack messages
    (SSH failures, FTP failures, nmap scans) originating FROM other hosts.
    Returns a dict: { ip_address: bonus_score }
    These bonus points are added to the attacker host's risk score.
    """
    try:
        result = es_client.search(index=INDEX, body={
            "size": 500,
            "query": {
                "bool": {
                    "should": [
                        {"match_phrase": {"message": "Failed password"}},
                        {"match_phrase": {"message": "invalid user"}},
                        {"match_phrase": {"message": "authentication failure"}},
                        {"match_phrase": {"message": "FAIL LOGIN"}},
                        {"match_phrase": {"message": "NMAP_NULL"}},
                        {"match_phrase": {"message": "NMAP_XMAS"}},
                        {"match_phrase": {"message": "NMAP_SYNFIN"}},
                        {"match_phrase": {"message": "NMAP_RST"}},
                    ],
                    "minimum_should_match": 1,
                    "filter": [{"range": {"@timestamp": {"gte": "now-24h", "lt": "now"}}}]
                }
            },
            "_source": ["message", "host.ip"]
        })

        # Regex to extract source IP from log messages
        # Covers: "from 192.168.x.x", "rhost=::ffff:192.168.x.x", "SRC=192.168.x.x"
        ip_pattern = re.compile(
            r'from\s+(?:::ffff:)?([\d]{1,3}(?:\.[\d]{1,3}){3})'
            r'|rhost=(?:::ffff:)?([\d]{1,3}(?:\.[\d]{1,3}){3})'
            r'|SRC=([\d]{1,3}(?:\.[\d]{1,3}){3})'
        )

        attacker_hits = {}  # { source_ip: count }
        for hit in result["hits"]["hits"]:
            msg = hit["_source"].get("message", "")
            for match in ip_pattern.finditer(msg):
                src_ip = match.group(1) or match.group(2) or match.group(3)
                if src_ip:
                    attacker_hits[src_ip] = attacker_hits.get(src_ip, 0) + 1

        # Convert hit counts to bonus scores (25 points per attack event, capped at 200)
        bonus_scores = {}
        for ip, count in attacker_hits.items():
            bonus_scores[ip] = min(count * 25, 200)

        return bonus_scores
    except Exception as e:
        app.logger.error(f"[CrossHostCorrelation] {e}")
        return {}


# ── GET /api/endpoints — unique hosts aggregated from ES ──
@app.route("/api/endpoints/<hostname>/isolate", methods=["POST"])
@require_auth
def isolate_endpoint(hostname):
    try:
        hosts = get_isolated_hosts()
        if hostname not in hosts:
            hosts[hostname] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            set_isolated_hosts(hosts)
        return jsonify({"status": "ok", "message": f"Host {hostname} isolated", "isolated_at": hosts[hostname]})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/endpoints/<hostname>/deisolate", methods=["POST"])
@require_auth
def deisolate_endpoint(hostname):
    try:
        hosts = get_isolated_hosts()
        if hostname in hosts:
            del hosts[hostname]
            set_isolated_hosts(hosts)
        return jsonify({"status": "ok", "message": f"Host {hostname} deisolated"})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/endpoints", methods=["GET"])
@require_auth
def get_endpoints():
    try:
        # Fetch isolated hosts (dict: {hostname: iso_timestamp})
        isolated = get_isolated_hosts()

        query_must = []
        query_must.append(BASE_FILTER)
        query_must.append({"range": {"@timestamp": {"gte": "now-24h", "lt": "now"}}})
        endpoint_query = {"bool": {"must": query_must}}

        # --- Build sub-aggregations for each host ---
        host_aggs = {
            "ip": {
                "terms": {"field": "host.ip.keyword", "size": 1}
            },
            "os": {
                "terms": {"field": "host.os.name.keyword", "size": 1}
            },
            "os_version": {
                "terms": {"field": "host.os.version.keyword", "size": 1}
            },
            "os_platform": {
                "terms": {"field": "host.os.platform.keyword", "size": 1}
            },
            "arch": {
                "terms": {"field": "host.architecture.keyword", "size": 1}
            },
            "last_active": {
                "max": {"field": "@timestamp"}
            },
            # ── ECS-based severity aggregation ──
            # Primary: uses structured event.severity field (1=low, 2=med, 3=high, 4=critical)
            "ecs_severities": {
                "filters": {
                    "filters": {
                        "critical": {"term": {"event.severity": 4}},
                        "high":     {"term": {"event.severity": 3}},
                        "medium":   {"term": {"event.severity": 2}},
                        "low":      {"term": {"event.severity": 1}}
                    }
                }
            },
            # ── ECS: Authentication failures (structured) ──
            "auth_failures": {
                "filter": {
                    "bool": {
                        "must": [
                            {"term": {"event.outcome.keyword": "failure"}},
                            {"term": {"event.category.keyword": "authentication"}}
                        ]
                    }
                }
            },
            # ── ECS: Privilege escalation events ──
            "priv_escalations": {
                "filter": {
                    "bool": {
                        "should": [
                            {"term": {"event.action.keyword": "sudo_command"}},
                            {"term": {"event.action.keyword": "session_start"}}
                        ],
                        "minimum_should_match": 1,
                        "must": [
                            {"term": {"event.severity": 3}}
                        ]
                    }
                }
            },
            # ── Keyword fallback for legacy logs without ECS fields ──
            "legacy_severities": {
                "filters": {
                    "filters": {
                        "critical": {"bool": {"should": [
                            {"match_phrase": {"message": "Failed password"}},
                            {"match_phrase": {"message": "authentication failure"}},
                            {"match_phrase": {"message": "invalid user"}},
                            {"match_phrase": {"message": "FAIL LOGIN"}},
                            {"match_phrase": {"message": "LOGIN FAILURE"}},
                            {"match_phrase": {"message": "401 Unauthorized"}},
                            {"match_phrase": {"message": "relay denied"}},
                            {"match_phrase": {"message": "Access denied for user"}},
                            {"match_phrase": {"message": "NT_STATUS_LOGON_FAILURE"}},
                            {"match_phrase": {"message": "authenticationFailure"}},
                            {"match_phrase": {"message": "bad community string"}},
                            {"match_phrase": {"message": "NMAP_NULL"}},
                            {"match_phrase": {"message": "NMAP_XMAS"}},
                            {"match_phrase": {"message": "NMAP_SYNFIN"}},
                        ], "minimum_should_match": 1, "must_not": [
                            {"exists": {"field": "event.severity"}}
                        ]}},
                        "high": {"bool": {"should": [
                            {"match_phrase": {"message": "session opened for user root"}},
                            {"match_phrase": {"message": "sudo"}},
                            {"match_phrase": {"message": "403 Forbidden"}},
                            {"match_phrase": {"message": "directory traversal"}},
                            {"match_phrase": {"message": "SQL injection"}},
                            {"match_phrase": {"message": "zone transfer"}},
                            {"match_phrase": {"message": "AXFR"}},
                        ], "minimum_should_match": 1, "must_not": [
                            {"exists": {"field": "event.severity"}}
                        ]}},
                        "medium": {"bool": {"should": [
                            {"match_phrase": {"message": "session opened"}},
                            {"match_phrase": {"message": "Accepted password"}},
                            {"match_phrase": {"message": "FTP session opened"}},
                            {"match_phrase": {"message": "LOGIN ON"}},
                            {"match_phrase": {"message": "connection from"}},
                        ], "minimum_should_match": 1, "must_not": [
                            {"exists": {"field": "event.severity"}}
                        ]}}
                    }
                }
            }
        }

        resp = es.search(index=INDEX, body={
            "size": 0,
            "query": endpoint_query,
            "aggs": {
                "hosts": {
                    "terms": {
                        "field": "host.hostname.keyword",
                        "size": 200
                    },
                    "aggs": host_aggs
                }
            }
        })

        # ── Fetch cross-host attacker bonus scores once for all hosts ──
        attacker_bonus = get_attacker_bonus_scores(es)

        endpoints = []
        for bucket in resp["aggregations"]["hosts"]["buckets"]:
            hostname = bucket["key"]

            ip_obj = bucket.get("ip") or {}
            ip_buckets = ip_obj.get("buckets") or []

            os_obj = bucket.get("os") or {}
            os_buckets = os_obj.get("buckets") or []

            os_ver_obj = bucket.get("os_version") or {}
            os_ver_buckets = os_ver_obj.get("buckets") or []

            os_plat_obj = bucket.get("os_platform") or {}
            os_plat_buckets = os_plat_obj.get("buckets") or []

            arch_obj = bucket.get("arch") or {}
            arch_buckets = arch_obj.get("buckets") or []

            # ── Merge ECS + legacy severity counts ──
            ecs_sev = (bucket.get("ecs_severities") or {}).get("buckets") or {}
            leg_sev = (bucket.get("legacy_severities") or {}).get("buckets") or {}

            critical_count = ecs_sev.get("critical", {}).get("doc_count", 0) + leg_sev.get("critical", {}).get("doc_count", 0)
            high_count     = ecs_sev.get("high", {}).get("doc_count", 0)     + leg_sev.get("high", {}).get("doc_count", 0)
            medium_count   = ecs_sev.get("medium", {}).get("doc_count", 0)   + leg_sev.get("medium", {}).get("doc_count", 0)
            low_count      = ecs_sev.get("low", {}).get("doc_count", 0)

            # ── ECS-specific counters ──
            auth_failures_count  = (bucket.get("auth_failures") or {}).get("doc_count", 0)
            priv_escalation_count = (bucket.get("priv_escalations") or {}).get("doc_count", 0)

            # ── Threshold-based status detection ──
            # Compromised: > 5 critical events OR > 10 auth failures
            # At Risk:     > 2 critical events OR > 5 high events OR > 5 auth failures
            # Healthy:     below all thresholds
            if critical_count > 5 or auth_failures_count > 10:
                status = "Compromised"
            elif critical_count > 2 or high_count > 5 or auth_failures_count > 5:
                status = "At Risk"
            else:
                status = "Healthy"

            # ── Determine policy based on status ──
            if hostname in isolated:
                status = "Isolated"
                policy = "Isolated (Network Blocked)"
                isolated_at = isolated[hostname]
            else:
                isolated_at = None
                if status == "Compromised":
                    policy = "Isolate & Investigate"
                elif status == "At Risk":
                    policy = "Enhanced Monitoring"
                else:
                    policy = "Standard Protection"

            # ── Risk score (for display — sum of weighted counts) ──
            base_score = (critical_count * 50) + (high_count * 15) 
            # ── Cross-host correlation bonus ──
            # If this host's IP appears as an attacker in other hosts' logs,
            # add bonus points to reflect its offensive activity
            host_ips = [b["key"] for b in ip_buckets] if ip_buckets else []
            cross_host_bonus = max(attacker_bonus.get(ip, 0) for ip in host_ips) if host_ips else 0
            risk_score = base_score + cross_host_bonus

            # Build OS string with version
            os_name = os_buckets[0]["key"] if os_buckets else ""
            os_version = os_ver_buckets[0]["key"] if os_ver_buckets else ""
            os_full = f"{os_name} {os_version}".strip() if os_name else ""

            # Get last active timestamp
            last_active_obj = bucket.get("last_active") or {}
            last_active_ms = last_active_obj.get("value", None)
            last_active_str = ""
            if last_active_ms is not None:
                last_active_str = last_active_obj.get("value_as_string", "")

            endpoints.append({
                "hostname": hostname,
                "ip": ip_buckets[0]["key"] if ip_buckets else "",
                "os": os_full or os_name,
                "os_platform": os_plat_buckets[0]["key"] if os_plat_buckets else "",
                "architecture": arch_buckets[0]["key"] if arch_buckets else "",
                "last_active": last_active_str,
                "event_count": bucket["doc_count"],
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "auth_failures": auth_failures_count,
                "priv_escalations": priv_escalation_count,
                "risk_score": risk_score,
                "cross_host_bonus": cross_host_bonus,
                "status": status,
                "policy": policy,
                "isolated_at": isolated_at
            })

        # Sort: Isolated first, then Compromised, then At Risk, then Healthy
        status_order = {"Isolated": 0, "Compromised": 1, "At Risk": 2, "Healthy": 3}
        endpoints.sort(key=lambda ep: (status_order.get(ep["status"], 4), -ep["event_count"]))

        return jsonify({"status": "ok", "endpoints": endpoints})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/hosts — list of unique hosts with log counts ─────
@app.route("/api/hosts", methods=["GET"])
@require_auth
def get_hosts():
    try:
        resp = es.search(index=INDEX, body={
            "size": 0,
            "query": BASE_FILTER,
            "aggs": {
                "hosts": {
                    "terms": {
                        "field": "host.hostname.keyword",
                        "size": 200,
                        "order": {"_count": "desc"}
                    }
                }
            }
        })

        hosts = [
            {"hostname": b["key"], "log_count": b["doc_count"]}
            for b in resp["aggregations"]["hosts"]["buckets"]
        ]

        return jsonify({"status": "ok", "hosts": hosts})
    except Exception as e:
        return jsonify({"status": "error", "hosts": [], "message": str(e)}), 500


# ── GET /api/logs/host/<hostname> — logs for a specific host ──
@app.route("/api/logs/host/<hostname>", methods=["GET"])
@require_auth
def get_host_logs(hostname):
    size = int(request.args.get("size", 100))
    event_type = request.args.get("event_type", None)

    query = {
        "bool": {
            "must": [
                {"term": {"host.hostname.keyword": hostname}}
            ],
            "must_not": BASE_FILTER["bool"]["must_not"]
        }
    }

    if event_type:
        query["bool"]["must"].append({"term": {"event.type.keyword": event_type}})

    try:
        result = es.search(index=INDEX, body={
            "size": size,
            "sort": [{"@timestamp": "desc"}],
            "query": query,
            "aggs": {
                "severities": {
                    "terms": {"field": "message", "size": 0}
                },
                "event_types": {
                    "terms": {"field": "event.type.keyword", "size": 20}
                }
            }
        })

        logs = [format_alert(h) for h in result["hits"]["hits"]]
        total = result["hits"]["total"]["value"]

        # Build severity counts from logs
        sev_counts = {}
        for log in logs:
            s = log["severity"]
            sev_counts[s] = sev_counts.get(s, 0) + 1
        severities = [{"severity": k, "count": v} for k, v in sev_counts.items()]

        event_types = [
            {"type": b["key"], "count": b["doc_count"]}
            for b in result.get("aggregations", {}).get("event_types", {}).get("buckets", [])
        ]

        return jsonify({
            "logs": logs,
            "total": total,
            "severities": severities,
            "event_types": event_types
        })
    except Exception as e:
        return jsonify({"logs": [], "total": 0, "severities": [], "event_types": [], "error": str(e)})

def _abbreviate_isp(isp, country=""):
    if not isp:
        return "–"
    # Remove common suffixes
    for suffix in [
        " Co., Limited", " Co., Ltd.", " Co.,Ltd",
        " Co. Limited", " Co. Ltd.", " Technologies",
        " Technology", " Communications", " Telecom",
        " Network", " Networks", " Internet",
        " Services", " Solutions", " Systems",
        " Corporation", " Corp.", " Corp",
        " Limited", " Ltd.", " Ltd",
        " Inc.", " Inc", " LLC", " LLP",
        " GmbH", " S.A.", " B.V.",
    ]:
        isp = isp.replace(suffix, "")

    # Take first two meaningful words max
    words = [w for w in isp.split() if len(w) > 1]
    short = "-".join(words[:2]).upper()

    # Append country code
    if country:
        short = f"{short}-{country}"

    return short[:20]  # cap at 20 chars

# ── GET /api/threat/lookup/<ip> — single IP reputation lookup ─────────────
@app.route("/api/threat/lookup/<ip>", methods=["GET"])
@require_auth
def lookup_ip(ip):
    try:
        resp = http_requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True
            },
            timeout=10
        )
        data = resp.json().get("data", {})

        # Reports breakdown by time window
        reports = data.get("reports", [])
        now = datetime.utcnow()
        reports_30 = sum(1 for r in reports if r.get("reportedAt") and
                        (now - datetime.fromisoformat(r["reportedAt"].replace("Z",""))).days <= 30)
        reports_60 = sum(1 for r in reports if r.get("reportedAt") and
                        (now - datetime.fromisoformat(r["reportedAt"].replace("Z",""))).days <= 60)
        reports_90 = len(reports)

        # ISP abbreviation
        isp_full = data.get("isp", "")
        isp_short = _abbreviate_isp(isp_full, data.get("countryCode", ""))

        return jsonify({
            "status": "ok",
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", ""),
            "city": data.get("city", "") or "",
            "isp": isp_full,
            "isp_short": isp_short,
            "domain": data.get("domain", ""),
            "total_reports": data.get("totalReports", 0),
            "reports_30d": reports_30,
            "reports_60d": reports_60,
            "reports_90d": reports_90,
            "last_reported": data.get("lastReportedAt", ""),
            "is_whitelisted": data.get("isWhitelisted", False),
            "usage_type": data.get("usageType", ""),
            "is_tor": data.get("isTor", False),
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/threat/enrich — enrich all recent attacker IPs ───────────────
@app.route("/api/threat/enrich", methods=["GET"])
@require_auth
def enrich_attackers():
    try:
        # Pull unique source IPs from recent NMAP and brute force logs
        result = es.search(index=INDEX, body={
            "size": 0,
            "query": {
                "bool": {
                    "should": [
                        {"match_phrase": {"message": "NMAP_NULL"}},
                        {"match_phrase": {"message": "NMAP_XMAS"}},
                        {"match_phrase": {"message": "NMAP_RST"}},
                        {"match_phrase": {"message": "NMAP_SYNFIN"}},
                        {"match_phrase": {"message": "NMAP_UDP"}},
                        {"match_phrase": {"message": "Failed password"}},
                        {"match_phrase": {"message": "authentication failure"}},
                        {"match_phrase": {"message": "invalid user"}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "unique_messages": {
                    "terms": {
                        "field": "message.keyword",
                        "size": 50
                    }
                }
            }
        })

        # Extract IPs from message field using regex
        import re
        ip_pattern = re.compile(r'SRC=([\d.]+)|from ([\d.]+)')
        seen_ips = set()

        # Also do a direct search for raw messages to extract IPs
        raw = es.search(index=INDEX, body={
            "size": 200,
            "query": {
                "bool": {
                    "should": [
                        {"match_phrase": {"message": "NMAP_NULL"}},
                        {"match_phrase": {"message": "NMAP_XMAS"}},
                        {"match_phrase": {"message": "NMAP_RST"}},
                        {"match_phrase": {"message": "Failed password"}},
                        {"match_phrase": {"message": "invalid user"}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "_source": ["message"]
        })

        for hit in raw["hits"]["hits"]:
            msg = hit["_source"].get("message", "")
            for match in ip_pattern.finditer(msg):
                ip = match.group(1) or match.group(2)
                if ip:
                    seen_ips.add(ip)

        # Filter out private/local IPs
        def is_private(ip):
            import ipaddress
            try:
                return ipaddress.ip_address(ip).is_private
            except:
                return True

        public_ips = [ip for ip in seen_ips if not is_private(ip)]

        # Limit to 10 to avoid burning API quota
        public_ips = public_ips[:10]

        enriched = []
        for ip in public_ips:
            try:
                resp = http_requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={
                        "Key": ABUSEIPDB_API_KEY,
                        "Accept": "application/json"
                    },
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                    },
                    timeout=10
                )
                data = resp.json().get("data", {})
                enriched.append({
                "ip": ip,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", ""),
                "city": data.get("city", "") or "",
                "isp": data.get("isp", ""),
                "isp_short": _abbreviate_isp(data.get("isp", ""), data.get("countryCode", "")),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", ""),
                "is_whitelisted": data.get("isWhitelisted", False),
                "usage_type": data.get("usageType", ""),
                "is_tor": data.get("isTor", False),
            })
            except:
                continue

        return jsonify({"status": "ok", "total": len(enriched), "results": enriched})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ── Background rule evaluation thread ────────────────────
def run_rule_engine():
    import time
    global fired_alerts
    while True:
        try:
            new_alerts = rule_engine.evaluate_all_rules(es)
            if new_alerts:
                with fired_alerts_lock:
                    fired_alerts = new_alerts + fired_alerts
                    fired_alerts = fired_alerts[:FIRED_ALERTS_MAX]
                app.logger.info(f"[RuleEngine] {len(new_alerts)} alert(s) stored.")
        except Exception as e:
            app.logger.error(f"[RuleEngine] {e}")
        time.sleep(60)


# ── Background correlation evaluation thread ─────────────────────────────
def run_correlator():
    import time
    global correlated_alerts
    while True:
        try:
            new_alerts = correlator.evaluate_all_rules(es)
            if new_alerts:
                with correlated_alerts_lock:
                    correlated_alerts = new_alerts + correlated_alerts
                    correlated_alerts = correlated_alerts[:CORRELATED_ALERTS_MAX]
                app.logger.info(f"[Correlator] {len(new_alerts)} correlated alert(s) stored.")
        except Exception as e:
            app.logger.error(f"[Correlator] {e}")
        time.sleep(60)


if __name__ == "__main__":
    rule_thread = threading.Thread(target=run_rule_engine, daemon=True)
    rule_thread.start()

    corr_thread = threading.Thread(target=run_correlator, daemon=True)
    corr_thread.start()

    app.run(host="0.0.0.0", port=5000, debug=True)
