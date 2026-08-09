"""
SENTINEL Platform - Flask Application

Includes:
- LEA registration + encrypted uploads
- Admin login with failed-login lockout + optional TOTP 2FA
- Session/inactivity configuration endpoints
- Tile-based dashboard APIs for OSINT, Analyzer, Intelligence Hub, Cases, AI Assistant
- Admin API/AI/SMTP management scaffolding
- CDR/IPDR CSV analysis on user-uploaded lawful evidence files
"""

import base64
import collections
import contextlib
import csv
import io
import json
import os
import re
import shlex
import subprocess
import threading
import time
import smtplib
import ssl
import shutil
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import mysql.connector
import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_from_directory,
    session,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret_change_this")
app.permanent_session_lifetime = timedelta(minutes=int(os.getenv("SESSION_TIMEOUT_MIN", "60")))

BASE_DIR = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXT = {"png", "jpg", "jpeg", "pdf"}
MAX_FILE_SIZE = 5 * 1024 * 1024

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "sentinel_db"),
}

# ─────────────────────────────────────────────
# ENCRYPTION
# ─────────────────────────────────────────────
_enc_key = os.getenv("ENCRYPTION_KEY")
if not _enc_key:
    _enc_key = Fernet.generate_key().decode()
    print("=" * 70)
    print("WARNING: No ENCRYPTION_KEY set. Temporary key generated for dev only.")
    print("Add this to .env to persist encrypted uploads/API keys across restarts:")
    print(f"ENCRYPTION_KEY={_enc_key}")
    print("=" * 70)

fernet = Fernet(_enc_key.encode())


def encrypt_text(plaintext: str | None) -> str | None:
    if plaintext is None:
        return None
    return fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_text(token: str | None) -> str:
    if not token:
        return ""
    try:
        return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        # Legacy/plain value fallback.
        return token


def encrypt_bytes(data: bytes) -> bytes:
    return fernet.encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    return fernet.decrypt(data)


def get_db():
    return mysql.connector.connect(**DB_CONFIG)


@contextlib.contextmanager
def db_conn():
    """Context manager — always closes connection, even on exception."""
    conn = get_db()
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def mysql_dt_to_aware(dt):
    if not dt:
        return None
    if dt.tzinfo:
        return dt
    return dt.replace(tzinfo=timezone.utc)


# ─────────────────────────────────────────────
# RATE LIMITER (in-memory, per IP, thread-safe)
# ─────────────────────────────────────────────
class _RateLimiter:
    """Sliding-window rate limiter. Default: 60 requests per 60 seconds per key."""

    def __init__(self):
        self._windows: dict[str, collections.deque] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str, max_requests: int = 60, window_seconds: int = 60) -> bool:
        now = time.monotonic()
        with self._lock:
            dq = self._windows.setdefault(key, collections.deque())
            cutoff = now - window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= max_requests:
                return False
            dq.append(now)
            return True


_rate_limiter = _RateLimiter()


def rate_limit(max_requests: int = 60, window_seconds: int = 60, per: str = "ip"):
    """Decorator: apply sliding-window rate limit to a route."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if per == "user":
                key = f"{f.__name__}:user:{session.get('user_id') or session.get('admin_id') or _client_ip()}"
            else:
                key = f"{f.__name__}:ip:{_client_ip()}"
            if not _rate_limiter.is_allowed(key, max_requests, window_seconds):
                return jsonify({"error": "Too many requests. Please slow down."}), 429
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ─────────────────────────────────────────────
# AUTH / SECURITY DECORATORS
# ─────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return wrapper


def user_required(f):
    """Decorator: require an authenticated user session."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_user"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return wrapper


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("is_admin"):
                return jsonify({"error": "Unauthorized"}), 401
            if roles and session.get("admin_role") not in roles:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)

        return wrapper

    return decorator


def mask_secret(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep:
        return "•" * len(value)
    return "•" * (len(value) - keep) + value[-keep:]


def get_setting(key: str, default: str = "") -> str:
    try:
        with db_conn() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT setting_value FROM app_settings WHERE setting_key=%s", (key,))
            row = cursor.fetchone()
        return row["setting_value"] if row else default
    except Exception:
        return default


def set_setting(key: str, value: str):
    with db_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO app_settings (setting_key, setting_value)
            VALUES (%s,%s)
            ON DUPLICATE KEY UPDATE setting_value=%s, updated_at=NOW()
            """,
            (key, value, value),
        )
        conn.commit()



def _client_ip():
    return (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()


def table_has_column(table: str, column: str) -> bool:
    try:
        conn = get_db(); cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s AND COLUMN_NAME=%s", (table, column))
        ok = bool(cursor.fetchone()); conn.close(); return ok
    except Exception:
        return False


def log_audit(action: str, description: str, old_value=None, new_value=None, actor_type="admin", actor_id=None):
    try:
        conn=get_db(); cursor=conn.cursor(); admin_id=session.get("admin_id") if actor_type=="admin" else None
        if table_has_column("activity_log","old_value"):
            cursor.execute("INSERT INTO activity_log (admin_id, action, description, old_value, new_value, ip_address, actor_type, actor_id, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW())", (admin_id, action, description, json.dumps(old_value, default=str) if old_value is not None else None, json.dumps(new_value, default=str) if new_value is not None else None, _client_ip(), actor_type, actor_id or session.get("admin_id") or session.get("user_id")))
        else:
            cursor.execute("INSERT INTO activity_log (admin_id, action, description, created_at) VALUES (%s,%s,%s,NOW())", (admin_id, action, description))
        conn.commit(); conn.close()
    except Exception as exc:
        print(f"audit log failed: {exc}")


def _norm_header(value):
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _normalize_row(row):
    return {_norm_header(k): ("" if v is None else str(v).strip()) for k, v in (row or {}).items()}


def _json_clean(row):
    out={}
    for k,v in (row or {}).items():
        out[k]=v.isoformat() if hasattr(v,"isoformat") else v
    return out

def log_activity(admin_id, action: str, description: str):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO activity_log (admin_id, action, description, created_at)
            VALUES (%s,%s,%s,NOW())
            """,
            (admin_id, action, description),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"activity log failed: {exc}")


# ─────────────────────────────────────────────
# PAGE ROUTES
# ─────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")


@app.route("/admin")
def admin_page():
    return render_template("admin.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/analysis")
@app.route("/cdr-analysis")
def cdr_analysis_page():
    """Google Sheets-style CDR / IPDR spreadsheet analysis interface."""
    return render_template("cdr_analysis.html")


# ─────────────────────────────────────────────
# PUBLIC TILE CATALOGS
# ─────────────────────────────────────────────
OSINT_TOOLS = [
    {"code": "mobile_lookup", "name": "Mobile Lookup", "icon": "📱", "category": "phone", "credits": 2, "status": "active", "description": "Lookup mobile number intelligence"},
    {"code": "email_lookup", "name": "Email Lookup", "icon": "✉️", "category": "email", "credits": 2, "status": "upcoming", "description": "Lookup email intelligence"},
    {"code": "username_lookup", "name": "Username Lookup", "icon": "👤", "category": "identity", "credits": 2, "status": "upcoming", "description": "Search public username footprint"},
    {"code": "vehicle_lookup", "name": "Vehicle Lookup", "icon": "🚗", "category": "registry", "credits": 3, "status": "upcoming", "description": "Vehicle registration intelligence"},
    {"code": "ip_lookup", "name": "IP Lookup", "icon": "🌐", "category": "network", "credits": 2, "status": "upcoming", "description": "IP reputation and geo intel"},
    {"code": "domain_lookup", "name": "Domain Lookup", "icon": "◎", "category": "domain", "credits": 2, "status": "upcoming", "description": "WHOIS, DNS and infrastructure"},
    {"code": "social_media_lookup", "name": "Social Media Lookup", "icon": "🔗", "category": "social", "credits": 4, "status": "upcoming", "description": "Public social profile intelligence"},
    {"code": "breach_search", "name": "Data Breach Search", "icon": "⚠️", "category": "breach", "credits": 4, "status": "upcoming", "description": "Breach and exposure indicators"},
    {"code": "reverse_image", "name": "Reverse Image Search", "icon": "🖼️", "category": "image", "credits": 3, "status": "upcoming", "description": "Image intelligence workflow"},
    {"code": "address_osint", "name": "Address OSINT", "icon": "📍", "category": "maps", "credits": 2, "status": "upcoming", "description": "Address and map intelligence"},
    {"code": "aadhaar_validator", "name": "Aadhaar Validation", "icon": "🪪", "category": "identity", "credits": 1, "status": "upcoming", "description": "Checksum/format validation only"},
    {"code": "universal_search", "name": "Universal Search", "icon": "🔎", "category": "multi", "credits": 5, "status": "upcoming", "description": "One search across enabled sources"},
]

ANALYZER_TOOLS = [
    {"code": "cdr_analysis", "name": "CDR Analysis", "icon": "📞", "category": "telecom", "credits": 10, "status": "upcoming", "description": "Analyze uploaded CDR CSV"},
    {"code": "ipdr_analysis", "name": "IPDR Analysis", "icon": "📶", "category": "telecom", "credits": 10, "status": "upcoming", "description": "Analyze uploaded IPDR CSV"},
    {"code": "bank_statement", "name": "Bank Statement Analysis", "icon": "🏦", "category": "financial", "credits": 15, "status": "upcoming", "description": "Transaction pattern analytics"},
    {"code": "call_pattern", "name": "Call Pattern Analysis", "icon": "📈", "category": "telecom", "credits": 8, "status": "upcoming", "description": "Detect calling anomalies"},
    {"code": "tower_dump", "name": "Tower Dump Analysis", "icon": "📡", "category": "telecom", "credits": 15, "status": "upcoming", "description": "Tower dump correlation"},
    {"code": "contact_correlation", "name": "Contact Correlation", "icon": "🕸️", "category": "graph", "credits": 8, "status": "upcoming", "description": "Find common contacts"},
    {"code": "communication_analysis", "name": "Communication Analysis", "icon": "💬", "category": "telecom", "credits": 8, "status": "upcoming", "description": "Communication graph and stats"},
    {"code": "timeline_analysis", "name": "Timeline Analysis", "icon": "🕒", "category": "timeline", "credits": 5, "status": "upcoming", "description": "Build investigation chronology"},
    {"code": "geo_analysis", "name": "Geo Analysis", "icon": "🗺️", "category": "mapping", "credits": 8, "status": "upcoming", "description": "Movement and location insights"},
]

AI_COMMANDS = [
    "Analyze this CDR",
    "Find common contacts",
    "Show suspect movement",
    "Generate investigation report",
    "Correlate CDR + IPDR + Bank Statement",
    "Summarize investigation findings",
    "Detect suspicious communication patterns",
]


@app.route("/api/dashboard/catalog", methods=["GET"])
def dashboard_catalog():
    """Dashboard catalog is DB-driven so Admin service enable/disable and
    credit edits sync immediately with the user dashboard."""
    osint_tools, analyzer_tools = OSINT_TOOLS, ANALYZER_TOOLS
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM services ORDER BY sort_order, id")
        rows = cursor.fetchall()
        conn.close()
        osint_tools, analyzer_tools = [], []
        analyzer_categories = {"telecom", "financial", "digital_forensics", "mapping", "graph", "timeline", "fraud", "analyzer"}
        for r in rows:
            item = {
                "id": r["id"],
                "code": r["code"],
                "name": r["name"],
                "icon": r.get("icon") or "🔧",
                "category": r.get("category") or "custom",
                "credits": int(r.get("credits_per_use") or 0),
                "credits_per_use": int(r.get("credits_per_use") or 0),
                "status": "upcoming" if r.get("status") == "upcoming" else ("active" if r.get("is_enabled") else "inactive"),
                "is_enabled": bool(r.get("is_enabled")),
                "is_free": bool(r.get("is_free")),
                "description": r.get("description") or "",
                "tool_category": r.get("tool_category") or "OSINT",
            }
            if r.get("visible_to_users") == 0:
                continue
            if not item["is_enabled"] and item["status"] != "upcoming":
                continue
            if r.get("maintenance_mode"):
                item["status"] = "maintenance"
            if item.get("tool_category") == "OSINT" or item["category"] == "osint" or item["code"] in {x["code"] for x in OSINT_TOOLS}:
                osint_tools.append(item)
            elif item.get("tool_category") == "Analyzer" or item["category"] in analyzer_categories or item["code"] in {"cdr_processor", "ipdr_analysis", "bank_statement", "call_pattern", "tower_dump", "contact_correlation", "communication_analysis", "timeline_analysis", "geo_analysis"}:
                analyzer_tools.append(item)
            else:
                osint_tools.append(item)
    except Exception as exc:
        print(f"dashboard catalog DB fallback: {exc}")

    return jsonify({
        "tabs": ["OSINT Lookup", "Analyzer", "Intelligence Hub", "Case Management", "AI Assistant"],
        "osint_tools": osint_tools,
        "analyzer_tools": analyzer_tools,
        "ai_commands": AI_COMMANDS,
    })


@app.route("/api/intelligence/summary", methods=["GET"])
def intelligence_summary():
    # Demo/dashboard scaffolding. Replace with live DB aggregations as integrations mature.
    return jsonify(
        {
            "stats": {
                "active_cases": 12,
                "todays_searches": 248,
                "high_risk_hits": 17,
                "telecom_queries": 96,
                "financial_queries": 54,
                "threat_score": 87,
            },
            "recent_searches": [
                {"query": "+91 9876543210", "type": "Mobile Lookup", "time": "2 mins ago"},
                {"query": "DL8CAX1234", "type": "Vehicle Lookup", "time": "15 mins ago"},
                {"query": "user@example.com", "type": "Email OSINT", "time": "1 hour ago"},
            ],
            "watchlist_hits": [
                {"label": "Number found in watchlist", "severity": "high", "detail": "Possible fraudster"},
                {"label": "Domain associated with suspicious IP", "severity": "medium", "detail": "Source: threat feed"},
            ],
            "live_feed": [
                {"tag": "BREACH", "text": "Email found in data breach", "source": "Breach database", "time": "2 mins ago"},
                {"tag": "MATCH", "text": "Domain associated with suspicious IP", "source": "Threat intel", "time": "10 mins ago"},
                {"tag": "INFO", "text": "New OSINT source added", "source": "Admin", "time": "18 mins ago"},
                {"tag": "ALERT", "text": "Multiple failed login attempts", "source": "Security", "time": "23 mins ago"},
            ],
        }
    )


# ─────────────────────────────────────────────
# SITE CONTENT
# ─────────────────────────────────────────────
@app.route("/api/site-content", methods=["GET"])
def get_site_content():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT setting_value FROM app_settings WHERE setting_key='site_content'")
    row = cursor.fetchone()
    conn.close()
    if not row or not row["setting_value"]:
        return jsonify({})
    return jsonify(json.loads(row["setting_value"]))


@app.route("/api/admin/site-content", methods=["POST"])
@admin_required
def save_site_content():
    content = request.json or {}
    set_setting("site_content", json.dumps(content))
    log_activity(session.get("admin_id"), "site_content_update", f"{session.get('admin_name')} updated landing page content ({len(content)} fields)")
    return jsonify({"success": True})


# ─────────────────────────────────────────────
# LEA REGISTRATION
# ─────────────────────────────────────────────
@app.route("/api/lea/register", methods=["POST"])
def lea_register():
    form = request.form
    required = ["full_name", "phone", "department", "designation", "service_id", "unit", "jurisdiction"]
    for field in required:
        if not form.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    gov_id = request.files.get("gov_id")
    dept_id = request.files.get("dept_id")
    if not gov_id or not dept_id:
        return jsonify({"error": "Both ID documents are required"}), 400
    for uploaded in (gov_id, dept_id):
        if not allowed_file(uploaded.filename):
            return jsonify({"error": "Only JPG, PNG, PDF files allowed"}), 400

    app_uuid = uuid.uuid4().hex[:10]
    gov_id_filename = f"{app_uuid}_govid_{secure_filename(gov_id.filename)}.enc"
    dept_id_filename = f"{app_uuid}_deptid_{secure_filename(dept_id.filename)}.enc"

    gov_id_bytes = gov_id.read()
    dept_id_bytes = dept_id.read()
    if len(gov_id_bytes) > MAX_FILE_SIZE or len(dept_id_bytes) > MAX_FILE_SIZE:
        return jsonify({"error": "File too large (max 5MB)"}), 400

    with open(os.path.join(UPLOAD_FOLDER, gov_id_filename), "wb") as f:
        f.write(encrypt_bytes(gov_id_bytes))
    with open(os.path.join(UPLOAD_FOLDER, dept_id_filename), "wb") as f:
        f.write(encrypt_bytes(dept_id_bytes))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO lea_applications
        (full_name, phone, official_email, department, designation, service_id,
         unit, jurisdiction, notes, id_proof_path, dept_id_path, status)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending')
        """,
        (
            form["full_name"],
            form["phone"],
            form.get("official_email", ""),
            form["department"],
            form["designation"],
            form["service_id"],
            form["unit"],
            form["jurisdiction"],
            encrypt_text(form.get("notes", "")),
            gov_id_filename,
            dept_id_filename,
        ),
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()

    application_id = f"LEA-{datetime.now().year}-{new_id:04d}"
    return jsonify({"success": True, "application_id": application_id}), 200




# ─────────────────────────────────────────────
# USER AUTH (development phase)
# Public user login page is /login. In production, make /dashboard user_required
# and add email OTP/reset delivery through configured SMTP.
# ─────────────────────────────────────────────
@app.route("/api/user/login", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=300, per="ip")  # 10 attempts / 5 min per IP
def user_login():
    data = request.json or {}
    identifier = (data.get("identifier") or data.get("phone") or data.get("email") or "").strip()
    password = data.get("password", "")
    ip = _client_ip()

    if not identifier or not password:
        return jsonify({"error": "Phone/email and password are required"}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # Support both newer schemas with official_email and older schemas without it.
    try:
        cursor.execute(
            """
            SELECT id, phone, name, department, official_email, password_hash, credits, status, twofa_enabled, twofa_secret,
                   COALESCE(failed_login_count, 0) AS failed_login_count,
                   locked_until
            FROM bot_users
            WHERE phone=%s OR official_email=%s
            LIMIT 1
            """,
            (identifier, identifier),
        )
    except mysql.connector.Error:
        cursor.execute(
            """
            SELECT id, phone, name, department, NULL AS official_email, password_hash, credits, status,
                   0 AS twofa_enabled, NULL AS twofa_secret,
                   0 AS failed_login_count, NULL AS locked_until
            FROM bot_users
            WHERE phone=%s
            LIMIT 1
            """,
            (identifier,),
        )

    user = cursor.fetchone()

    if not user:
        conn.close()
        log_activity(None, "failed_login", f"Unknown identifier attempted login from {ip}: {identifier[:32]}")
        return jsonify({"error": "User not found. Please register or wait for LEA approval."}), 404

    # Lockout check
    limit = int(get_setting("user_failed_login_limit", os.getenv("FAILED_LOGIN_LIMIT", "5")))
    lockout_hours = int(get_setting("lockout_hours", os.getenv("LOCKOUT_HOURS", "2")))
    locked_until = mysql_dt_to_aware(user.get("locked_until"))
    if locked_until and locked_until > now_utc():
        remaining = int((locked_until - now_utc()).total_seconds())
        conn.close()
        return jsonify({"error": "Account locked due to too many failed attempts.", "locked": True, "remaining_seconds": remaining}), 423

    if user.get("status") != "approved":
        conn.close()
        return jsonify({"error": f"Account is {user.get('status')}. Access allowed only after approval."}), 403

    stored_hash = user.get("password_hash")
    dev_password = os.getenv("DEV_USER_PASSWORD", "dev123")

    password_ok = False
    if stored_hash:
        password_ok = check_password_hash(stored_hash, password)
    else:
        # Development convenience only. In production, force password setup/reset.
        password_ok = (password == dev_password)

    if not password_ok:
        failed_count = int(user.get("failed_login_count") or 0) + 1
        try:
            if failed_count >= limit:
                cursor.execute(
                    "UPDATE bot_users SET failed_login_count=%s, locked_until=DATE_ADD(NOW(), INTERVAL %s HOUR) WHERE id=%s",
                    (failed_count, lockout_hours, user["id"]),
                )
                conn.commit()
                conn.close()
                log_activity(user["id"], "user_account_locked", f"User {identifier} locked after {failed_count} failed attempts from {ip}")
                return jsonify({"error": f"Account locked for {lockout_hours} hours after too many failed attempts.", "locked": True}), 423
            cursor.execute("UPDATE bot_users SET failed_login_count=%s WHERE id=%s", (failed_count, user["id"]))
            conn.commit()
        except Exception:
            pass
        conn.close()
        log_activity(user["id"], "failed_login", f"Failed login for {identifier} from {ip} ({failed_count}/{limit})")
        return jsonify({"error": "Invalid credentials"}), 401

    if user.get("twofa_enabled"):
        otp = (data.get("otp") or "").strip()
        if not otp:
            conn.close()
            return jsonify({"error": "2FA code required", "twofa_required": True}), 401
        secret = decrypt_text(user.get("twofa_secret"))
        if not secret or not pyotp.TOTP(secret).verify(otp, valid_window=1):
            conn.close()
            return jsonify({"error": "Invalid 2FA code", "twofa_required": True}), 401

    # Successful login — reset counter
    try:
        cursor.execute("UPDATE bot_users SET failed_login_count=0, locked_until=NULL WHERE id=%s", (user["id"],))
        conn.commit()
    except Exception:
        pass
    conn.close()

    session.permanent = True
    session["is_user"] = True
    session["user_id"] = user["id"]
    session["user_phone"] = user["phone"]
    session["user_name"] = user.get("name") or "Operator"
    session["user_department"] = user.get("department") or ""
    session["user_login_at"] = datetime.utcnow().isoformat()

    log_activity(user["id"], "user_login", f"{user.get('name') or identifier} logged in from {ip}")

    return jsonify({
        "success": True,
        "redirect": "/dashboard",
        "user": {
            "id": user["id"],
            "phone": user["phone"],
            "name": user.get("name") or "Operator",
            "department": user.get("department") or "",
            "credits": user.get("credits", 0),
        },
    })


@app.route("/api/user/logout", methods=["POST"])
@user_required
def user_logout():
    log_activity(session.get("user_id"), "user_logout", f"{session.get('user_name', 'User')} logged out from {_client_ip()}")
    for key in ["is_user", "user_id", "user_phone", "user_name", "user_department", "user_login_at"]:
        session.pop(key, None)
    return jsonify({"success": True})


@app.route("/api/user/session", methods=["GET"])
def user_session():
    if not session.get("is_user"):
        return jsonify({"logged_in": False}), 401
    return jsonify({
        "logged_in": True,
        "user": {
            "id": session.get("user_id"),
            "phone": session.get("user_phone"),
            "name": session.get("user_name"),
            "department": session.get("user_department"),
        },
    })


@app.route("/api/user/password-reset/request", methods=["POST"])
def user_password_reset_request():
    # Development placeholder. Production should generate OTP, store hashed OTP + expiry,
    # and send only to government-authorized email domains through configured SMTP.
    identifier = (request.json or {}).get("identifier", "").strip()
    if not identifier:
        return jsonify({"error": "phone/email required"}), 400
    return jsonify({"success": True, "message": "Password reset flow placeholder. Configure SMTP in admin for production OTP emails."})


# ─────────────────────────────────────────────
# ADMIN AUTH + SECURITY
# ─────────────────────────────────────────────
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    otp = data.get("otp", "").strip()
    recovery_code = data.get("recovery_code", "").strip()

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin_users WHERE username=%s AND is_active=1", (username,))
    admin = cursor.fetchone()

    generic_error = {"error": "Invalid credentials"}
    limit = int(get_setting("failed_login_limit", os.getenv("FAILED_LOGIN_LIMIT", "3")))
    lockout_hours = int(get_setting("lockout_hours", os.getenv("LOCKOUT_HOURS", "2")))

    if not admin:
        conn.close()
        log_activity(None, "failed_login", f"Failed login attempt for unknown username: {username}")
        return jsonify(generic_error), 401

    locked_until = mysql_dt_to_aware(admin.get("locked_until"))
    if locked_until and locked_until > now_utc():
        remaining = int((locked_until - now_utc()).total_seconds())
        conn.close()
        log_activity(admin["id"], "locked_login_attempt", f"Locked account login blocked for {username}")
        return jsonify({"error": "Account locked", "locked": True, "remaining_seconds": remaining}), 423

    if not check_password_hash(admin["password_hash"], password):
        failed_count = int(admin.get("failed_login_count") or 0) + 1
        if failed_count >= limit:
            cursor.execute(
                "UPDATE admin_users SET failed_login_count=%s, locked_until=DATE_ADD(NOW(), INTERVAL %s HOUR) WHERE id=%s",
                (failed_count, lockout_hours, admin["id"]),
            )
            conn.commit()
            conn.close()
            log_activity(admin["id"], "account_locked", f"{username} locked after {failed_count} failed login attempts")
            return jsonify({"error": f"Account locked for {lockout_hours} hours", "locked": True}), 423
        cursor.execute("UPDATE admin_users SET failed_login_count=%s WHERE id=%s", (failed_count, admin["id"]))
        conn.commit()
        conn.close()
        log_activity(admin["id"], "failed_login", f"Failed login attempt for {username} ({failed_count}/{limit})")
        return jsonify(generic_error), 401

    if admin.get("twofa_enabled"):
        verified = False
        if otp and admin.get("twofa_secret"):
            verified = pyotp.TOTP(decrypt_text(admin["twofa_secret"])).verify(otp, valid_window=1)
        if not verified and recovery_code:
            # Recovery code hashes are stored as JSON list of hashes.
            try:
                hashes = json.loads(admin.get("recovery_codes_hash") or "[]")
                remaining_hashes = []
                for h in hashes:
                    if not verified and check_password_hash(h, recovery_code):
                        verified = True
                    else:
                        remaining_hashes.append(h)
                if verified:
                    cursor.execute("UPDATE admin_users SET recovery_codes_hash=%s WHERE id=%s", (json.dumps(remaining_hashes), admin["id"]))
                    conn.commit()
            except Exception:
                verified = False
        if not verified:
            conn.close()
            return jsonify({"error": "2FA code required", "twofa_required": True}), 401

    cursor.execute("UPDATE admin_users SET failed_login_count=0, locked_until=NULL, last_login_at=NOW() WHERE id=%s", (admin["id"],))
    conn.commit()
    conn.close()

    session.permanent = True
    session["is_admin"] = True
    session["admin_id"] = admin["id"]
    session["admin_name"] = admin["name"]
    session["admin_role"] = admin["role"]
    session["login_at"] = datetime.utcnow().isoformat()
    log_activity(admin["id"], "login", f"{admin['name']} logged in from {_client_ip()}")
    return jsonify({"success": True, "name": admin["name"], "role": admin["role"], "session_timeout_min": int(os.getenv("SESSION_TIMEOUT_MIN", "60"))})


@app.route("/api/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    log_activity(session.get("admin_id"), "logout", f"{session.get('admin_name')} logged out")
    session.clear()
    return jsonify({"success": True})


@app.route("/api/admin/session-info", methods=["GET"])
@admin_required
def session_info():
    login_at = session.get("login_at")
    timeout_min = int(get_setting("session_timeout_min", os.getenv("SESSION_TIMEOUT_MIN", "60")))
    inactivity_min = int(get_setting("inactivity_timeout_min", os.getenv("INACTIVITY_TIMEOUT_MIN", "15")))
    remaining = timeout_min * 60
    if login_at:
        try:
            start = datetime.fromisoformat(login_at)
            elapsed = (datetime.utcnow() - start).total_seconds()
            remaining = max(0, int(timeout_min * 60 - elapsed))
        except Exception:
            pass
    return jsonify({"session_remaining_seconds": remaining, "inactivity_timeout_seconds": inactivity_min * 60})


@app.route("/api/admin/2fa/setup", methods=["POST"])
@admin_required
def setup_2fa():
    admin_id = session.get("admin_id")
    secret = pyotp.random_base32()
    issuer = "SENTINEL"
    label = f"{issuer}:{session.get('admin_name','admin')}"
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE admin_users SET twofa_secret=%s WHERE id=%s", (encrypt_text(secret), admin_id))
    conn.commit()
    conn.close()
    log_activity(admin_id, "2fa_setup_started", f"{session.get('admin_name')} started 2FA setup")
    return jsonify({"success": True, "qr_data_uri": f"data:image/png;base64,{qr_b64}", "manual_secret": secret})


@app.route("/api/admin/2fa/enable", methods=["POST"])
@admin_required
def enable_2fa():
    otp = (request.json or {}).get("otp", "").strip()
    admin_id = session.get("admin_id")
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT twofa_secret FROM admin_users WHERE id=%s", (admin_id,))
    row = cursor.fetchone()
    if not row or not row.get("twofa_secret"):
        conn.close()
        return jsonify({"error": "Run setup first"}), 400
    secret = decrypt_text(row["twofa_secret"])
    if not pyotp.TOTP(secret).verify(otp, valid_window=1):
        conn.close()
        return jsonify({"error": "Invalid 2FA code"}), 400

    recovery_codes = [uuid.uuid4().hex[:10].upper() for _ in range(8)]
    recovery_hashes = [generate_password_hash(code) for code in recovery_codes]
    cursor.execute("UPDATE admin_users SET twofa_enabled=1, recovery_codes_hash=%s WHERE id=%s", (json.dumps(recovery_hashes), admin_id))
    conn.commit()
    conn.close()
    log_activity(admin_id, "2fa_enabled", f"{session.get('admin_name')} enabled 2FA")
    return jsonify({"success": True, "recovery_codes": recovery_codes})


@app.route("/api/admin/2fa/disable", methods=["POST"])
@admin_required
def disable_2fa():
    admin_id = session.get("admin_id")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE admin_users SET twofa_enabled=0, twofa_secret=NULL, recovery_codes_hash=NULL WHERE id=%s", (admin_id,))
    conn.commit()
    conn.close()
    log_activity(admin_id, "2fa_disabled", f"{session.get('admin_name')} disabled 2FA")
    return jsonify({"success": True})


# ─────────────────────────────────────────────
# ADMIN: LEA VERIFICATION QUEUE
# ─────────────────────────────────────────────
@app.route("/api/admin/lea/applications", methods=["GET"])
@admin_required
def list_lea_applications():
    status = request.args.get("status", "pending")
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    if status == "all":
        cursor.execute("SELECT * FROM lea_applications ORDER BY created_at DESC")
    else:
        cursor.execute("SELECT * FROM lea_applications WHERE status=%s ORDER BY created_at DESC", (status,))
    apps = cursor.fetchall()
    conn.close()
    for a in apps:
        a["application_id"] = f"LEA-{a['created_at'].year}-{a['id']:04d}"
        a["id_proof_url"] = f"/uploads/{a['id_proof_path']}"
        a["dept_id_url"] = f"/uploads/{a['dept_id_path']}"
        a["notes"] = decrypt_text(a.get("notes"))
        a["created_at"] = a["created_at"].isoformat()
        if a.get("reviewed_at"):
            a["reviewed_at"] = a["reviewed_at"].isoformat()
    return jsonify(apps)


@app.route("/api/admin/lea/applications/<int:app_id>/approve", methods=["POST"])
@admin_required
def approve_lea_application(app_id):
    data = request.json or {}
    free_credits = int(data.get("free_credits", os.getenv("DEFAULT_FREE_CREDITS", "20")))
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM lea_applications WHERE id=%s", (app_id,))
    application = cursor.fetchone()
    if not application:
        conn.close()
        return jsonify({"error": "Application not found"}), 404
    if application["status"] != "pending":
        conn.close()
        return jsonify({"error": f"Application already {application['status']}"}), 400

    phone = application["phone"]
    cursor.execute("SELECT id FROM bot_users WHERE phone=%s", (phone,))
    existing = cursor.fetchone()
    if existing:
        cursor.execute(
            """
            UPDATE bot_users SET status='approved', credits=credits+%s,
            name=%s, department=%s, lea_application_id=%s WHERE phone=%s
            """,
            (free_credits, application["full_name"], application["department"], app_id, phone),
        )
    else:
        cursor.execute(
            """
            INSERT INTO bot_users (phone, name, department, credits, status, lea_application_id)
            VALUES (%s,%s,%s,%s,'approved',%s)
            """,
            (phone, application["full_name"], application["department"], free_credits, app_id),
        )
    cursor.execute("UPDATE lea_applications SET status='approved', reviewed_by=%s, reviewed_at=NOW() WHERE id=%s", (session.get("admin_name"), app_id))
    cursor.execute("INSERT INTO credit_transactions (phone, type, amount, reason) VALUES (%s,'credit',%s,'lea_approval_bonus')", (phone, free_credits))
    conn.commit()
    conn.close()
    log_activity(session.get("admin_id"), "lea_approve", f"Approved LEA-{application['created_at'].year}-{app_id:04d} ({application['full_name']}) — {free_credits} credits granted")
    return jsonify({"success": True, "message": "Application approved", "phone": phone})


@app.route("/api/admin/lea/applications/<int:app_id>/reject", methods=["POST"])
@admin_required
def reject_lea_application(app_id):
    reason = (request.json or {}).get("reason", "Not specified")
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM lea_applications WHERE id=%s", (app_id,))
    application = cursor.fetchone()
    if not application:
        conn.close()
        return jsonify({"error": "Application not found"}), 404
    cursor.execute(
        "UPDATE lea_applications SET status='rejected', reviewed_by=%s, reviewed_at=NOW(), rejection_reason=%s WHERE id=%s",
        (session.get("admin_name"), reason, app_id),
    )
    conn.commit()
    conn.close()
    log_activity(session.get("admin_id"), "lea_reject", f"Rejected LEA-{application['created_at'].year}-{app_id:04d} ({application['full_name']}) — {reason}")
    return jsonify({"success": True, "message": "Application rejected"})


@app.route("/uploads/<filename>")
@admin_required
def serve_upload(filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.isfile(filepath):
        return jsonify({"error": "Not found"}), 404
    if filename.endswith(".enc"):
        with open(filepath, "rb") as f:
            decrypted = decrypt_bytes(f.read())
        original_name = filename[:-4]
        ext = original_name.rsplit(".", 1)[-1].lower()
        mimetypes = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "pdf": "application/pdf"}
        return Response(decrypted, mimetype=mimetypes.get(ext, "application/octet-stream"))
    return send_from_directory(UPLOAD_FOLDER, filename)


# ─────────────────────────────────────────────
# ADMIN: USERS, ACTIVITY, API/AI/SMTP MANAGEMENT
# ─────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
@admin_required
def list_users():
    search = request.args.get("search", "")
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    if search:
        cursor.execute(
            """
            SELECT id, phone, name, department, credits, status, block_reason, created_at, last_login_at, twofa_enabled
            FROM bot_users WHERE name LIKE %s OR phone LIKE %s ORDER BY created_at DESC LIMIT 100
            """,
            (f"%{search}%", f"%{search}%"),
        )
    else:
        cursor.execute("SELECT id, phone, name, department, credits, status, block_reason, created_at, last_login_at, twofa_enabled FROM bot_users ORDER BY created_at DESC LIMIT 100")
    users = cursor.fetchall()
    conn.close()
    for u in users:
        u["created_at"] = u["created_at"].isoformat() if u.get("created_at") else None
        if u.get("last_login_at"):
            u["last_login_at"] = u["last_login_at"].isoformat()
    return jsonify(users)


@app.route("/api/admin/users/<int:user_id>/credits", methods=["POST"])
@admin_required
def modify_credits(user_id):
    data = request.json or {}
    action = data.get("action")
    amount = int(data.get("amount", 0))
    reason = data.get("reason", "admin_adjustment")
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM bot_users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    if action == "add":
        new_val = user["credits"] + amount
        txn_type, txn_amt = "credit", amount
    elif action == "deduct":
        new_val = max(0, user["credits"] - amount)
        txn_type, txn_amt = "debit", amount
    elif action == "set":
        new_val = amount
        txn_type, txn_amt = ("credit", amount - user["credits"]) if amount >= user["credits"] else ("debit", user["credits"] - amount)
    else:
        conn.close()
        return jsonify({"error": "Invalid action"}), 400
    cursor.execute("UPDATE bot_users SET credits=%s WHERE id=%s", (new_val, user_id))
    cursor.execute("INSERT INTO credit_transactions (phone, type, amount, reason) VALUES (%s,%s,%s,%s)", (user["phone"], txn_type, abs(txn_amt), f"{reason} (by {session.get('admin_name')})"))
    conn.commit()
    conn.close()
    log_activity(session.get("admin_id"), "credit_adjust", f"{action} {amount} credits for {user['name']} ({user['phone']}) — {reason}. New balance: {new_val}")
    return jsonify({"success": True, "new_balance": new_val})


@app.route("/api/admin/users/<int:user_id>/status", methods=["POST"])
@admin_required
def update_user_status(user_id):
    data = request.json or {}
    status = data.get("status")
    reason = data.get("reason", "")
    if status not in {"pending", "approved", "rejected", "blocked", "inactive"}:
        return jsonify({"error": "Invalid status"}), 400
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM bot_users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    cursor.execute("UPDATE bot_users SET status=%s, block_reason=%s WHERE id=%s", (status, reason if status == "blocked" else None, user_id))
    conn.commit()
    conn.close()
    log_activity(session.get("admin_id"), "user_status_update", f"Set {user['phone']} status to {status}. {reason}")
    return jsonify({"success": True})


@app.route("/api/admin/users/<int:user_id>/password-reset", methods=["POST"])
@admin_required
def admin_password_reset(user_id):
    # Scaffold for OTP/email flow. Do not expose passwords. Generate a reset token/OTP and send to verified govt email.
    log_activity(session.get("admin_id"), "password_reset_requested", f"Password reset initiated for user_id={user_id}")
    return jsonify({"success": True, "message": "Password reset OTP should be sent to the user's government-authorized email."})


@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) AS c FROM bot_users")
    total_users = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) AS c FROM bot_users WHERE status='approved'")
    active_users = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) AS c FROM lea_applications WHERE status='pending'")
    pending_apps = cursor.fetchone()["c"]
    cursor.execute("SELECT COALESCE(SUM(amount),0) AS c FROM credit_transactions WHERE reason='razorpay'")
    total_credits_sold_txn = cursor.fetchone()["c"]
    conn.close()
    return jsonify({"total_users": total_users, "active_users": active_users, "pending_lea_applications": pending_apps, "credits_sold_via_razorpay": total_credits_sold_txn})


@app.route("/api/admin/activity", methods=["GET"])
@admin_required
def get_activity_log():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT al.*, au.name AS admin_name
        FROM activity_log al LEFT JOIN admin_users au ON al.admin_id = au.id
        ORDER BY al.created_at DESC LIMIT 100
        """
    )
    logs = cursor.fetchall()
    conn.close()
    for l in logs:
        l["created_at"] = l["created_at"].isoformat()
    return jsonify(logs)


@app.route("/api/admin/integrations", methods=["GET", "POST"])
@admin_required
def integrations_collection():
    if request.method == "GET":
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM integrations ORDER BY category, name")
        rows = cursor.fetchall()
        conn.close()
        for r in rows:
            r["api_key_masked"] = mask_secret(decrypt_text(r.pop("api_key", None)))
            r["api_secret_masked"] = mask_secret(decrypt_text(r.pop("api_secret", None)))
            r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
            r["updated_at"] = r["updated_at"].isoformat() if r.get("updated_at") else None
        return jsonify(rows)

    data = request.json or {}
    if not data.get("name") or not data.get("category"):
        return jsonify({"error": "name and category are required"}), 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO integrations
        (name, category, description, base_url, api_key, api_secret, config_json, usage_limit_daily, credits_per_call, is_enabled, show_on_dashboard)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            data["name"],
            data["category"],
            data.get("description", ""),
            data.get("base_url", ""),
            encrypt_text(data.get("api_key", "")),
            encrypt_text(data.get("api_secret", "")),
            json.dumps(data.get("config", {})),
            int(data.get("usage_limit_daily", 0) or 0),
            int(data.get("credits_per_call", 0) or 0),
            1 if data.get("is_enabled") else 0,
            1 if data.get("show_on_dashboard", True) else 0,
        ),
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    log_activity(session.get("admin_id"), "integration_create", f"Added API integration '{data['name']}'")
    return jsonify({"success": True, "id": new_id})


@app.route("/api/admin/integrations/<int:integration_id>", methods=["PUT", "DELETE"])
@admin_required
def integration_item(integration_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM integrations WHERE id=%s", (integration_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "Integration not found"}), 404
    if request.method == "DELETE":
        cursor.execute("DELETE FROM integrations WHERE id=%s", (integration_id,))
        conn.commit()
        conn.close()
        log_activity(session.get("admin_id"), "integration_delete", f"Deleted API integration '{existing['name']}'")
        return jsonify({"success": True})

    data = request.json or {}
    new_api_key = encrypt_text(data["api_key"]) if data.get("api_key") else existing["api_key"]
    new_api_secret = encrypt_text(data["api_secret"]) if data.get("api_secret") else existing["api_secret"]
    cursor.execute(
        """
        UPDATE integrations SET name=%s, category=%s, description=%s, base_url=%s,
        api_key=%s, api_secret=%s, config_json=%s, usage_limit_daily=%s, credits_per_call=%s,
        is_enabled=%s, show_on_dashboard=%s WHERE id=%s
        """,
        (
            data.get("name", existing["name"]),
            data.get("category", existing["category"]),
            data.get("description", existing["description"]),
            data.get("base_url", existing["base_url"]),
            new_api_key,
            new_api_secret,
            json.dumps(data.get("config", json.loads(existing.get("config_json") or "{}"))),
            int(data.get("usage_limit_daily", existing.get("usage_limit_daily") or 0)),
            int(data.get("credits_per_call", existing.get("credits_per_call") or 0)),
            1 if data.get("is_enabled") else 0,
            1 if data.get("show_on_dashboard", True) else 0,
            integration_id,
        ),
    )
    conn.commit()
    conn.close()
    log_activity(session.get("admin_id"), "integration_update", f"Updated API integration '{existing['name']}'")
    return jsonify({"success": True})


@app.route("/api/admin/ai-providers", methods=["GET", "POST"])
@admin_required
def ai_providers_collection():
    if request.method == "GET":
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM ai_providers ORDER BY is_default DESC, provider_name")
        rows = cursor.fetchall()
        conn.close()
        for r in rows:
            r["api_key_masked"] = mask_secret(decrypt_text(r.pop("api_key", None)))
            r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
            r["updated_at"] = r["updated_at"].isoformat() if r.get("updated_at") else None
        return jsonify(rows)

    data = request.json or {}
    if not data.get("provider_name") or not data.get("model_name"):
        return jsonify({"error": "provider_name and model_name required"}), 400
    conn = get_db()
    cursor = conn.cursor()
    if data.get("is_default"):
        cursor.execute("UPDATE ai_providers SET is_default=0")
    cursor.execute(
        """
        INSERT INTO ai_providers (provider_name, model_name, base_url, api_key, is_enabled, is_default, config_json)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            data["provider_name"],
            data["model_name"],
            data.get("base_url", ""),
            encrypt_text(data.get("api_key", "")),
            1 if data.get("is_enabled") else 0,
            1 if data.get("is_default") else 0,
            json.dumps(data.get("config", {})),
        ),
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    log_activity(session.get("admin_id"), "ai_provider_create", f"Added AI provider {data['provider_name']} / {data['model_name']}")
    return jsonify({"success": True, "id": new_id})


@app.route("/api/admin/settings/smtp", methods=["GET", "POST"])
@admin_required
def smtp_settings():
    if request.method == "GET":
        return jsonify(
            {
                "smtp_host": get_setting("smtp_host"),
                "smtp_port": get_setting("smtp_port", "587"),
                "smtp_username": get_setting("smtp_username"),
                "smtp_password_masked": mask_secret(decrypt_text(get_setting("smtp_password"))),
                "smtp_security": get_setting("smtp_security", "tls"),
                "allowed_email_domains": get_setting("allowed_email_domains", "gov.in,police.gov.in,nic.in"),
            }
        )
    data = request.json or {}
    for key in ["smtp_host", "smtp_port", "smtp_username", "smtp_security", "allowed_email_domains"]:
        if key in data:
            set_setting(key, str(data.get(key, "")))
    if data.get("smtp_password"):
        set_setting("smtp_password", encrypt_text(data["smtp_password"]))
    log_activity(session.get("admin_id"), "smtp_update", f"{session.get('admin_name')} updated SMTP settings")
    return jsonify({"success": True})


@app.route("/api/admin/settings/smtp/test", methods=["POST"])
@admin_required
def smtp_test():
    email = (request.json or {}).get("email", "").strip()
    allowed_domains = [d.strip().lower() for d in get_setting("allowed_email_domains", "gov.in,police.gov.in,nic.in").split(",") if d.strip()]
    if "@" not in email or not any(email.lower().endswith("@" + d) or email.lower().endswith("." + d) for d in allowed_domains):
        return jsonify({"error": "Only government-authorized email domains are allowed for sensitive recovery emails"}), 400

    host = get_setting("smtp_host", "").strip()
    port = int(get_setting("smtp_port", "587") or 587)
    username = get_setting("smtp_username", "").strip()
    password = decrypt_text(get_setting("smtp_password", ""))
    security = get_setting("smtp_security", "tls")
    if not host or not username or not password:
        return jsonify({"error": "SMTP host, username and password must be configured first"}), 400

    msg = (
        f"From: {username}\r\n"
        f"To: {email}\r\n"
        "Subject: SENTINEL SMTP Test\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        "This is a SENTINEL SMTP test email. If you received this, SMTP configuration is working.\r\n"
    )
    try:
        if security == "ssl":
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as server:
                server.login(username, password)
                server.sendmail(username, [email], msg.encode("utf-8"))
        else:
            with smtplib.SMTP(host, port, timeout=20) as server:
                server.ehlo()
                if security == "tls":
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                server.login(username, password)
                server.sendmail(username, [email], msg.encode("utf-8"))
    except Exception as exc:
        log_activity(session.get("admin_id"), "smtp_test_failed", f"SMTP test failed for {email}: {exc}")
        return jsonify({"error": f"SMTP test failed: {exc}"}), 400

    log_activity(session.get("admin_id"), "smtp_test", f"SMTP test email sent to {email}")
    return jsonify({"success": True, "message": "SMTP test email sent successfully"})


# ─────────────────────────────────────────────
# PUBLIC USER/SERVICE APIs
# ─────────────────────────────────────────────
@app.route("/api/me", methods=["GET"])
def get_current_user():
    phone = request.args.get("phone")
    if not phone:
        return jsonify({"error": "phone required"}), 400
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, phone, name, department, credits, status, plan_id FROM bot_users WHERE phone=%s", (phone,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)


@app.route("/api/services", methods=["GET"])
def list_services_public():
    # Use DB services when available; fallback to the analyzer + OSINT tile lists.
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM services WHERE is_enabled=1 ORDER BY sort_order")
        services = cursor.fetchall()
        conn.close()
        for s in services:
            s["created_at"] = s["created_at"].isoformat() if s.get("created_at") else None
            s["accessible"] = True
            s["is_free_for_user"] = bool(s.get("is_free"))
        return jsonify(services)
    except Exception:
        return jsonify(ANALYZER_TOOLS)




# ─────────────────────────────────────────────
# USER PROFILE / PASSWORD / 2FA
# ─────────────────────────────────────────────
@app.route("/api/user/profile", methods=["GET"])
def user_profile():
    if not session.get("is_user"):
        return jsonify({"error": "Login required"}), 401
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, phone, name, department, official_email, credits, status, twofa_enabled, created_at FROM bot_users WHERE id=%s", (session.get("user_id"),))
    except mysql.connector.Error:
        cursor.execute("SELECT id, phone, name, department, NULL AS official_email, credits, status, 0 AS twofa_enabled, created_at FROM bot_users WHERE id=%s", (session.get("user_id"),))
    user = cursor.fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.get("created_at"):
        user["created_at"] = user["created_at"].isoformat()
    return jsonify({"user": user, "twofa_mandatory": True})


@app.route("/api/user/credit-history", methods=["GET"])
@user_required
def user_credit_history():
    """The logged-in user's own credit_transactions — filtered by their own session
    phone only, never a caller-supplied identifier, so there's no IDOR here."""
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, type, amount, reason, status, created_at FROM credit_transactions WHERE phone=%s ORDER BY created_at DESC LIMIT 100",
        (session.get("user_phone"),),
    )
    rows = cursor.fetchall()
    conn.close()
    for r in rows:
        if r.get("created_at"):
            r["created_at"] = r["created_at"].isoformat()
    return jsonify({"transactions": rows})


@app.route("/api/user/password-change", methods=["POST"])
def user_password_change():
    if not session.get("is_user"):
        return jsonify({"error": "Login required"}), 401
    data = request.json or {}
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT password_hash FROM bot_users WHERE id=%s", (session.get("user_id"),))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    existing = row.get("password_hash")
    if existing:
        if not check_password_hash(existing, current_password):
            conn.close()
            return jsonify({"error": "Current password is incorrect"}), 401
    else:
        if current_password != os.getenv("DEV_USER_PASSWORD", "dev123"):
            conn.close()
            return jsonify({"error": "Current development password is incorrect"}), 401
    cursor.execute("UPDATE bot_users SET password_hash=%s WHERE id=%s", (generate_password_hash(new_password), session.get("user_id")))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/user/2fa/setup", methods=["POST"])
def user_2fa_setup():
    if not session.get("is_user"):
        return jsonify({"error": "Login required"}), 401
    secret = pyotp.random_base32()
    label = f"SENTINEL:{session.get('user_phone')}"
    uri = pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name="SENTINEL")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE bot_users SET twofa_secret=%s WHERE id=%s", (encrypt_text(secret), session.get("user_id")))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "qr_data_uri": f"data:image/png;base64,{qr_b64}", "manual_secret": secret})


@app.route("/api/user/2fa/enable", methods=["POST"])
def user_2fa_enable():
    if not session.get("is_user"):
        return jsonify({"error": "Login required"}), 401
    otp = (request.json or {}).get("otp", "").strip()
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT twofa_secret FROM bot_users WHERE id=%s", (session.get("user_id"),))
    row = cursor.fetchone()
    if not row or not row.get("twofa_secret"):
        conn.close()
        return jsonify({"error": "Run setup first"}), 400
    secret = decrypt_text(row["twofa_secret"])
    if not pyotp.TOTP(secret).verify(otp, valid_window=1):
        conn.close()
        return jsonify({"error": "Invalid OTP"}), 400
    recovery_codes = [uuid.uuid4().hex[:10].upper() for _ in range(8)]
    recovery_hashes = [generate_password_hash(code) for code in recovery_codes]
    cursor.execute("UPDATE bot_users SET twofa_enabled=1, recovery_codes_hash=%s WHERE id=%s", (json.dumps(recovery_hashes), session.get("user_id")))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "recovery_codes": recovery_codes})


# ─────────────────────────────────────────────
# AI + TOOL EXECUTION
# ─────────────────────────────────────────────
def _http_json(url, payload=None, headers=None, method="POST", timeout=45):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
        return json.loads(raw) if raw else {}


def _default_ai_provider():
    """AI chat first uses Admin → AI Integration. If no AI provider is enabled,
    it falls back to Central API Manager integrations named/category Gemini/OpenAI
    so API Manager and dashboard stay connected in development."""
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM ai_providers WHERE is_enabled=1 ORDER BY is_default DESC, id LIMIT 1")
        row = cursor.fetchone()
    except Exception:
        row = None
    if row:
        conn.close()
        row["api_key_plain"] = decrypt_text(row.get("api_key"))
        return row

    cursor.execute("""
        SELECT * FROM integrations
        WHERE is_enabled=1 AND (category IN ('gemini','openai','ai') OR name LIKE '%Gemini%' OR name LIKE '%OpenAI%')
        ORDER BY last_status='working' DESC, id LIMIT 1
    """)
    integ = cursor.fetchone()
    conn.close()
    if not integ:
        return None
    name = integ.get("name") or ""
    category = (integ.get("category") or "").lower()
    if "gemini" in name.lower() or category == "gemini":
        model = (json.loads(integ.get("config_json") or "{}").get("model") if False else None) or "gemini-1.5-flash"
    else:
        model = "gpt-4o-mini"
    try:
        cfg = json.loads(integ.get("config_json") or "{}")
        model = cfg.get("model") or model
    except Exception:
        pass
    return {
        "provider_name": "Google Gemini" if "gemini" in name.lower() or category == "gemini" else "OpenAI",
        "model_name": model,
        "base_url": integ.get("base_url"),
        "api_key_plain": decrypt_text(integ.get("api_key")),
    }

def call_ai_provider(prompt: str):
    provider = _default_ai_provider()
    if not provider:
        return None, "No enabled AI provider configured in Admin → AI Integration"
    api_key = provider.get("api_key_plain")
    if not api_key:
        return None, "Selected AI provider has no API key configured"
    name = (provider.get("provider_name") or "").lower()
    model = provider.get("model_name") or ""
    base = (provider.get("base_url") or "").rstrip("/")
    try:
        if "gemini" in name or "google" in name:
            base = base or "https://generativelanguage.googleapis.com/v1beta"
            url = f"{base}/models/{urllib.parse.quote(model or 'gemini-1.5-flash')}:generateContent?key={urllib.parse.quote(api_key)}"
            data = _http_json(url, {"contents": [{"parts": [{"text": prompt}]}]}, {"Content-Type": "application/json"})
            text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            return text or "Gemini returned an empty response", None
        if "openai" in name:
            base = base or "https://api.openai.com/v1"
            data = _http_json(f"{base}/chat/completions", {"model": model or "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}]}, {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"})
            return data.get("choices", [{}])[0].get("message", {}).get("content", ""), None
        return None, f"AI provider '{provider.get('provider_name')}' is saved, but connector is not implemented yet. Supported now: Google Gemini and OpenAI."
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")[:800]
        return None, f"AI API HTTP {exc.code}: {detail}"
    except Exception as exc:
        return None, f"AI API error: {exc}"


@app.route("/api/ai/chat", methods=["POST"])
@user_required
@rate_limit(max_requests=20, window_seconds=60, per="user")
def ai_chat():
    data = request.json or {}
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"error": "prompt required"}), 400
    answer, error = call_ai_provider(prompt)
    if error:
        return jsonify({"error": error}), 400
    return jsonify({"success": True, "answer": answer})


TOOL_CATEGORY_MAP = {
    "mobile_lookup": "phone", "email_lookup": "email", "username_lookup": "social", "vehicle_lookup": "registry",
    "ip_lookup": "network", "domain_lookup": "domain", "social_media_lookup": "social", "breach_search": "breach",
    "reverse_image": "image", "address_osint": "maps", "universal_search": "multi",
}


@app.route("/api/tools/run", methods=["POST"])
@user_required
@rate_limit(max_requests=30, window_seconds=60, per="user")
def run_tool_generic():
    """Live tool runner. Database lookup tools work without API dependency.
    API tools use configured integrations when present; otherwise return a clear actionable error.
    """
    data = request.json or {}
    code = (data.get("code") or "").strip()
    query = (data.get("query") or "").strip()
    if not code:
        return jsonify({"error": "tool code required"}), 400
    if not query:
        return jsonify({"error": "query required"}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM services WHERE code=%s", (code,))
    service = cursor.fetchone()
    if service and not service.get("is_enabled"):
        conn.close()
        return jsonify({"error": "This service is disabled by admin"}), 403
    if service and service.get("maintenance_mode"):
        conn.close()
        return jsonify({"error": "This service is currently in maintenance mode"}), 503
    if service and service.get("status") == "upcoming":
        conn.close()
        return jsonify({"error": "This tool is marked as Coming Soon by admin"}), 403

    results = []
    errors = []

    # 1) Native database lookup tools — no API dependency required.
    try:
        if code in {"mobile_lookup", "subscriber_lookup"}:
            user_id = session.get("user_id")
            user_phone = session.get("user_phone")
            credits_required = 0 if (service and service.get("is_free")) else int((service or {}).get("credits_per_use") or 0)
            case_reference = str(data.get("case_reference") or "").strip()[:100] or None

            # Pre-flight balance check — block before running any query, per the billing plan.
            if credits_required and user_id:
                cursor.execute("SELECT credits FROM bot_users WHERE id=%s", (user_id,))
                balance_row = cursor.fetchone()
                current_credits = balance_row["credits"] if balance_row else 0
                if current_credits < credits_required:
                    conn.close()
                    return jsonify({"error": "Insufficient credits for this search.", "credits_required": credits_required, "credits_available": current_credits}), 402

            def _record_search(found: bool, source: str):
                """Atomically charge a credit on a match, then always write the search_logs
                audit row (found or not) — that's the actual compliance record.
                Returns the amount charged, or None if a concurrent request won the race
                for the last credit (caller must treat this as insufficient-credits)."""
                charged = 0
                if found and credits_required and user_id:
                    cursor.execute(
                        "UPDATE bot_users SET credits = credits - %s WHERE id = %s AND credits >= %s",
                        (credits_required, user_id, credits_required),
                    )
                    if cursor.rowcount == 0:
                        conn.rollback()
                        return None
                    charged = credits_required
                    cursor.execute(
                        "INSERT INTO credit_transactions (phone, type, amount, reason) VALUES (%s,'debit',%s,%s)",
                        (user_phone, charged, f"service:{code}"),
                    )
                if user_id:
                    cursor.execute(
                        "INSERT INTO search_logs (user_id, phone, search_type, query_value, case_reference, credits_used, sources_queried) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (user_id, user_phone, "mobile", query, case_reference, charged, source),
                    )
                conn.commit()
                return charged

            cursor.execute("SELECT * FROM subscriber_records WHERE mobile_number=%s LIMIT 1", (query,))
            row = cursor.fetchone()
            if row:
                charged = _record_search(True, "Subscriber Database")
                if charged is None:
                    conn.close()
                    return jsonify({"error": "Insufficient credits for this search.", "credits_required": credits_required}), 402
                conn.close()
                return jsonify({"success": True, "tool": code, "query": query, "credits_charged": charged, "results": [{"source": "Subscriber Database", "status": "ok", "data": _json_clean(row)}]})
            # Fallback to generic uploaded records if old importer was used.
            try:
                cursor.execute("SELECT * FROM master_data_records WHERE source_type IN ('subscriber','custom') AND (record_key=%s OR data_json LIKE %s) ORDER BY created_at DESC LIMIT 20", (query, f"%{query}%"))
                rows = cursor.fetchall()
                if rows:
                    charged = _record_search(True, "Uploaded Master Data")
                    if charged is None:
                        conn.close()
                        return jsonify({"error": "Insufficient credits for this search.", "credits_required": credits_required}), 402
                    for r in rows:
                        try: r["data"] = json.loads(r.get("data_json") or "{}")
                        except Exception: r["data"] = r.get("data_json")
                    conn.close()
                    return jsonify({"success": True, "tool": code, "query": query, "credits_charged": charged, "results": [{"source": "Uploaded Master Data", "status": "ok", "data": rows}]})
            except Exception:
                pass
            # Neither source matched — log the attempt for the audit trail, but charge nothing.
            _record_search(False, "No match")

        if code == "vehicle_lookup":
            cursor.execute("SELECT * FROM vehicle_records WHERE registration_number=%s LIMIT 1", (query,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return jsonify({"success": True, "tool": code, "query": query, "results": [{"source": "Vehicle Database", "status": "ok", "data": _json_clean(row)}]})
            return jsonify({"success": False, "error": "No vehicle record found. Upload Vehicle Database from Admin → Data Upload."}), 404

        if code in {"tower_bts_lookup", "tower_analysis"}:
            lac, cell_id = "", ""
            if ":" in query:
                lac, cell_id = query.split(":", 1)
            elif "," in query:
                lac, cell_id = query.split(",", 1)
            else:
                parts = query.split()
                if len(parts) >= 2:
                    lac, cell_id = parts[0], parts[1]
            if not lac or not cell_id:
                conn.close()
                return jsonify({"error": "Enter BTS key as LAC:CELL_ID, e.g. 101:5001"}), 400
            cursor.execute("SELECT * FROM bts_tower_records WHERE lac=%s AND cell_id=%s LIMIT 1", (lac.strip(), cell_id.strip()))
            row = cursor.fetchone(); conn.close()
            if row:
                return jsonify({"success": True, "tool": code, "query": query, "results": [{"source": "BTS/Tower Database", "status": "ok", "data": _json_clean(row)}]})
            return jsonify({"success": False, "error": "No BTS/Tower record found. Upload BTS Database from Admin → Data Upload."}), 404

        if code in {"aadhaar_validator", "aadhaar_osint"}:
            conn.close()
            digits = ''.join(ch for ch in query if ch.isdigit())
            return jsonify({"success": True, "tool": code, "query": query, "results": [{"source": "Local Validator", "status": "ok", "data": {"aadhaar_digits": digits[-4:].rjust(len(digits), "X"), "format_length_valid": len(digits)==12, "note": "Only format validation. No Aadhaar database lookup is performed."}}]})
    except mysql.connector.Error as exc:
        conn.close()
        return jsonify({"error": f"Database lookup failed: {exc}"}), 500

    # 2) API based lookups — use enabled integration by category/API dependency.
    category = TOOL_CATEGORY_MAP.get(code) or (service.get("category") if service else "")
    api_dep = (service.get("api_dependency") if service else "") or ""
    if api_dep:
        cursor.execute("SELECT * FROM integrations WHERE is_enabled=1 AND (name=%s OR category=%s) ORDER BY id LIMIT 1", (api_dep, api_dep))
    else:
        cursor.execute("SELECT * FROM integrations WHERE is_enabled=1 AND category=%s ORDER BY id LIMIT 1", (category,))
    integ = cursor.fetchone()
    conn.close()

    # IP-API has a free endpoint; allow IP lookup even if no integration exists.
    if code in {"ip_lookup", "ip_intelligence"}:
        try:
            url = f"http://ip-api.com/json/{urllib.parse.quote(query)}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query,proxy,hosting"
            resp = _http_json(url, None, {}, method="GET")
            results.append({"source": "IP-API", "status": "ok", "data": resp})
        except Exception as exc:
            errors.append(f"IP-API failed: {exc}")

    if integ:
        name = (integ.get("name") or "").lower()
        base = (integ.get("base_url") or "").rstrip("/")
        key = decrypt_text(integ.get("api_key"))
        secret = decrypt_text(integ.get("api_secret"))
        try:
            if "twilio" in name and code in {"mobile_lookup", "subscriber_lookup"}:
                auth = base64.b64encode(f"{key}:{secret}".encode()).decode()
                url = f"{base or 'https://lookups.twilio.com/v2'}/PhoneNumbers/{urllib.parse.quote(query)}"
                resp = _http_json(url, None, {"Authorization": f"Basic {auth}"}, method="GET")
                results.append({"source": integ["name"], "status": "ok", "data": resp})
            elif "hunter" in name and code == "email_lookup":
                url = f"{base or 'https://api.hunter.io/v2'}/email-verifier?email={urllib.parse.quote(query)}&api_key={urllib.parse.quote(key)}"
                resp = _http_json(url, None, {}, method="GET")
                results.append({"source": integ["name"], "status": "ok", "data": resp})
            elif "haveibeenpwned" in name or "pwned" in name:
                url = f"{base or 'https://haveibeenpwned.com/api/v3'}/breachedaccount/{urllib.parse.quote(query)}?truncateResponse=false"
                try:
                    resp = _http_json(url, None, {"hibp-api-key": key, "user-agent": "SENTINEL"}, method="GET")
                except urllib.error.HTTPError as exc:
                    if exc.code == 404:
                        resp = {"breaches": [], "message": "No breach found"}
                    else:
                        raise
                results.append({"source": integ["name"], "status": "ok", "data": resp})
            elif "shodan" in name:
                url = f"{base or 'https://api.shodan.io'}/shodan/host/{urllib.parse.quote(query)}?key={urllib.parse.quote(key)}"
                resp = _http_json(url, None, {}, method="GET")
                results.append({"source": integ["name"], "status": "ok", "data": resp})
            elif "virustotal" in name:
                endpoint = "ip_addresses" if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", query) else "domains"
                url = f"{base or 'https://www.virustotal.com/api/v3'}/{endpoint}/{urllib.parse.quote(query)}"
                resp = _http_json(url, None, {"x-apikey": key}, method="GET")
                results.append({"source": integ["name"], "status": "ok", "data": resp})
            elif "abuseipdb" in name:
                url = f"{base or 'https://api.abuseipdb.com/api/v2'}/check?ipAddress={urllib.parse.quote(query)}&maxAgeInDays=90"
                resp = _http_json(url, None, {"Key": key, "Accept": "application/json"}, method="GET")
                results.append({"source": integ["name"], "status": "ok", "data": resp})
            elif "google" in name:
                cx = secret
                if not cx:
                    raise ValueError("Google CSE requires CX ID in API Secret field")
                url = f"{base or 'https://www.googleapis.com/customsearch/v1'}?key={urllib.parse.quote(key)}&cx={urllib.parse.quote(cx)}&q={urllib.parse.quote(query)}"
                resp = _http_json(url, None, {}, method="GET")
                results.append({"source": integ["name"], "status": "ok", "data": resp})
            else:
                errors.append(f"Integration '{integ['name']}' found but no live connector is implemented for this provider/tool combination.")
        except Exception as exc:
            errors.append(f"{integ.get('name')} failed: {exc}")

    if results:
        return jsonify({"success": True, "tool": code, "query": query, "results": results, "errors": errors})

    if code in {"mobile_lookup", "subscriber_lookup"}:
        return jsonify({"success": False, "error": "No subscriber record found. Upload Subscriber Database from Admin → Data Upload. Optional: configure Twilio/Numverify API for external phone intelligence.", "errors": errors}), 404
    return jsonify({"success": False, "error": f"No working connector/data found for tool '{code}'. Configure API dependency or upload database.", "errors": errors}), 400




# ─────────────────────────────────────────────
# ENTERPRISE CONTROL: API TESTING / HEALTH / REAL-TIME EVENTS / IMPORTS
# ─────────────────────────────────────────────
def _integration_safe_public(row):
    return {
        "id": row.get("id"), "name": row.get("name"), "category": row.get("category"),
        "description": row.get("description"), "base_url": row.get("base_url"),
        "is_enabled": bool(row.get("is_enabled")), "show_on_dashboard": bool(row.get("show_on_dashboard")),
        "usage_limit_daily": row.get("usage_limit_daily", 0), "credits_per_call": row.get("credits_per_call", 0),
        "last_status": row.get("last_status") or "unknown",
        "last_error": row.get("last_error") or "",
        "last_test_at": row.get("last_test_at").isoformat() if row.get("last_test_at") else None,
        "last_sync_at": row.get("last_sync_at").isoformat() if row.get("last_sync_at") else None,
        "api_key_masked": mask_secret(decrypt_text(row.get("api_key"))),
        "api_secret_masked": mask_secret(decrypt_text(row.get("api_secret"))),
    }


def _test_integration(row):
    name = (row.get("name") or "").lower()
    category = (row.get("category") or "").lower()
    base = (row.get("base_url") or "").rstrip("/")
    key = decrypt_text(row.get("api_key"))
    secret = decrypt_text(row.get("api_secret"))
    if not key and category not in {"smtp"}:
        return False, "API key missing"
    try:
        if category == "smtp" or "smtp" in name:
            if get_setting("smtp_host", "") and get_setting("smtp_username", "") and decrypt_text(get_setting("smtp_password", "")):
                return True, "SMTP configuration present. Use SMTP Center Send Test Email for full send verification."
            return False, "SMTP is not fully configured in SMTP Center"
        if "gemini" in name or "gemini" in category:
            url = f"{base or 'https://generativelanguage.googleapis.com/v1beta'}/models?key={urllib.parse.quote(key)}"
            _http_json(url, None, {}, method="GET", timeout=20)
        elif "openai" in name or category == "openai":
            _http_json(f"{base or 'https://api.openai.com/v1'}/models", None, {"Authorization": f"Bearer {key}"}, method="GET", timeout=20)
        elif "shodan" in name:
            url = f"{base or 'https://api.shodan.io'}/api-info?key={urllib.parse.quote(key)}"
            _http_json(url, None, {}, method="GET", timeout=20)
        elif "haveibeenpwned" in name or "hibp" in name or "pwned" in name:
            url = f"{base or 'https://haveibeenpwned.com/api/v3'}/breaches"
            _http_json(url, None, {"hibp-api-key": key, "user-agent": "SENTINEL"}, method="GET", timeout=20)
        elif "virustotal" in name or "virus" in category:
            url = f"{base or 'https://www.virustotal.com/api/v3'}/users/current"
            _http_json(url, None, {"x-apikey": key}, method="GET", timeout=20)
        elif "abuseipdb" in name or "abuse" in category:
            url = f"{base or 'https://api.abuseipdb.com/api/v2'}/check?ipAddress=8.8.8.8&maxAgeInDays=90"
            _http_json(url, None, {"Key": key, "Accept": "application/json"}, method="GET", timeout=20)
        elif "twilio" in name:
            auth = base64.b64encode(f"{key}:{secret}".encode()).decode()
            _http_json(f"{base or 'https://api.twilio.com/2010-04-01'}/Accounts.json", None, {"Authorization": f"Basic {auth}"}, method="GET", timeout=20)
        else:
            if not base:
                return False, "Base URL missing and no built-in tester exists for this provider"
            _http_json(base, None, {}, method="GET", timeout=20)
        return True, "Connection verified"
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")[:500]
        return False, f"API Authentication/HTTP Failed {exc.code}: {detail}"
    except Exception as exc:
        return False, f"API Connection Failed: {exc}"


@app.route("/api/admin/integrations/<int:integration_id>/test", methods=["POST"])
@admin_required
def test_integration(integration_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM integrations WHERE id=%s", (integration_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Integration not found"}), 404
    ok, message = _test_integration(row)
    status = "working" if ok else "failed"
    try:
        cursor.execute("UPDATE integrations SET last_status=%s, last_error=%s, last_test_at=NOW(), last_sync_at=NOW() WHERE id=%s", (status, "" if ok else message, integration_id))
        conn.commit()
    except mysql.connector.Error:
        pass
    conn.close()
    log_audit("integration_test", f"Tested API {row['name']}: {status}", None, {"status": status, "message": message})
    return jsonify({"success": ok, "status": status, "message": message}), (200 if ok else 400)


@app.route("/api/admin/integrations/status", methods=["GET"])
@admin_required
def integrations_status():
    conn = get_db(); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM integrations ORDER BY category, name")
    rows = cursor.fetchall(); conn.close()
    return jsonify([_integration_safe_public(r) for r in rows])


@app.route("/api/api-status", methods=["GET"])
def public_api_status():
    conn = get_db(); cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT name, category, is_enabled, last_status, last_error, last_test_at FROM integrations WHERE show_on_dashboard=1 ORDER BY category, name")
    except mysql.connector.Error:
        cursor.execute("SELECT name, category, is_enabled, 'unknown' AS last_status, '' AS last_error, NULL AS last_test_at FROM integrations WHERE show_on_dashboard=1 ORDER BY category, name")
    rows = cursor.fetchall(); conn.close()
    for r in rows:
        if r.get("last_test_at"): r["last_test_at"] = r["last_test_at"].isoformat()
    return jsonify(rows)


@app.route("/api/admin/health", methods=["GET"])
@admin_required
def admin_health():
    health = {"database": {"status": "unknown"}, "smtp": {"status": "unknown"}, "apis": {"status": "unknown"}, "system": {}}
    try:
        conn = get_db(); cursor = conn.cursor(); cursor.execute("SELECT 1"); cursor.fetchone(); conn.close()
        health["database"] = {"status": "green", "message": "Connected"}
    except Exception as exc:
        health["database"] = {"status": "red", "message": str(exc)}
    try:
        conn = get_db(); cursor = conn.cursor(dictionary=True); cursor.execute("SELECT is_enabled, COALESCE(last_status,'unknown') last_status FROM integrations"); api_rows=cursor.fetchall(); conn.close()
        failed = [a for a in api_rows if a.get("is_enabled") and a.get("last_status") == "failed"]
        health["apis"] = {"status": "red" if failed else "green", "failed_count": len(failed), "total": len(api_rows)}
    except Exception as exc:
        health["apis"] = {"status": "yellow", "message": str(exc)}
    smtp_host = get_setting("smtp_host", "")
    health["smtp"] = {"status": "green" if smtp_host and get_setting("smtp_username", "") else "yellow", "message": "Configured" if smtp_host else "Not configured"}
    try:
        total, used, free = shutil.disk_usage(BASE_DIR)
        health["system"]["storage"] = {"total_gb": round(total/1e9,2), "used_gb": round(used/1e9,2), "percent": round(used/total*100,1), "status": "red" if used/total > .9 else "green"}
        if psutil:
            health["system"]["cpu_percent"] = psutil.cpu_percent(interval=0.1)
            health["system"]["ram_percent"] = psutil.virtual_memory().percent
    except Exception as exc:
        health["system"]["error"] = str(exc)
    return jsonify(health)


@app.route("/api/events")
def event_stream():
    def gen():
        while True:
            yield f"data: {json.dumps({'type':'sync','ts':time.time()})}\n\n"
            time.sleep(5)
    return Response(gen(), mimetype="text/event-stream")


def _parse_import_file(file):
    name = (file.filename or "").lower(); raw = file.read()
    if name.endswith(".json"):
        data = json.loads(raw.decode("utf-8", errors="ignore")); return data if isinstance(data, list) else [data]
    if name.endswith(".xlsx"):
        try: import openpyxl
        except Exception: raise ValueError("XLSX support requires openpyxl. Run: pip install openpyxl")
        wb = openpyxl.load_workbook(io.BytesIO(raw), read_only=True, data_only=True); ws = wb.active
        rows = list(ws.iter_rows(values_only=True));
        if not rows: return []
        headers = [str(h or "").strip() for h in rows[0]]
        return [dict(zip(headers, row)) for row in rows[1:]]
    return list(csv.DictReader(io.StringIO(raw.decode("utf-8", errors="ignore"))))


@app.route("/api/admin/data/preview", methods=["POST"])
@admin_required
def admin_data_preview():
    file = request.files.get("file")
    if not file: return jsonify({"error": "file required"}), 400
    try: rows = _parse_import_file(file)
    except Exception as exc: return jsonify({"error": str(exc)}), 400
    headers = list(rows[0].keys()) if rows else []
    return jsonify({"success": True, "headers": headers, "total_rows": len(rows), "preview": rows[:10]})


@app.route("/api/admin/data/rollback/<int:batch_id>", methods=["POST"])
@admin_required
def rollback_import(batch_id):
    conn = get_db(); cursor = conn.cursor()
    try: cursor.execute("DELETE FROM master_data_records WHERE import_batch_id=%s", (batch_id,))
    except mysql.connector.Error: cursor.execute("DELETE FROM master_data_records WHERE id=0")
    deleted = cursor.rowcount
    try: cursor.execute("UPDATE import_batches SET status='rolled_back', rolled_back_at=NOW() WHERE id=%s", (batch_id,))
    except Exception: pass
    conn.commit(); conn.close(); log_audit("data_import_rollback", f"Rolled back import batch {batch_id}", None, {"deleted": deleted})
    return jsonify({"success": True, "deleted": deleted})


@app.route("/api/universal-search", methods=["POST"])
def universal_search():
    data = request.json or {}; query = (data.get("query") or "").strip()
    if not query: return jsonify({"error": "query required"}), 400
    q = query.lower()
    if "@" in q: modules = ["email_lookup", "breach_search"]
    elif q.replace("+", "").replace(" ", "").isdigit() and len(q.replace("+", "").replace(" ", "")) >= 10: modules = ["mobile_lookup", "subscriber"]
    elif "." in q: modules = ["domain_lookup", "ip_lookup"]
    else: modules = ["username_lookup", "vehicle_lookup", "address_osint"]
    return jsonify({"success": True, "query": query, "modules_selected": modules, "message": "Universal Search router selected relevant modules. Live execution depends on configured connectors."})

# ─────────────────────────────────────────────
# ADMIN DATA MANAGEMENT: Upload tower/BTS/subscriber/custom records from GUI
# ─────────────────────────────────────────────
@app.route("/api/admin/data/upload", methods=["POST"])
@admin_required
def admin_data_upload():
    source_type = request.form.get("source_type", "custom")
    key_field = request.form.get("key_field", "")
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "CSV file required"}), 400
    try:
        rows = _parse_import_file(file)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    conn = get_db()
    cursor = conn.cursor()
    batch_id = None
    try:
        cursor.execute("INSERT INTO import_batches (source_type, original_filename, total_rows, imported_by, status) VALUES (%s,%s,%s,%s,'imported')", (source_type, file.filename, len(rows), session.get("admin_name")))
        batch_id = cursor.lastrowid
    except Exception:
        batch_id = None
    inserted = 0
    for row in rows:
        record_key = str(row.get(key_field, "")) if key_field else ""
        try:
            cursor.execute("INSERT INTO master_data_records (source_type, record_key, data_json, uploaded_by, import_batch_id) VALUES (%s,%s,%s,%s,%s)", (source_type, record_key, json.dumps(row, default=str), session.get("admin_name"), batch_id))
        except mysql.connector.Error:
            cursor.execute("INSERT INTO master_data_records (source_type, record_key, data_json, uploaded_by) VALUES (%s,%s,%s,%s)", (source_type, record_key, json.dumps(row, default=str), session.get("admin_name")))
        inserted += 1
    conn.commit()
    conn.close()
    log_audit("data_upload", f"Uploaded {inserted} {source_type} records", None, {"source_type": source_type, "inserted": inserted, "batch_id": batch_id})
    return jsonify({"success": True, "inserted": inserted, "batch_id": batch_id})


@app.route("/api/admin/data/records", methods=["GET"])
@admin_required
def admin_data_records():
    source_type = request.args.get("source_type", "")
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    if source_type:
        cursor.execute("SELECT * FROM master_data_records WHERE source_type=%s ORDER BY created_at DESC LIMIT 200", (source_type,))
    else:
        cursor.execute("SELECT * FROM master_data_records ORDER BY created_at DESC LIMIT 200")
    rows = cursor.fetchall()
    conn.close()
    for r in rows:
        r["created_at"] = r["created_at"].isoformat()
        try:
            r["data"] = json.loads(r.pop("data_json") or "{}")
        except Exception:
            r["data"] = {}
    return jsonify(rows)


# ─────────────────────────────────────────────
# ANALYSIS MODULES — Uploaded evidence files only
# ─────────────────────────────────────────────
def _csv_rows_from_upload(file):
    content = file.read().decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)
    if not rows:
        raise ValueError("File appears empty or invalid")
    return rows


def _col(row, *names):
    for n in names:
        for k in row.keys():
            if k.strip().lower() == n:
                return row[k]
    return None


@app.route("/api/tools/cdr/analyze", methods=["POST"])
@user_required
@rate_limit(max_requests=10, window_seconds=60, per="user")
def cdr_analyze():
    phone = request.form.get("phone")
    case_reference = request.form.get("case_reference", "")
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No CDR file uploaded"}), 400
    try:
        rows = _csv_rows_from_upload(file)
    except Exception as e:
        return jsonify({"error": f"Could not parse CSV: {e}"}), 400

    contact_counts: dict[str, int] = {}
    total_duration = 0
    durations: list[int] = []
    call_types: dict[str, int] = {}
    nodes: set[str] = set()
    edges: list[dict] = []
    # Time-based analysis buckets
    hour_of_day: dict[int, int] = {h: 0 for h in range(24)}
    day_of_week: dict[str, int] = {d: 0 for d in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]}
    # Bidirectional contact tracking for common_contacts
    call_pairs: dict[tuple, int] = {}

    _DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

    for row in rows:
        a = _col(row, "calling_number", "a_party", "caller")
        b = _col(row, "called_number", "b_party", "callee")
        dur_raw = _col(row, "duration", "call_duration")
        ctype = _col(row, "call_type", "type") or "unknown"
        dt_raw = _col(row, "date_time", "call_date", "start_time", "timestamp", "date")

        if a:
            nodes.add(a)
        if b:
            nodes.add(b)
        if a and b:
            edges.append({"from": a, "to": b})
            contact_counts[b] = contact_counts.get(b, 0) + 1
            # Track bidirectional pairs (sorted so A↔B and B↔A merge)
            pair = tuple(sorted([a, b]))
            call_pairs[pair] = call_pairs.get(pair, 0) + 1

        # Duration
        dur = 0
        try:
            dur = int(dur_raw) if dur_raw else 0
        except (ValueError, TypeError):
            pass
        if dur > 0:
            durations.append(dur)
            total_duration += dur

        call_types[ctype] = call_types.get(ctype, 0) + 1

        # Parse timestamp for time-pattern analysis
        if dt_raw:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S",
                        "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d-%m-%Y %H:%M"):
                try:
                    dt = datetime.strptime(dt_raw.strip(), fmt)
                    hour_of_day[dt.hour] = hour_of_day.get(dt.hour, 0) + 1
                    day_of_week[_DAY_NAMES[dt.weekday()]] = day_of_week.get(_DAY_NAMES[dt.weekday()], 0) + 1
                    break
                except (ValueError, AttributeError):
                    continue

    top_contacts = sorted(contact_counts.items(), key=lambda x: -x[1])[:10]
    common_contacts = sorted(
        [{"pair": list(p), "total_calls": c} for p, c in call_pairs.items() if c >= 2],
        key=lambda x: -x["total_calls"]
    )[:20]

    # Duration statistics
    avg_duration = int(sum(durations) / len(durations)) if durations else 0
    max_duration = max(durations) if durations else 0
    min_duration = min(durations) if durations else 0

    # Peak hour detection
    peak_hour = max(hour_of_day, key=lambda h: hour_of_day[h]) if any(hour_of_day.values()) else None
    peak_day = max(day_of_week, key=lambda d: day_of_week[d]) if any(day_of_week.values()) else None

    result = {
        "total_records": len(rows),
        "unique_numbers": len(nodes),
        "total_duration_seconds": total_duration,
        "duration_stats": {
            "average_seconds": avg_duration,
            "max_seconds": max_duration,
            "min_seconds": min_duration,
            "calls_with_duration": len(durations),
        },
        "call_type_breakdown": call_types,
        "top_contacts": [{"number": n, "call_count": c} for n, c in top_contacts],
        "common_contacts": common_contacts,
        "time_analysis": {
            "hour_of_day": hour_of_day,
            "day_of_week": day_of_week,
            "peak_hour": peak_hour,
            "peak_day": peak_day,
            "has_time_data": any(hour_of_day.values()),
        },
        "graph": {"nodes": list(nodes)[:200], "edges": edges[:500]},
    }
    if phone:
        log_service_usage_internal(phone, "cdr_processor", case_reference, f"CDR file: {len(rows)} rows analyzed")
    return jsonify(result)


@app.route("/api/tools/ipdr/analyze", methods=["POST"])
@user_required
@rate_limit(max_requests=10, window_seconds=60, per="user")
def ipdr_analyze():
    phone = request.form.get("phone")
    case_reference = request.form.get("case_reference", "")
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No IPDR file uploaded"}), 400
    try:
        rows = _csv_rows_from_upload(file)
    except Exception as e:
        return jsonify({"error": f"Could not parse CSV: {e}"}), 400

    dest_ip_counts: dict[str, int] = {}
    dest_ip_bytes: dict[str, int] = {}
    total_bytes = 0
    session_bytes: list[int] = []
    msisdns: set[str] = set()
    protocols: dict[str, int] = {}
    hour_of_day: dict[int, int] = {h: 0 for h in range(24)}
    _DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    day_of_week: dict[str, int] = {d: 0 for d in _DAY_NAMES}

    for row in rows:
        dest_ip = _col(row, "dest_ip", "destination_ip", "server_ip")
        msisdn = _col(row, "msisdn", "mobile_number", "subscriber")
        nbytes_raw = _col(row, "bytes_transferred", "data_volume", "bytes", "total_bytes")
        protocol = _col(row, "protocol", "app_protocol", "service_type") or "unknown"
        dt_raw = _col(row, "date_time", "start_time", "timestamp", "session_start", "date")

        if dest_ip:
            dest_ip_counts[dest_ip] = dest_ip_counts.get(dest_ip, 0) + 1
        if msisdn:
            msisdns.add(msisdn)

        nbytes = 0
        try:
            nbytes = int(nbytes_raw) if nbytes_raw else 0
        except (ValueError, TypeError):
            pass
        if nbytes > 0:
            total_bytes += nbytes
            session_bytes.append(nbytes)
            if dest_ip:
                dest_ip_bytes[dest_ip] = dest_ip_bytes.get(dest_ip, 0) + nbytes

        protocols[protocol] = protocols.get(protocol, 0) + 1

        if dt_raw:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S",
                        "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                try:
                    dt = datetime.strptime(dt_raw.strip(), fmt)
                    hour_of_day[dt.hour] = hour_of_day.get(dt.hour, 0) + 1
                    day_of_week[_DAY_NAMES[dt.weekday()]] = day_of_week.get(_DAY_NAMES[dt.weekday()], 0) + 1
                    break
                except (ValueError, AttributeError):
                    continue

    top_destinations = sorted(dest_ip_counts.items(), key=lambda x: -x[1])[:10]
    top_by_data = sorted(dest_ip_bytes.items(), key=lambda x: -x[1])[:10]
    avg_bytes = int(sum(session_bytes) / len(session_bytes)) if session_bytes else 0
    peak_hour = max(hour_of_day, key=lambda h: hour_of_day[h]) if any(hour_of_day.values()) else None
    peak_day = max(day_of_week, key=lambda d: day_of_week[d]) if any(day_of_week.values()) else None

    result = {
        "total_records": len(rows),
        "unique_subscribers": len(msisdns),
        "total_bytes_transferred": total_bytes,
        "total_mb_transferred": round(total_bytes / (1024 * 1024), 2),
        "data_stats": {
            "average_bytes_per_session": avg_bytes,
            "max_bytes": max(session_bytes) if session_bytes else 0,
            "sessions_with_data": len(session_bytes),
        },
        "top_destination_ips": [{"ip": ip, "session_count": c} for ip, c in top_destinations],
        "top_ips_by_data": [{"ip": ip, "bytes": b, "mb": round(b / (1024 * 1024), 2)} for ip, b in top_by_data],
        "protocol_breakdown": protocols,
        "time_analysis": {
            "hour_of_day": hour_of_day,
            "day_of_week": day_of_week,
            "peak_hour": peak_hour,
            "peak_day": peak_day,
            "has_time_data": any(hour_of_day.values()),
        },
    }
    if phone:
        log_service_usage_internal(phone, "ipdr_analysis", case_reference, f"IPDR file: {len(rows)} rows analyzed")
    return jsonify(result)


def log_service_usage_internal(phone, service_code, case_reference, input_summary):
    try:
        with db_conn() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM services WHERE code=%s", (service_code,))
            service = cursor.fetchone()
            cursor.execute("SELECT * FROM bot_users WHERE phone=%s", (phone,))
            user = cursor.fetchone()
            if not service or not user:
                return
            is_free = bool(service["is_free"])
            credits_charged = 0 if is_free else int(service["credits_per_use"])
            if credits_charged and user["credits"] >= credits_charged:
                cursor.execute("UPDATE bot_users SET credits=credits-%s WHERE id=%s", (credits_charged, user["id"]))
                cursor.execute("INSERT INTO credit_transactions (phone, type, amount, reason) VALUES (%s,'debit',%s,%s)", (phone, credits_charged, f"service:{service_code}"))
            cursor.execute(
                "INSERT INTO service_usage_log (user_id, service_id, case_reference, input_summary, credits_charged) VALUES (%s,%s,%s,%s,%s)",
                (user["id"], service["id"], case_reference, input_summary, credits_charged),
            )
            conn.commit()
    except Exception as exc:
        print(f"service usage log failed: {exc}")


# ─────────────────────────────────────────────
# NEXT UPDATE: TOOL MANAGEMENT CENTER + IMPORT WIZARD + WORKSPACE + CLI
# ─────────────────────────────────────────────
IMPORT_MODULES = {
    "subscriber":{"label":"Subscriber Database","table":"subscriber_records","lookup_key":"mobile_number","required":["mobile_number","subscriber_name"],"columns":["mobile_number","subscriber_name","father_name","address","district","state","operator","sim_type","activation_date","status","alternate_number","email","id_type","id_number"]},
    "vehicle":{"label":"Vehicle Database","table":"vehicle_records","lookup_key":"registration_number","required":["registration_number","owner_name"],"columns":["registration_number","owner_name","father_name","address","vehicle_class","manufacturer","model","engine_number","chassis_number","fuel_type","registration_date","fitness_validity","insurance_validity","district"]},
    "bts":{"label":"BTS / Tower Database","table":"bts_tower_records","lookup_key":"lac+cell_id","required":["lac","cell_id"],"columns":["tower_id","operator","lac","cell_id","tower_name","latitude","longitude","full_address","district","state","technology","azimuth"]},
    "cdr":{"label":"CDR Import Engine","table":"cdr_records","lookup_key":"case_reference","required":["calling_number","called_number","start_time"],"columns":["calling_number","called_number","start_time","end_time","duration","imei","imsi","lac","cell_id"]},
    "ipdr":{"label":"IPDR Import Engine","table":"ipdr_records","lookup_key":"case_reference","required":["subscriber_number","source_ip","destination_ip","timestamp"],"columns":["subscriber_number","source_ip","destination_ip","timestamp","session_duration","lac","cell_id"]},
    "custom":{"label":"Custom Records","table":"custom_records_v2","lookup_key":"record_key","required":[],"columns":[]},
}

@app.route("/api/admin/settings", methods=["GET","POST"])
@admin_required
def admin_settings_center_v2():
    if request.method=="GET":
        conn=get_db(); cur=conn.cursor(dictionary=True); cur.execute("SELECT setting_key,setting_value FROM app_settings ORDER BY setting_key"); rows=cur.fetchall(); conn.close(); return jsonify({r['setting_key']:r['setting_value'] for r in rows})
    data=request.json or {}; old={}
    for k,v in data.items(): set_setting(k, str(v))
    log_audit("settings_update", f"Updated {len(data)} settings", old, data); return jsonify({"success":True,"message":"Configuration Saved"})

@app.route("/api/admin/services", methods=["GET","POST"])
@admin_required
def admin_services_v2():
    if request.method=="GET":
        conn=get_db(); cur=conn.cursor(dictionary=True); cur.execute("SELECT * FROM services ORDER BY sort_order,id"); rows=cur.fetchall(); conn.close()
        for r in rows:
            if r.get('created_at'): r['created_at']=r['created_at'].isoformat()
        return jsonify(rows)
    d=request.json or {}
    if not d.get('code') or not d.get('name'): return jsonify({"error":"Validation Failed: code and name required"}),400
    conn=get_db(); cur=conn.cursor()
    try:
        cur.execute("""INSERT INTO services (code,name,category,description,icon,credits_per_use,is_free,is_enabled,sort_order,tool_category,tool_type,api_dependency,search_limit,status,visible_to_users,maintenance_mode,external_command,timeout_seconds,allow_cli_execution) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", (d['code'],d['name'],d.get('category','custom'),d.get('description',''),d.get('icon','🔧'),int(d.get('credits_per_use',0) or 0),1 if d.get('is_free') else 0,1 if d.get('is_enabled',True) else 0,int(d.get('sort_order',999) or 999),d.get('tool_category','OSINT'),d.get('tool_type','API Based'),d.get('api_dependency',''),int(d.get('search_limit',0) or 0),d.get('status','enabled'),1 if d.get('visible_to_users',True) else 0,1 if d.get('maintenance_mode') else 0,d.get('external_command',''),int(d.get('timeout_seconds',60) or 60),1 if d.get('allow_cli_execution') else 0))
        conn.commit(); sid=cur.lastrowid
    except Exception as exc:
        conn.rollback(); conn.close(); return jsonify({"error":f"Database Write Failed: {exc}"}),400
    conn.close(); log_audit("tool_added", f"Added tool {d['name']}", None, d); return jsonify({"success":True,"id":sid})

@app.route("/api/admin/services/<int:service_id>", methods=["PUT","DELETE"])
@admin_required
def admin_service_item_v2(service_id):
    conn=get_db(); cur=conn.cursor(dictionary=True); cur.execute("SELECT * FROM services WHERE id=%s",(service_id,)); old=cur.fetchone()
    if not old: conn.close(); return jsonify({"error":"Tool not found"}),404
    if request.method=="DELETE":
        cur.execute("DELETE FROM services WHERE id=%s",(service_id,)); conn.commit(); conn.close(); log_audit("tool_deleted",f"Deleted tool {old['name']}",old,None); return jsonify({"success":True})
    d=request.json or {}
    try:
        cur.execute("""UPDATE services SET name=%s,category=%s,description=%s,icon=%s,credits_per_use=%s,is_free=%s,is_enabled=%s,sort_order=%s,tool_category=%s,tool_type=%s,api_dependency=%s,search_limit=%s,status=%s,visible_to_users=%s,maintenance_mode=%s,external_command=%s,timeout_seconds=%s,allow_cli_execution=%s WHERE id=%s""", (d.get('name',old['name']),d.get('category',old.get('category')),d.get('description',old.get('description') or ''),d.get('icon',old.get('icon') or '🔧'),int(d.get('credits_per_use',old.get('credits_per_use') or 0)),1 if d.get('is_free') else 0,1 if d.get('is_enabled') else 0,int(d.get('sort_order',old.get('sort_order') or 0)),d.get('tool_category',old.get('tool_category') or 'OSINT'),d.get('tool_type',old.get('tool_type') or 'API Based'),d.get('api_dependency',old.get('api_dependency') or ''),int(d.get('search_limit',old.get('search_limit') or 0)),d.get('status',old.get('status') or 'enabled'),1 if d.get('visible_to_users',True) else 0,1 if d.get('maintenance_mode') else 0,d.get('external_command',old.get('external_command') or ''),int(d.get('timeout_seconds',old.get('timeout_seconds') or 60)),1 if d.get('allow_cli_execution') else 0,service_id))
        conn.commit()
    except Exception as exc:
        conn.rollback(); conn.close(); return jsonify({"error":f"Database Write Failed: {exc}"}),400
    conn.close(); log_audit("tool_edited",f"Edited tool {old['name']}",old,d); return jsonify({"success":True})

@app.route("/api/admin/tools/<int:service_id>/cli-test", methods=["POST"])
@admin_required
def admin_cli_test_v2(service_id):
    q=(request.json or {}).get('query','test'); conn=get_db(); cur=conn.cursor(dictionary=True); cur.execute("SELECT * FROM services WHERE id=%s",(service_id,)); svc=cur.fetchone();
    if not svc: conn.close(); return jsonify({"error":"Tool not found"}),404
    if not svc.get('allow_cli_execution'): conn.close(); return jsonify({"error":"CLI execution disabled for this tool"}),403
    cmd=(svc.get('external_command') or '').replace('{query}',str(q));
    if not cmd: conn.close(); return jsonify({"error":"external_command missing"}),400
    cur.execute("INSERT INTO external_tool_jobs (service_id,user_id,command,status,started_at) VALUES (%s,%s,%s,'running',NOW())",(service_id,session.get('user_id'),cmd)); jid=cur.lastrowid; conn.commit(); start=time.time()
    try:
        proc=subprocess.run(shlex.split(cmd),capture_output=True,text=True,timeout=int(svc.get('timeout_seconds') or 60),cwd=BASE_DIR); status='success' if proc.returncode==0 else 'failed'; rt=int((time.time()-start)*1000)
        cur.execute("UPDATE external_tool_jobs SET status=%s,exit_code=%s,stdout=%s,stderr=%s,runtime_ms=%s,finished_at=NOW() WHERE id=%s",(status,proc.returncode,(proc.stdout or '')[:200000],(proc.stderr or '')[:50000],rt,jid)); conn.commit(); conn.close(); return jsonify({"success":proc.returncode==0,"job_id":jid,"stdout":proc.stdout,"stderr":proc.stderr,"runtime_ms":rt}), (200 if proc.returncode==0 else 500)
    except Exception as exc:
        cur.execute("UPDATE external_tool_jobs SET status='failed',stderr=%s,finished_at=NOW() WHERE id=%s",(str(exc),jid)); conn.commit(); conn.close(); return jsonify({"error":str(exc),"job_id":jid}),500

@app.route("/api/admin/tools/jobs", methods=["GET"])
@admin_required
def cli_jobs_v2():
    conn=get_db(); cur=conn.cursor(dictionary=True); cur.execute("SELECT j.*,s.name service_name FROM external_tool_jobs j LEFT JOIN services s ON s.id=j.service_id ORDER BY j.created_at DESC LIMIT 100"); rows=cur.fetchall(); conn.close();
    for r in rows:
        for k in ['created_at','started_at','finished_at']:
            if r.get(k): r[k]=r[k].isoformat()
    return jsonify(rows)

@app.route("/api/admin/tool-package/upload", methods=["POST"])
@admin_required
def tool_package_upload_v2():
    f=request.files.get('file')
    if not f: return jsonify({"error":"JSON tool package required"}),400
    try: pkg=json.loads(f.read().decode('utf-8'))
    except Exception as exc: return jsonify({"error":f"Invalid JSON: {exc}"}),400
    tools=pkg.get('tools') if isinstance(pkg,dict) else [pkg]
    created=[]
    for t in tools:
        t.setdefault('code',_norm_header(t.get('name'))); t.setdefault('name',t.get('code'))
        conn=get_db(); cur=conn.cursor()
        try:
            cur.execute("INSERT INTO services (code,name,category,description,icon,credits_per_use,is_enabled,tool_category,tool_type,status,visible_to_users) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(t['code'],t['name'],t.get('category','custom'),t.get('description',''),t.get('icon','🔧'),int(t.get('credits_per_use',0) or 0),1 if t.get('is_enabled',True) else 0,t.get('tool_category','OSINT'),t.get('tool_type','External Tool'),t.get('status','upcoming'),1 if t.get('visible_to_users',True) else 0)); conn.commit(); created.append(t['name'])
        except Exception: conn.rollback()
        conn.close()
    return jsonify({"success":True,"created":created})


def _parse_date_or_none(value):
    value=str(value or '').strip()
    if not value: return None
    for fmt in ['%Y-%m-%d','%d-%m-%Y','%d/%m/%Y','%Y-%m-%d %H:%M:%S','%d/%m/%Y %H:%M:%S']:
        try: return datetime.strptime(value,fmt).strftime('%Y-%m-%d %H:%M:%S' if 'H' in fmt else '%Y-%m-%d')
        except Exception: pass
    try: return datetime.fromisoformat(value).strftime('%Y-%m-%d %H:%M:%S')
    except Exception: return None

def validate_import_rows(module, rows, mapping=None):
    cfg=IMPORT_MODULES.get(module,{}); mapping=mapping or {}; issues=[]; out=[]; seen=set(); dup=0
    for i,orig in enumerate(rows,start=1):
        raw=_normalize_row(orig); row={}
        if mapping:
            for dest,src in mapping.items(): row[dest]=raw.get(_norm_header(src),'')
        else: row=raw
        row['_raw']=raw
        for req in cfg.get('required',[]):
            if not row.get(req): issues.append({'row':i,'type':'missing_required','field':req,'message':f'Missing mandatory field: {req}'})
        key=''
        if module=='subscriber': key=row.get('mobile_number','')
        elif module=='vehicle': key=row.get('registration_number','')
        elif module=='bts': key=f"{row.get('lac')}::{row.get('cell_id')}"
        elif module=='cdr': key=f"{row.get('calling_number')}::{row.get('called_number')}::{row.get('start_time')}"
        elif module=='ipdr': key=f"{row.get('subscriber_number')}::{row.get('source_ip')}::{row.get('destination_ip')}::{row.get('timestamp')}"
        if key and key in seen: dup+=1; issues.append({'row':i,'type':'duplicate_in_file','field':'key','message':f'Duplicate key: {key}'})
        seen.add(key); out.append(row)
    errors=len([x for x in issues if x['type']=='missing_required'])
    return out,issues,{'total_rows':len(rows),'valid_rows':len(rows)-errors,'error_count':errors,'warning_count':len(issues)-errors,'duplicate_count':dup}

@app.route('/api/admin/import/modules', methods=['GET'])
@admin_required
def import_modules_v2(): return jsonify(IMPORT_MODULES)

@app.route('/api/admin/import/preview', methods=['POST'])
@admin_required
def import_preview_v2():
    module=request.form.get('module',''); f=request.files.get('file')
    if not f: return jsonify({'error':'file required'}),400
    rows=_parse_import_file(f); headers=list(rows[0].keys()) if rows else []; norm=[_norm_header(h) for h in headers]; cfg=IMPORT_MODULES.get(module,{})
    auto={}
    for col in cfg.get('columns',[]):
        if col in norm: auto[col]=headers[norm.index(col)]
    _,issues,summary=validate_import_rows(module,rows[:200],auto)
    return jsonify({'success':True,'headers':headers,'auto_mapping':auto,'preview':rows[:10],'issues_preview':issues[:50],'summary_preview':summary,'total_rows':len(rows)})

@app.route('/api/admin/import/validate', methods=['POST'])
@admin_required
def import_validate_v2():
    module=request.form.get('module',''); mapping=json.loads(request.form.get('mapping','{}') or '{}'); f=request.files.get('file')
    if not f: return jsonify({'error':'file required'}),400
    rows=_parse_import_file(f); _,issues,summary=validate_import_rows(module,rows,mapping)
    return jsonify({'success':summary['error_count']==0,'issues':issues[:500],'summary':summary})

def _bts_lookup2(cur,lac,cell_id):
    if not lac or not cell_id: return None
    cur.execute('SELECT * FROM bts_tower_records WHERE lac=%s AND cell_id=%s LIMIT 1',(str(lac),str(cell_id))); return cur.fetchone()

@app.route('/api/admin/import/execute', methods=['POST'])
@admin_required
def import_execute_v2():
    module=request.form.get('module',''); mapping=json.loads(request.form.get('mapping','{}') or '{}'); case_ref=request.form.get('case_reference') or None; f=request.files.get('file')
    if module not in IMPORT_MODULES: return jsonify({'error':'invalid module'}),400
    if not f: return jsonify({'error':'file required'}),400
    rows=_parse_import_file(f); rows,issues,summary=validate_import_rows(module,rows,mapping)
    if summary['error_count']>0: return jsonify({'error':'Validation Failed','issues':issues,'summary':summary}),400
    conn=get_db(); cur=conn.cursor(dictionary=True); cur.execute("INSERT INTO import_batches (source_type,original_filename,total_rows,imported_by,status) VALUES (%s,%s,%s,%s,'imported')",(module,f.filename,len(rows),session.get('admin_name'))); batch=cur.lastrowid
    imported=0; enriched=0
    for row in rows:
        if module=='subscriber': cur.execute("INSERT INTO subscriber_records (mobile_number,subscriber_name,father_name,address,district,state,operator,sim_type,activation_date,status,alternate_number,email,id_type,id_number,import_batch_id,raw_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE subscriber_name=VALUES(subscriber_name),address=VALUES(address),raw_json=VALUES(raw_json)",(row.get('mobile_number'),row.get('subscriber_name'),row.get('father_name'),row.get('address'),row.get('district'),row.get('state'),row.get('operator'),row.get('sim_type'),_parse_date_or_none(row.get('activation_date')),row.get('status'),row.get('alternate_number'),row.get('email'),row.get('id_type'),row.get('id_number'),batch,json.dumps(row.get('_raw',row),default=str)))
        elif module=='vehicle': cur.execute("INSERT INTO vehicle_records (registration_number,owner_name,father_name,address,vehicle_class,manufacturer,model,engine_number,chassis_number,fuel_type,registration_date,fitness_validity,insurance_validity,district,import_batch_id,raw_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE owner_name=VALUES(owner_name),address=VALUES(address),raw_json=VALUES(raw_json)",(row.get('registration_number'),row.get('owner_name'),row.get('father_name'),row.get('address'),row.get('vehicle_class'),row.get('manufacturer'),row.get('model'),row.get('engine_number'),row.get('chassis_number'),row.get('fuel_type'),_parse_date_or_none(row.get('registration_date')),_parse_date_or_none(row.get('fitness_validity')),_parse_date_or_none(row.get('insurance_validity')),row.get('district'),batch,json.dumps(row.get('_raw',row),default=str)))
        elif module=='bts': cur.execute("INSERT INTO bts_tower_records (lac,cell_id,operator,tower_id,tower_name,latitude,longitude,full_address,district,state,technology,azimuth,import_batch_id,raw_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE full_address=VALUES(full_address),latitude=VALUES(latitude),longitude=VALUES(longitude),district=VALUES(district),state=VALUES(state),raw_json=VALUES(raw_json)",(row.get('lac'),row.get('cell_id'),row.get('operator'),row.get('tower_id'),row.get('tower_name'),row.get('latitude') or None,row.get('longitude') or None,row.get('full_address'),row.get('district'),row.get('state'),row.get('technology'),row.get('azimuth') or None,batch,json.dumps(row.get('_raw',row),default=str)))
        elif module=='cdr':
            b=_bts_lookup2(cur,row.get('lac'),row.get('cell_id')); enriched += 1 if b else 0
            cur.execute("INSERT INTO cdr_records (case_reference,calling_number,called_number,start_time,end_time,duration,imei,imsi,lac,cell_id,tower_address,tower_latitude,tower_longitude,tower_district,import_batch_id,raw_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(case_ref,row.get('calling_number'),row.get('called_number'),_parse_date_or_none(row.get('start_time')),_parse_date_or_none(row.get('end_time')),int(row.get('duration') or 0),row.get('imei'),row.get('imsi'),row.get('lac'),row.get('cell_id'),b.get('full_address') if b else None,b.get('latitude') if b else None,b.get('longitude') if b else None,b.get('district') if b else None,batch,json.dumps(row.get('_raw',row),default=str)))
        elif module=='ipdr':
            b=_bts_lookup2(cur,row.get('lac'),row.get('cell_id')); enriched += 1 if b else 0; coords=f"{b.get('latitude')},{b.get('longitude')}" if b and b.get('latitude') else None
            cur.execute("INSERT INTO ipdr_records (case_reference,subscriber_number,source_ip,destination_ip,timestamp,session_duration,lac,cell_id,tower_address,tower_coordinates,import_batch_id,raw_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(case_ref,row.get('subscriber_number'),row.get('source_ip'),row.get('destination_ip'),_parse_date_or_none(row.get('timestamp')),int(row.get('session_duration') or 0),row.get('lac'),row.get('cell_id'),b.get('full_address') if b else None,coords,batch,json.dumps(row.get('_raw',row),default=str)))
        imported+=1
    conn.commit(); conn.close(); return jsonify({'success':True,'batch_id':batch,'imported':imported,'enriched_rows':enriched,'summary':summary})

@app.route('/api/admin/import/batches', methods=['GET'])
@admin_required
def import_batches_v2():
    conn=get_db(); cur=conn.cursor(dictionary=True); cur.execute('SELECT * FROM import_batches ORDER BY created_at DESC LIMIT 100'); rows=cur.fetchall(); conn.close()
    for r in rows:
        if r.get('created_at'): r['created_at']=r['created_at'].isoformat()
    return jsonify(rows)

@app.route('/api/analysis/workspace/<int:batch_id>', methods=['GET'])
def analysis_workspace_v2(batch_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute('SELECT * FROM import_batches WHERE id=%s', (batch_id,))
    batch = cur.fetchone()
    if not batch:
        conn.close()
        return jsonify({'error': 'Batch not found'}), 404
    table = 'cdr_records' if batch['source_type'] == 'cdr' else 'ipdr_records' if batch['source_type'] == 'ipdr' else None
    if not table:
        conn.close()
        return jsonify({'error': 'Workspace only for CDR/IPDR'}), 400
    cur.execute(f'SELECT * FROM {table} WHERE import_batch_id=%s ORDER BY id LIMIT 5000', (batch_id,))
    rows = cur.fetchall()
    conn.close()

    for r in rows:
        for k, v in list(r.items()):
            if hasattr(v, 'isoformat'):
                r[k] = v.isoformat()

    _DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

    if batch['source_type'] == 'cdr':
        contacts: dict[str, int] = {}
        locs: dict[str, int] = {}
        imeis: dict[str, int] = {}
        edges: list[dict] = []
        call_pairs: dict[tuple, int] = {}
        hour_of_day: dict[int, int] = {h: 0 for h in range(24)}
        day_of_week: dict[str, int] = {d: 0 for d in _DAY_NAMES}
        durations: list[int] = []

        for r in rows:
            calling = r.get('calling_number')
            called = r.get('called_number')
            if called:
                contacts[called] = contacts.get(called, 0) + 1
            loc = r.get('tower_address') or f"{r.get('lac')}:{r.get('cell_id')}"
            locs[loc] = locs.get(loc, 0) + 1
            imei = r.get('imei')
            if imei:
                imeis[imei] = imeis.get(imei, 0) + 1
            if calling and called:
                edges.append({'from': calling, 'to': called, 'duration': r.get('duration')})
                pair = tuple(sorted([calling, called]))
                call_pairs[pair] = call_pairs.get(pair, 0) + 1
            try:
                dur = int(r.get('duration') or 0)
                if dur > 0:
                    durations.append(dur)
            except (ValueError, TypeError):
                pass
            # Time analysis from stored datetime fields
            for dt_field in ('date_time', 'call_date', 'start_time', 'timestamp'):
                dt_raw = r.get(dt_field)
                if dt_raw and isinstance(dt_raw, str):
                    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
                        try:
                            dt = datetime.strptime(dt_raw[:19], fmt)
                            hour_of_day[dt.hour] = hour_of_day.get(dt.hour, 0) + 1
                            day_of_week[_DAY_NAMES[dt.weekday()]] = day_of_week.get(_DAY_NAMES[dt.weekday()], 0) + 1
                            break
                        except (ValueError, AttributeError):
                            continue
                    break

        common_contacts = sorted(
            [{'pair': list(p), 'total_calls': c} for p, c in call_pairs.items() if c >= 2],
            key=lambda x: -x['total_calls']
        )[:20]
        peak_hour = max(hour_of_day, key=lambda h: hour_of_day[h]) if any(hour_of_day.values()) else None
        peak_day = max(day_of_week, key=lambda d: day_of_week[d]) if any(day_of_week.values()) else None

        tabs = {
            'master_cdr': rows,
            'max_calls': sorted([{'number': k, 'total_calls': v} for k, v in contacts.items() if k], key=lambda x: -x['total_calls']),
            'max_locations': sorted([{'location': k, 'frequency': v} for k, v in locs.items() if k and k != 'None:None'], key=lambda x: -x['frequency']),
            'imei_used': sorted([{'imei': k, 'total_usage': v} for k, v in imeis.items() if k], key=lambda x: -x['total_usage']),
            'common_contacts': common_contacts,
            'movement_analysis': rows,
            'timeline': sorted(rows, key=lambda r: r.get('date_time') or r.get('call_date') or ''),
            'tower_analysis': sorted([{'location': k, 'frequency': v} for k, v in locs.items() if k and k != 'None:None'], key=lambda x: -x['frequency']),
            'communication_graph': {'edges': edges},
            'time_analysis': {
                'hour_of_day': hour_of_day,
                'day_of_week': day_of_week,
                'peak_hour': peak_hour,
                'peak_day': peak_day,
            },
            'duration_stats': {
                'average_seconds': int(sum(durations) / len(durations)) if durations else 0,
                'max_seconds': max(durations) if durations else 0,
                'total_seconds': sum(durations),
            },
            'report_summary': {
                'total_records': len(rows),
                'unique_contacts': len(contacts),
                'unique_locations': len(locs),
                'unique_imeis': len(imeis),
                'common_contact_pairs': len(common_contacts),
                'peak_hour': peak_hour,
                'peak_day': peak_day,
            },
        }
    else:
        dst: dict[str, int] = {}
        dst_bytes: dict[str, int] = {}
        src: dict[str, int] = {}
        locs: dict[str, int] = {}
        protocols: dict[str, int] = {}
        total_bytes = 0
        hour_of_day: dict[int, int] = {h: 0 for h in range(24)}
        day_of_week: dict[str, int] = {d: 0 for d in _DAY_NAMES}

        for r in rows:
            sip = r.get('source_ip')
            dip = r.get('destination_ip')
            if sip:
                src[sip] = src.get(sip, 0) + 1
            if dip:
                dst[dip] = dst.get(dip, 0) + 1
            loc = r.get('tower_address') or f"{r.get('lac')}:{r.get('cell_id')}"
            locs[loc] = locs.get(loc, 0) + 1
            proto = r.get('protocol') or r.get('app_protocol') or 'unknown'
            protocols[proto] = protocols.get(proto, 0) + 1
            try:
                nb = int(r.get('bytes_transferred') or r.get('total_bytes') or 0)
                if nb > 0:
                    total_bytes += nb
                    if dip:
                        dst_bytes[dip] = dst_bytes.get(dip, 0) + nb
            except (ValueError, TypeError):
                pass
            for dt_field in ('start_time', 'date_time', 'timestamp', 'session_start'):
                dt_raw = r.get(dt_field)
                if dt_raw and isinstance(dt_raw, str):
                    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
                        try:
                            dt = datetime.strptime(dt_raw[:19], fmt)
                            hour_of_day[dt.hour] = hour_of_day.get(dt.hour, 0) + 1
                            day_of_week[_DAY_NAMES[dt.weekday()]] = day_of_week.get(_DAY_NAMES[dt.weekday()], 0) + 1
                            break
                        except (ValueError, AttributeError):
                            continue
                    break

        peak_hour = max(hour_of_day, key=lambda h: hour_of_day[h]) if any(hour_of_day.values()) else None
        peak_day = max(day_of_week, key=lambda d: day_of_week[d]) if any(day_of_week.values()) else None

        tabs = {
            'master_ipdr': rows,
            'top_source_ip': sorted([{'ip': k, 'sessions': v} for k, v in src.items()], key=lambda x: -x['sessions']),
            'top_destination_ip': sorted([{'ip': k, 'sessions': v} for k, v in dst.items()], key=lambda x: -x['sessions']),
            'top_ips_by_data': sorted([{'ip': k, 'bytes': v, 'mb': round(v / (1024 * 1024), 2)} for k, v in dst_bytes.items()], key=lambda x: -x['bytes'])[:10],
            'top_domains': [],
            'protocol_breakdown': protocols,
            'location_analysis': sorted([{'location': k, 'frequency': v} for k, v in locs.items() if k and k != 'None:None'], key=lambda x: -x['frequency']),
            'tower_analysis': sorted([{'location': k, 'frequency': v} for k, v in locs.items() if k and k != 'None:None'], key=lambda x: -x['frequency']),
            'time_analysis': {
                'hour_of_day': hour_of_day,
                'day_of_week': day_of_week,
                'peak_hour': peak_hour,
                'peak_day': peak_day,
            },
            'session_analysis': {
                'total_sessions': len(rows),
                'total_bytes': total_bytes,
                'total_mb': round(total_bytes / (1024 * 1024), 2),
            },
            'threat_analysis': [],
            'timeline': sorted(rows, key=lambda r: r.get('start_time') or r.get('date_time') or ''),
            'report_summary': {
                'total_records': len(rows),
                'unique_source_ips': len(src),
                'unique_destination_ips': len(dst),
                'total_data_mb': round(total_bytes / (1024 * 1024), 2),
                'peak_hour': peak_hour,
                'peak_day': peak_day,
            },
        }

    return jsonify({'type': batch['source_type'], 'batch': {k: (v.isoformat() if hasattr(v, 'isoformat') else v) for k, v in batch.items()}, 'tabs': tabs})



@app.route('/workspace/<int:batch_id>')
def workspace_page(batch_id):
    return render_template('workspace.html', batch_id=batch_id)

@app.route('/api/admin/import/report/<int:batch_id>')
@admin_required
def import_report_v2(batch_id):
    return analysis_workspace_v2(batch_id)

@app.route('/api/admin/import/report/<int:batch_id>/pdf')
@admin_required
def import_report_pdf_v2(batch_id):
    data=analysis_workspace_v2(batch_id).get_json(); return Response(json.dumps(data,indent=2),mimetype='application/json',headers={'Content-Disposition':f'attachment; filename=sentinel_report_{batch_id}.json'})

@app.route('/api/admin/data/rollback/<int:batch_id>', methods=['POST'])
@admin_required
def rollback_batch_v2(batch_id):
    conn=get_db(); cur=conn.cursor(); deleted=0
    for table,col in [('cdr_records','import_batch_id'),('ipdr_records','import_batch_id'),('subscriber_records','import_batch_id'),('vehicle_records','import_batch_id'),('bts_tower_records','import_batch_id'),('master_data_records','import_batch_id'),('import_batches','id')]:
        try: cur.execute(f'DELETE FROM {table} WHERE {col}=%s',(batch_id,)); deleted+=cur.rowcount
        except Exception: pass
    conn.commit(); conn.close(); return jsonify({'success':True,'deleted':deleted})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
