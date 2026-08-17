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
import hashlib
import hmac
import io
import json
import os
import re
import secrets
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
from xml.sax.saxutils import escape as xml_escape

import mysql.connector
import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)

# FLASK_ENV is treated as production-like unless explicitly set to "development" —
# an unset value must fail closed, not silently behave as dev. This is what lets
# SECRET_KEY / ENCRYPTION_KEY fail fast below instead of falling back to an
# insecure or ephemeral value that only "happens" to be safe in dev.
FLASK_ENV = os.getenv("FLASK_ENV", "production")
IS_DEV_ENV = FLASK_ENV == "development"

_secret_key = os.getenv("SECRET_KEY")
if not _secret_key:
    if not IS_DEV_ENV:
        raise RuntimeError(
            "SECRET_KEY is not set. Refusing to start outside FLASK_ENV=development — "
            "an insecure fallback here means session cookies (including admin sessions) "
            "are forgeable. Generate one with: "
            'python3 -c "import secrets; print(secrets.token_urlsafe(48))" '
            "and set it in .env."
        )
    _secret_key = "dev_secret_change_this"
    print("WARNING: SECRET_KEY not set — using an insecure development-only fallback "
          "(allowed because FLASK_ENV=development). Do not deploy like this.")
app.secret_key = _secret_key
app.permanent_session_lifetime = timedelta(minutes=int(os.getenv("SESSION_TIMEOUT_MIN", "60")))

# Session cookie hardening. HTTPONLY and SAMESITE=Lax apply unconditionally — neither
# has a dev-mode downside. SECURE (browser will not send the cookie over plain HTTP at
# all) is relaxed only in dev, since local `flask run` / a throwaway Docker MySQL setup
# is normally accessed over http://localhost without TLS in front.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = not IS_DEV_ENV

# X-Forwarded-For is client-supplied and must never be trusted blindly — an attacker
# who can set it defeats the login rate limit, the lockout counter and the IP recorded
# in activity_log. Only honour as many hops as we actually run behind.
# TRUSTED_PROXY_COUNT=0 means "no proxy": remote_addr is used and the header ignored.
TRUSTED_PROXY_COUNT = int(os.getenv("TRUSTED_PROXY_COUNT", "0"))
if TRUSTED_PROXY_COUNT > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=TRUSTED_PROXY_COUNT,
        x_proto=TRUSTED_PROXY_COUNT,
        x_host=TRUSTED_PROXY_COUNT,
        x_port=0,
        x_prefix=0,
    )

BASE_DIR = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXT = {"png", "jpg", "jpeg", "pdf"}
MAX_FILE_SIZE = 5 * 1024 * 1024

# Upper bound on a single /api/events SSE connection's lifetime — see event_stream().
EVENT_STREAM_MAX_SECONDS = 600

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
    if not IS_DEV_ENV:
        raise RuntimeError(
            "ENCRYPTION_KEY is not set. Refusing to start outside FLASK_ENV=development — "
            "a generated-at-restart key would silently and permanently brick every existing "
            "encrypted gov-ID upload, 2FA secret and stored API key. Generate one with: "
            'python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" '
            "and set it in .env."
        )
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


def session_required(f):
    """Require either an authenticated user or admin session.

    For endpoints whose content is the same regardless of which side is
    calling (e.g. the /api/events sync heartbeat, consumed by both
    dashboard.html and admin.html) — this only excludes fully anonymous
    callers, not one role or the other.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not (session.get("is_user") or session.get("is_admin")):
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


# ─────────────────────────────────────────────
# CSRF PROTECTION (lightweight double-submit token)
#
# No CSRF protection existed anywhere before this: every session-authenticated
# state-changing endpoint was forgeable by a page the victim's browser merely
# visited while logged in — the browser attaches the session cookie
# automatically to a cross-site request, and Flask's default session config
# has no SameSite restriction to stop that.
#
# A random token is minted into the server-side session at login (both user
# and admin, see user_login()/admin_login()) and the frontend must echo it
# back in the X-CSRF-Token header on every state-changing request. An
# attacker's cross-site form/fetch carries the victim's cookies but cannot
# read anything out of the victim's session (same-origin policy), so it has
# no way to reproduce the header.
#
# Deliberately scoped to *authenticated* requests only: unauthenticated
# POSTs (signup, login itself, password-reset request/confirm) have no
# session to protect yet, and standing up a pre-session anonymous CSRF
# cookie is unneeded complexity for this threat model — the sensitive,
# side-effecting actions are all behind @user_required/@admin_required.
# ─────────────────────────────────────────────
CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


@app.before_request
def _enforce_csrf():
    if request.method in CSRF_SAFE_METHODS:
        return None
    if not (session.get("is_user") or session.get("is_admin")):
        return None  # no authenticated session to forge yet
    expected = session.get("csrf_token")
    provided = request.headers.get("X-CSRF-Token", "")
    if not expected or not provided or not hmac.compare_digest(str(expected), provided):
        return jsonify({"error": "CSRF token missing or invalid. Refresh the page and try again."}), 403
    return None


@app.route("/api/csrf-token", methods=["GET"])
def csrf_token_endpoint():
    """Issue (or return the existing) CSRF token for the current session.

    Only meaningful once a session is authenticated — there is nothing to
    protect before that, and the frontend fetch wrapper only needs a token
    once it starts issuing POST/PUT/DELETE calls.
    """
    if not (session.get("is_user") or session.get("is_admin")):
        return jsonify({"error": "Authentication required"}), 401
    if not session.get("csrf_token"):
        session["csrf_token"] = _new_csrf_token()
    return jsonify({"csrf_token": session["csrf_token"]})


# ─────────────────────────────────────────────
# SECURITY HEADERS
#
# No security headers were set anywhere before this. The CSP below allows
# 'unsafe-inline' for scripts and styles because every template ships its CSS
# and JS inline with no nonce plumbing — tightening that is a real frontend
# change (adding a per-request nonce to every <script>/<style> tag across 9
# templates), not a one-line header, so it is left as a follow-up rather than
# attempted half-done here. img-src allows data: for the base64 2FA QR codes
# generated in setup_2fa().
# ─────────────────────────────────────────────
_CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = _CSP_POLICY
    # Only meaningful (and only sent) once the app is actually reachable over HTTPS —
    # sending it in dev over plain http://localhost would just be noise, and could be
    # actively wrong if a future request ever is proxied without TLS.
    if not IS_DEV_ENV and request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


# ─────────────────────────────────────────────
# ACCOUNT STATE vs DATA CLEARANCE
#
# These are two orthogonal facts and are deliberately kept in two columns:
#   bot_users.status              — can this account sign in at all
#   bot_users.verification_status — has this operator been cleared to query
#                                   subscriber data (the LEA gov-ID review)
#
# Anyone may sign up and sign in. Signing in buys you the dashboard, your profile
# and the pricing page — nothing else. Every route that returns real subscriber
# data must be behind @verified_required, and paying for credits does not grant
# clearance: money buys credits, the gov-ID review buys access.
# ─────────────────────────────────────────────
LOGIN_BLOCKED_STATUSES = {"blocked", "rejected", "inactive"}


def load_current_user(cursor=None):
    """Fetch the signed-in user's live row. Never trust session for authorization
    state — status and clearance can be revoked mid-session by an admin."""
    user_id = session.get("user_id")
    if not user_id:
        return None

    def _fetch(cur):
        cur.execute(
            """
            SELECT id, phone, name, department, official_email, credits, status,
                   verification_status, twofa_enabled
            FROM bot_users WHERE id=%s LIMIT 1
            """,
            (user_id,),
        )
        return cur.fetchone()

    if cursor is not None:
        return _fetch(cursor)
    with db_conn() as conn:
        return _fetch(conn.cursor(dictionary=True))


def verified_required(f):
    """Require an authenticated user who has passed LEA verification.

    Returns 403 with a machine-readable `reason` so the dashboard can render the
    right call to action (finish signup vs. awaiting review vs. rejected) instead
    of a flat error string.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_user"):
            return jsonify({"error": "Authentication required"}), 401
        user = load_current_user()
        if not user:
            session.clear()
            return jsonify({"error": "Authentication required"}), 401
        if user.get("status") in LOGIN_BLOCKED_STATUSES:
            session.clear()
            return jsonify({"error": f"Account is {user.get('status')}.", "reason": "account_blocked"}), 403
        state = user.get("verification_status") or "unverified"
        if state != "approved":
            return jsonify({
                "error": VERIFICATION_MESSAGES.get(state, VERIFICATION_MESSAGES["unverified"]),
                "reason": f"verification_{state}",
                "verification_status": state,
            }), 403
        return f(*args, **kwargs)

    return wrapper


VERIFICATION_MESSAGES = {
    "unverified": "Submit your LEA verification documents to unlock lookups.",
    "pending": "Your LEA verification is under review. Lookups unlock once it is approved.",
    "rejected": "Your LEA verification was rejected. Contact the administrator.",
}


# ─────────────────────────────────────────────
# SINGLE-USE TOKENS (activation / password reset)
# Stored hashed: a leaked database must not yield usable reset links.
# ─────────────────────────────────────────────
PASSWORD_RESET_TTL_HOURS = int(os.getenv("PASSWORD_RESET_TTL_HOURS", "24"))
MIN_PASSWORD_LENGTH = 10


def password_problem(password: str) -> str | None:
    """Return a human-readable reason the password is unacceptable, or None."""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain both letters and numbers."
    return None


def issue_reset_token(cursor, user_id: int, purpose: str = "reset", issued_by: str = "") -> str:
    """Create a single-use token, invalidating any outstanding ones for the user.

    Returns the plaintext token — the only moment it exists in readable form.
    """
    token = secrets.token_urlsafe(32)
    cursor.execute(
        "UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=%s AND used_at IS NULL",
        (user_id,),
    )
    cursor.execute(
        """
        INSERT INTO password_reset_tokens (user_id, token_hash, purpose, issued_by, expires_at)
        VALUES (%s,%s,%s,%s, DATE_ADD(NOW(), INTERVAL %s HOUR))
        """,
        (user_id, generate_password_hash(token), purpose, issued_by or None, PASSWORD_RESET_TTL_HOURS),
    )
    return token


def consume_reset_token(cursor, token: str):
    """Validate and burn a token. Returns the user_id, or None if unusable.

    The hash is salted per-row so we cannot look the token up directly; we scan
    only live, unexpired rows, which is a small set.
    """
    if not token:
        return None
    cursor.execute(
        """
        SELECT id, user_id, token_hash FROM password_reset_tokens
        WHERE used_at IS NULL AND expires_at > NOW()
        ORDER BY created_at DESC LIMIT 200
        """
    )
    for row in cursor.fetchall():
        if check_password_hash(row["token_hash"], token):
            cursor.execute("UPDATE password_reset_tokens SET used_at=NOW() WHERE id=%s", (row["id"],))
            return row["user_id"]
    return None


def consume_recovery_code(cursor, user_row, code: str, table: str = "bot_users") -> bool:
    """Verify a 2FA recovery code and remove it. Codes are single-use.

    Stored as a JSON array of password hashes, so the matching one is found by
    trial and the survivors are written back.
    """
    code = (code or "").strip()
    if not code:
        return False
    try:
        hashes = json.loads(user_row.get("recovery_codes_hash") or "[]")
    except (ValueError, TypeError):
        return False

    matched = False
    remaining = []
    for stored in hashes:
        if not matched and check_password_hash(stored, code):
            matched = True
            continue
        remaining.append(stored)

    if not matched:
        return False
    cursor.execute(
        f"UPDATE {table} SET recovery_codes_hash=%s WHERE id=%s",
        (json.dumps(remaining), user_row["id"]),
    )
    return True


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
    """Real peer address.

    ProxyFix (configured at startup from TRUSTED_PROXY_COUNT) has already rewritten
    request.remote_addr from the trusted number of X-Forwarded-For hops, so reading
    the raw header here would re-introduce the spoof it exists to prevent.
    """
    return (request.remote_addr or "").strip()


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
    if not session.get("is_user"):
        return redirect("/login")
    return render_template("dashboard.html")


@app.route("/admin")
def admin_page():
    return render_template("admin.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/pricing")
def pricing_page():
    return render_template("pricing.html")


@app.route("/reset-password")
def reset_password_page():
    return render_template("reset_password.html")


@app.route("/analysis")
@app.route("/cdr-analysis")
def cdr_analysis_page():
    """Google Sheets-style CDR / IPDR spreadsheet analysis interface."""
    return render_template("cdr_analysis.html")


@app.route("/robots.txt")
def robots_txt():
    return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")


# ─────────────────────────────────────────────
# ERROR HANDLERS
# ─────────────────────────────────────────────
@app.errorhandler(404)
def handle_404(e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def handle_500(e):
    return render_template("error.html", code=500, message="Something went wrong on our end."), 500


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
# LEA VERIFICATION
#
# This used to be the public front door: an unauthenticated multipart endpoint
# that wrote two files to disk per request, with no rate limit and no CAPTCHA.
# Signup now comes first, so verification is submitted from inside the dashboard
# by an account we can name, rate-limit and hold responsible. Identity fields come
# from the signed-in account rather than the form, so an applicant cannot claim to
# be a different officer than the one who signed in.
# ─────────────────────────────────────────────
@app.route("/api/lea/register", methods=["POST"])
@user_required
@rate_limit(max_requests=5, window_seconds=3600, per="user")
def lea_register():
    form = request.form
    required = ["department", "designation", "service_id", "unit", "jurisdiction"]
    for field in required:
        if not form.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    with db_conn() as conn:
        account = load_current_user(conn.cursor(dictionary=True))
    if not account:
        session.clear()
        return jsonify({"error": "Authentication required"}), 401
    if account.get("verification_status") == "approved":
        return jsonify({"error": "Your account is already verified."}), 409
    if account.get("verification_status") == "pending":
        return jsonify({"error": "You already have a verification request under review."}), 409

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
        (user_id, full_name, phone, official_email, department, designation, service_id,
         unit, jurisdiction, notes, id_proof_path, dept_id_path, status)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending')
        """,
        (
            account["id"],
            account.get("name") or "",
            account["phone"],
            account.get("official_email") or "",
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
    new_id = cursor.lastrowid
    cursor.execute(
        """
        UPDATE bot_users
        SET verification_status='pending', lea_application_id=%s, department=%s
        WHERE id=%s
        """,
        (new_id, form["department"], account["id"]),
    )
    conn.commit()
    conn.close()

    application_id = f"LEA-{datetime.now().year}-{new_id:04d}"
    log_activity(account["id"], "lea_verification_submitted", f"{account.get('name')} submitted {application_id}")
    return jsonify({"success": True, "application_id": application_id, "verification_status": "pending"}), 200




# ─────────────────────────────────────────────
# USER AUTH
#
# Self-serve signup. An account is created immediately with a password the user
# chooses, and starts life unverified: it can sign in and see the dashboard,
# pricing and its own profile, but every data route is behind @verified_required.
# ─────────────────────────────────────────────
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?\d{10,15}$")


def normalise_phone(raw: str) -> str:
    """Strip formatting so the same number cannot be registered twice in two shapes."""
    cleaned = re.sub(r"[\s\-()]", "", (raw or "").strip())
    return cleaned


@app.route("/api/user/signup", methods=["POST"])
@rate_limit(max_requests=5, window_seconds=3600, per="ip")
def user_signup():
    data = request.json or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = normalise_phone(data.get("phone") or "")
    password = data.get("password") or ""
    ip = _client_ip()

    if not name:
        return jsonify({"error": "Full name is required"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"error": "Enter a valid email address"}), 400
    if not PHONE_RE.match(phone):
        return jsonify({"error": "Enter a valid phone number (10-15 digits)"}), 400
    problem = password_problem(password)
    if problem:
        return jsonify({"error": problem}), 400

    free_credits = int(get_setting("signup_free_credits", "0"))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id FROM bot_users WHERE phone=%s OR official_email=%s LIMIT 1", (phone, email))
    if cursor.fetchone():
        conn.close()
        # Deliberately vague: confirming which of the two is taken would let an
        # attacker enumerate registered officers by phone number.
        return jsonify({"error": "An account already exists for that phone or email. Try signing in."}), 409

    try:
        cursor.execute(
            """
            INSERT INTO bot_users
                (phone, name, official_email, password_hash, password_set_at,
                 credits, status, verification_status)
            VALUES (%s,%s,%s,%s,NOW(),%s,'pending','unverified')
            """,
            (phone, name, email, generate_password_hash(password), free_credits),
        )
        user_id = cursor.lastrowid
        if free_credits:
            cursor.execute(
                "INSERT INTO credit_transactions (phone, type, amount, reason) VALUES (%s,'credit',%s,'signup_bonus')",
                (phone, free_credits),
            )
        conn.commit()
    except mysql.connector.Error:
        conn.close()
        return jsonify({"error": "An account already exists for that phone or email. Try signing in."}), 409
    conn.close()

    log_activity(user_id, "user_signup", f"{name} <{email}> signed up from {ip}")

    session.clear()
    session.permanent = True
    session["is_user"] = True
    session["user_id"] = user_id
    session["user_phone"] = phone
    session["user_name"] = name
    session["user_department"] = ""
    session["user_login_at"] = datetime.utcnow().isoformat()
    session["csrf_token"] = _new_csrf_token()

    return jsonify({
        "success": True,
        "csrf_token": session["csrf_token"],
        "redirect": "/dashboard",
        "user": {
            "id": user_id,
            "phone": phone,
            "name": name,
            "email": email,
            "credits": free_credits,
            "status": "pending",
            "verification_status": "unverified",
        },
    }), 201



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
            SELECT id, phone, name, department, official_email, password_hash, credits, status,
                   COALESCE(verification_status, 'unverified') AS verification_status,
                   twofa_enabled, twofa_secret, recovery_codes_hash,
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
                   'unverified' AS verification_status,
                   0 AS twofa_enabled, NULL AS twofa_secret, NULL AS recovery_codes_hash,
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
        # Same status/message as a wrong-password rejection below — a distinguishable
        # response here would let an attacker enumerate which phone/email is registered.
        return jsonify({"error": "Invalid credentials"}), 401

    # Lockout check
    limit = int(get_setting("user_failed_login_limit", os.getenv("FAILED_LOGIN_LIMIT", "5")))
    lockout_hours = int(get_setting("lockout_hours", os.getenv("LOCKOUT_HOURS", "2")))
    locked_until = mysql_dt_to_aware(user.get("locked_until"))
    if locked_until and locked_until > now_utc():
        remaining = int((locked_until - now_utc()).total_seconds())
        conn.close()
        return jsonify({"error": "Account locked due to too many failed attempts.", "locked": True, "remaining_seconds": remaining}), 423

    # Unverified accounts may sign in — they just cannot query anything. Only an
    # explicitly disabled account is refused at the door.
    if user.get("status") in LOGIN_BLOCKED_STATUSES:
        conn.close()
        return jsonify({"error": f"Account is {user.get('status')}. Contact the administrator."}), 403

    stored_hash = user.get("password_hash")

    # No usable credential means fail closed. There is no fallback password: an
    # account with no hash is one an admin must issue a reset token for.
    password_ok = bool(stored_hash) and check_password_hash(stored_hash, password)

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
        totp_ok = bool(secret) and pyotp.TOTP(secret).verify(otp, valid_window=1)
        if not totp_ok:
            # Recovery codes were being generated and handed out but never checked,
            # so losing an authenticator meant a permanent lockout. Accept one here
            # and burn it — a recovery code is single-use by definition.
            if not consume_recovery_code(cursor, user, otp):
                conn.close()
                return jsonify({"error": "Invalid 2FA code", "twofa_required": True}), 401
            conn.commit()
            log_activity(user["id"], "recovery_code_used", f"Recovery code consumed at login from {ip}")

    # Successful login — reset counter
    try:
        cursor.execute("UPDATE bot_users SET failed_login_count=0, locked_until=NULL WHERE id=%s", (user["id"],))
        conn.commit()
    except Exception:
        pass
    conn.close()

    # Regenerate the session on privilege change so a pre-login fixated cookie
    # cannot be reused as an authenticated one.
    session.clear()
    session.permanent = True
    session["is_user"] = True
    session["user_id"] = user["id"]
    session["user_phone"] = user["phone"]
    session["user_name"] = user.get("name") or "Operator"
    session["user_department"] = user.get("department") or ""
    session["user_login_at"] = datetime.utcnow().isoformat()
    session["csrf_token"] = _new_csrf_token()

    log_activity(user["id"], "user_login", f"{user.get('name') or identifier} logged in from {ip}")

    return jsonify({
        "success": True,
        "csrf_token": session["csrf_token"],
        "redirect": "/dashboard",
        "user": {
            "id": user["id"],
            "phone": user["phone"],
            "name": user.get("name") or "Operator",
            "email": user.get("official_email") or "",
            "department": user.get("department") or "",
            "credits": user.get("credits", 0),
            "status": user.get("status"),
            "verification_status": user.get("verification_status") or "unverified",
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
    """Live account state — credits and clearance are read from the database, not
    the session cookie, so an admin revoking access takes effect on the next poll."""
    if not session.get("is_user"):
        return jsonify({"logged_in": False}), 401
    user = load_current_user()
    if not user:
        session.clear()
        return jsonify({"logged_in": False}), 401
    if user.get("status") in LOGIN_BLOCKED_STATUSES:
        session.clear()
        return jsonify({"logged_in": False, "error": f"Account is {user.get('status')}."}), 401

    state = user.get("verification_status") or "unverified"
    return jsonify({
        "logged_in": True,
        "user": {
            "id": user["id"],
            "phone": user["phone"],
            "name": user.get("name"),
            "email": user.get("official_email") or "",
            "department": user.get("department") or "",
            "credits": int(user.get("credits") or 0),
            "status": user.get("status"),
            "verification_status": state,
            "verified": state == "approved",
            "twofa_enabled": bool(user.get("twofa_enabled")),
            "gate_message": "" if state == "approved" else VERIFICATION_MESSAGES.get(state, ""),
        },
    })


@app.route("/api/user/password-reset/request", methods=["POST"])
@rate_limit(max_requests=5, window_seconds=900, per="ip")
def user_password_reset_request():
    """Record a reset request for the admin queue.

    SMTP and SMS are both off, so nothing can be delivered automatically. Rather
    than returning a success message it does not honour, this files a request the
    admin sees and answers by issuing a token out of band. The response is
    identical whether or not the account exists, so it cannot be used to
    enumerate registered officers.
    """
    identifier = (request.json or {}).get("identifier", "").strip()
    if not identifier:
        return jsonify({"error": "Phone or email is required"}), 400

    generic = {
        "success": True,
        "message": "If an account exists for that phone or email, the administrator "
                   "has been notified and will issue a reset code out of band.",
    }
    try:
        with db_conn() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT id, name FROM bot_users WHERE phone=%s OR official_email=%s LIMIT 1",
                (normalise_phone(identifier), identifier.lower()),
            )
            row = cursor.fetchone()
            if row:
                log_activity(row["id"], "password_reset_requested",
                             f"{row.get('name') or identifier} requested a password reset from {_client_ip()}")
    except Exception:
        pass
    return jsonify(generic)


@app.route("/api/user/password-reset/confirm", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=900, per="ip")
def user_password_reset_confirm():
    """Consume an admin-issued token and set a new password."""
    data = request.json or {}
    token = (data.get("token") or "").strip()
    password = data.get("password") or ""

    if not token:
        return jsonify({"error": "Reset code is required"}), 400
    problem = password_problem(password)
    if problem:
        return jsonify({"error": problem}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    user_id = consume_reset_token(cursor, token)
    if not user_id:
        conn.rollback()
        conn.close()
        return jsonify({"error": "That reset code is invalid or has expired."}), 400

    cursor.execute(
        """
        UPDATE bot_users
        SET password_hash=%s, password_set_at=NOW(), failed_login_count=0, locked_until=NULL
        WHERE id=%s
        """,
        (generate_password_hash(password), user_id),
    )
    conn.commit()
    conn.close()

    log_activity(user_id, "password_reset_completed", f"Password set via reset code from {_client_ip()}")
    return jsonify({"success": True, "message": "Password updated. You can now sign in.", "redirect": "/login"})


# ─────────────────────────────────────────────
# ADMIN AUTH + SECURITY
# ─────────────────────────────────────────────
@app.route("/api/admin/login", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=300, per="ip")  # 10 attempts / 5 min per IP — same shape as user login
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

    # Regenerate the session on privilege change so a pre-login fixated cookie
    # cannot be reused as an authenticated admin one (same fix as user_login).
    session.clear()
    session.permanent = True
    session["is_admin"] = True
    session["admin_id"] = admin["id"]
    session["admin_name"] = admin["name"]
    session["admin_role"] = admin["role"]
    session["login_at"] = datetime.utcnow().isoformat()
    session["csrf_token"] = _new_csrf_token()
    log_activity(admin["id"], "login", f"{admin['name']} logged in from {_client_ip()}")
    return jsonify({
        "success": True,
        "name": admin["name"],
        "role": admin["role"],
        "csrf_token": session["csrf_token"],
        "session_timeout_min": int(os.getenv("SESSION_TIMEOUT_MIN", "60")),
    })


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
    free_credits = int(data.get("free_credits", get_setting("lea_approval_free_credits", os.getenv("DEFAULT_FREE_CREDITS", "20"))))
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

    # Approval grants clearance to an account that already exists and already has
    # a password the officer chose at signup. It must never mint an account here:
    # that is what previously produced rows with no password_hash at all.
    phone = application["phone"]
    user_id = application.get("user_id")
    if user_id:
        cursor.execute("SELECT id FROM bot_users WHERE id=%s", (user_id,))
    else:
        cursor.execute("SELECT id FROM bot_users WHERE phone=%s", (phone,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return jsonify({
            "error": "No account matches this application. The applicant must sign up "
                     "before verification can be approved."
        }), 409

    cursor.execute(
        """
        UPDATE bot_users
        SET status='approved', verification_status='approved', verified_at=NOW(),
            credits=credits+%s, department=%s, lea_application_id=%s
        WHERE id=%s
        """,
        (free_credits, application["department"], app_id, existing["id"]),
    )
    cursor.execute("UPDATE lea_applications SET status='approved', reviewed_by=%s, reviewed_at=NOW() WHERE id=%s", (session.get("admin_name"), app_id))
    if free_credits:
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
    # The account survives a rejected application — the operator keeps their login
    # and can correct and resubmit. Only clearance is withheld.
    if application.get("user_id"):
        cursor.execute(
            "UPDATE bot_users SET verification_status='rejected', verification_note=%s WHERE id=%s",
            (reason, application["user_id"]),
        )
    else:
        cursor.execute(
            "UPDATE bot_users SET verification_status='rejected', verification_note=%s WHERE phone=%s",
            (reason, application["phone"]),
        )
    conn.commit()
    conn.close()
    log_activity(session.get("admin_id"), "lea_reject", f"Rejected LEA-{application['created_at'].year}-{app_id:04d} ({application['full_name']}) — {reason}")
    return jsonify({"success": True, "message": "Application rejected"})


@app.route("/uploads/<filename>")
@admin_required
def serve_upload(filename):
    # The write path (lea_register()) already runs uploaded names through
    # secure_filename() before saving — this is the same guard on the read side,
    # so a URL segment like "../../etc/passwd" or an absolute path can't escape
    # UPLOAD_FOLDER. Admin-only already, this is defense-in-depth.
    filename = secure_filename(filename)
    if not filename:
        return jsonify({"error": "Not found"}), 404
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
            SELECT id, phone, name, department, official_email, credits, status, verification_status, block_reason, created_at, last_login_at, twofa_enabled
            FROM bot_users WHERE name LIKE %s OR phone LIKE %s ORDER BY created_at DESC LIMIT 100
            """,
            (f"%{search}%", f"%{search}%"),
        )
    else:
        cursor.execute("SELECT id, phone, name, department, official_email, credits, status, verification_status, block_reason, created_at, last_login_at, twofa_enabled FROM bot_users ORDER BY created_at DESC LIMIT 100")
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
    """Issue a single-use reset code for an operator.

    SMTP is off, so the code is returned to the admin once, here, to be handed
    over out of band — the same channel already used to tell an officer their
    application was approved. It is stored hashed and cannot be retrieved again.
    """
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, phone FROM bot_users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    token = issue_reset_token(cursor, user_id, purpose="reset", issued_by=session.get("admin_name") or "admin")
    # Clear any lockout: the point of a reset is to restore access.
    cursor.execute("UPDATE bot_users SET failed_login_count=0, locked_until=NULL WHERE id=%s", (user_id,))
    conn.commit()
    conn.close()

    log_activity(session.get("admin_id"), "password_reset_issued",
                 f"Reset code issued for {user.get('name') or user.get('phone')} (user_id={user_id})")
    return jsonify({
        "success": True,
        "reset_token": token,
        "expires_in_hours": PASSWORD_RESET_TTL_HOURS,
        "reset_url": f"/reset-password?token={urllib.parse.quote(token)}",
        "message": "Single-use reset code generated. Give it to the operator directly — "
                   "it is shown once and cannot be retrieved again.",
    })


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
@user_required
def get_current_user():
    # Scoped to the caller's own session — any `phone` query param is ignored,
    # so a logged-in user can't read another account by guessing its number.
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, phone, name, department, credits, status, plan_id FROM bot_users WHERE id=%s", (session.get("user_id"),))
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
    problem = password_problem(new_password)
    if problem:
        return jsonify({"error": problem}), 400
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT password_hash FROM bot_users WHERE id=%s", (session.get("user_id"),))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    existing = row.get("password_hash")
    # No stored hash means no way to prove ownership here. Fail closed and send
    # them through the admin-issued reset token instead of accepting a shared
    # development password.
    if not existing:
        conn.close()
        return jsonify({
            "error": "This account has no password set. Ask the administrator for a reset code."
        }), 409
    if not check_password_hash(existing, current_password):
        conn.close()
        return jsonify({"error": "Current password is incorrect"}), 401
    cursor.execute(
        "UPDATE bot_users SET password_hash=%s, password_set_at=NOW() WHERE id=%s",
        (generate_password_hash(new_password), session.get("user_id")),
    )
    conn.commit()
    conn.close()
    log_activity(session.get("user_id"), "password_changed", f"Password changed from {_client_ip()}")
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


def charge_for_lookup(cursor, user, service, code, query, case_reference="", found=True, source=""):
    """Write the audit trail for a lookup, debiting credits only if it found data.

    Called with ``found=False`` on a miss: that an officer searched a number is
    the compliance record whether or not anything came back, so the search_logs
    row is always written — but a miss is never billed.

    Returns ``(credits_charged, search_log_id)``. The id is what
    ``/api/tools/run/report/pdf/<search_log_id>`` prints from.
    """
    credits = lookup_cost(service) if found else 0
    if credits:
        cursor.execute(
            "UPDATE bot_users SET credits = credits - %s WHERE id=%s AND credits >= %s",
            (credits, user["id"], credits),
        )
        if cursor.rowcount != 1:
            # Balance moved under us (concurrent lookup). Treat as unaffordable.
            raise InsufficientCredits(credits)
        cursor.execute(
            "INSERT INTO credit_transactions (phone, type, amount, reason) VALUES (%s,'debit',%s,%s)",
            (user["phone"], credits, f"lookup:{code}"),
        )
    cursor.execute(
        """
        INSERT INTO search_logs (user_id, phone, search_type, query_value, case_reference,
                                 credits_used, sources_queried)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        """,
        (user["id"], user["phone"], code, query[:255], case_reference[:100] or None,
         credits, source or (service or {}).get("name") or code),
    )
    return credits, cursor.lastrowid


class InsufficientCredits(Exception):
    def __init__(self, required):
        super().__init__("Insufficient credits")
        self.required = required


def lookup_cost(service) -> int:
    """Credits a single run of this service costs. Admin-editable per service."""
    if not service:
        return 0
    if service.get("is_free"):
        return 0
    return int(service.get("credits_per_use") or 0)


@app.route("/api/tools/run", methods=["POST"])
@verified_required
@rate_limit(max_requests=30, window_seconds=60, per="user")
def run_tool_generic():
    """Live tool runner. Database lookup tools work without API dependency.
    API tools use configured integrations when present; otherwise return a clear actionable error.
    """
    data = request.json or {}
    code = (data.get("code") or "").strip()
    query = (data.get("query") or "").strip()
    case_reference = (data.get("case_reference") or "").strip()
    if not code:
        return jsonify({"error": "tool code required"}), 400
    if not query:
        return jsonify({"error": "query required"}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM services WHERE code=%s", (code,))
    service = cursor.fetchone()

    # Fail closed on an unknown code. Every gate below used to be written as
    # `if service and ...`, so a code with no services row skipped all of them and
    # ran uncharged — which is exactly how `subscriber_lookup` became a free,
    # unlimited alias of `mobile_lookup`. An absent row is not permission.
    if not service:
        conn.close()
        return jsonify({"error": f"Unknown tool '{code}'."}), 404
    if not service.get("is_enabled"):
        conn.close()
        return jsonify({"error": "This service is disabled by admin"}), 403
    if service.get("maintenance_mode"):
        conn.close()
        return jsonify({"error": "This service is currently in maintenance mode"}), 503
    if service.get("status") == "upcoming":
        conn.close()
        return jsonify({"error": "This tool is marked as Coming Soon by admin"}), 403

    user = load_current_user(cursor)
    if not user:
        conn.close()
        session.clear()
        return jsonify({"error": "Authentication required"}), 401

    # Affordability is checked up front so the user is told before the query runs,
    # but the debit happens only if data actually comes back.
    credits_required = lookup_cost(service)
    credits_available = int(user.get("credits") or 0)
    if credits_required > credits_available:
        conn.close()
        return jsonify({
            "error": "Insufficient credits for this lookup.",
            "reason": "insufficient_credits",
            "credits_required": credits_required,
            "credits_available": credits_available,
        }), 402

    results = []
    errors = []

    # 1) Native database lookup tools — no API dependency required.
    try:
        if code == "mobile_lookup":
            cursor.execute("SELECT * FROM subscriber_records WHERE mobile_number=%s LIMIT 1", (query,))
            row = cursor.fetchone()
            if row:
                try:
                    charged, search_log_id = charge_for_lookup(
                        cursor, user, service, code, query, case_reference, source="Subscriber Database")
                except InsufficientCredits as exc:
                    conn.rollback(); conn.close()
                    return jsonify({
                        "error": "Insufficient credits for this lookup.",
                        "reason": "insufficient_credits",
                        "credits_required": exc.required,
                        "credits_available": credits_available,
                    }), 402
                conn.commit(); conn.close()
                return jsonify({
                    "success": True, "tool": code, "query": query,
                    "credits_charged": charged,
                    "credits_remaining": credits_available - charged,
                    "search_log_id": search_log_id,
                    "results": [{"source": "Subscriber Database", "status": "ok", "data": _json_clean(row)}],
                })
            # Fallback to generic uploaded records if old importer was used.
            # Exact key only: the previous `data_json LIKE \'%query%\'` substring match
            # could bill for — and print a PDF from — an unrelated record that merely
            # contained the digits somewhere in its JSON.
            try:
                cursor.execute("SELECT * FROM master_data_records WHERE source_type IN (\'subscriber\',\'custom\') AND record_key=%s ORDER BY created_at DESC LIMIT 20", (query,))
                rows = cursor.fetchall()
                if rows:
                    for r in rows:
                        try: r["data"] = json.loads(r.get("data_json") or "{}")
                        except Exception: r["data"] = r.get("data_json")
                    try:
                        charged, search_log_id = charge_for_lookup(
                            cursor, user, service, code, query, case_reference, source="Uploaded Master Data")
                    except InsufficientCredits as exc:
                        conn.rollback(); conn.close()
                        return jsonify({
                            "error": "Insufficient credits for this lookup.",
                            "reason": "insufficient_credits",
                            "credits_required": exc.required,
                            "credits_available": credits_available,
                        }), 402
                    conn.commit(); conn.close()
                    return jsonify({
                        "success": True, "tool": code, "query": query,
                        "credits_charged": charged,
                        "credits_remaining": credits_available - charged,
                        "search_log_id": search_log_id,
                        "results": [{"source": "Uploaded Master Data", "status": "ok", "data": rows}],
                    })
            except mysql.connector.Error:
                pass
            # Neither source matched. The attempt is still recorded — that an officer
            # searched a number is the compliance record, hit or miss — but nothing is
            # charged for a miss.
            charge_for_lookup(cursor, user, service, code, query, case_reference,
                              found=False, source="No match")
            conn.commit()

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
            if "twilio" in name and code == "mobile_lookup":
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

    if code == "mobile_lookup":
        return jsonify({"success": False, "error": "No subscriber record found. Upload Subscriber Database from Admin → Data Upload. Optional: configure Twilio/Numverify API for external phone intelligence.", "errors": errors}), 404
    return jsonify({"success": False, "error": f"No working connector/data found for tool '{code}'. Configure API dependency or upload database.", "errors": errors}), 400


SUBSCRIBER_REPORT_FIELDS = [
    ("mobile_number", "Mobile Number"),
    ("subscriber_name", "Subscriber Name"),
    ("father_name", "Father's Name"),
    ("address", "Address"),
    ("district", "District"),
    ("state", "State"),
    ("operator", "Operator"),
    ("sim_type", "SIM Type"),
    ("activation_date", "Activation Date"),
    ("status", "Status"),
    ("alternate_number", "Alternate Number"),
    ("email", "Email"),
    ("id_type", "ID Type"),
    ("id_number", "ID Number"),
]


def _build_mobile_lookup_pdf(log: dict, record: dict) -> bytes:
    """Render a search_logs row + its subscriber record as a PDF report."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm, leftMargin=16 * mm, rightMargin=16 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("SentinelTitle", parent=styles["Title"], fontSize=18, textColor=colors.HexColor("#0e1a29"))
    meta_style = ParagraphStyle("SentinelMeta", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#444444"), leading=13)
    footer_style = ParagraphStyle("SentinelFooter", parent=styles["Normal"], fontSize=7.5, textColor=colors.HexColor("#777777"))

    # reportlab's Paragraph parses a mini XML-like markup (it's what makes <br/>
    # below work), so anything interpolated into one must be escaped first or a
    # value containing '<'/'&' can break rendering or inject unintended markup.
    # case_reference/query_value/sources_queried come from search_logs (user
    # input at search time); user_name/user_department come from the session,
    # itself seeded from the signup form. app_name/disclaimer are admin-set via
    # get_setting() — lower risk, but escaped too for consistency since nothing
    # here is meant to carry real markup.
    app_name = xml_escape(str(get_setting("app_name", "SENTINEL")))
    disclaimer = xml_escape(str(get_setting("login_notice", "Restricted access only. For authorized law-enforcement use.")))

    created_at = log.get("created_at")
    created_at_str = created_at.strftime("%Y-%m-%d %H:%M:%S") if hasattr(created_at, "strftime") else str(created_at or "")

    case_reference = xml_escape(str(log.get("case_reference") or "—"))
    search_log_id = xml_escape(str(log.get("id")))
    query_value = xml_escape(str(log.get("query_value") or ""))
    sources_queried = xml_escape(str(log.get("sources_queried") or "—"))
    requested_by_name = xml_escape(str(session.get("user_name", "Operator")))
    requested_by_dept = xml_escape(str(session.get("user_department") or "—"))

    story = [
        Paragraph(f"{app_name} — Mobile Lookup Report", title_style),
        Spacer(1, 4 * mm),
        Paragraph(
            f"Case Reference: {case_reference}<br/>"
            f"Search Log ID: {search_log_id}<br/>"
            f"Queried Number: {query_value}<br/>"
            f"Searched At: {created_at_str}<br/>"
            f"Source: {sources_queried}<br/>"
            f"Requested By: {requested_by_name} ({requested_by_dept})",
            meta_style,
        ),
        Spacer(1, 6 * mm),
    ]

    table_data = [["Field", "Value"]]
    for key, label in SUBSCRIBER_REPORT_FIELDS:
        value = record.get(key)
        if hasattr(value, "isoformat"):
            value = value.isoformat()
        table_data.append([label, str(value) if value not in (None, "") else "—"])

    table = Table(table_data, colWidths=[50 * mm, 110 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e1a29")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)
    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph(disclaimer, footer_style))

    doc.build(story)
    return buf.getvalue()


@app.route("/api/tools/run/report/pdf/<int:search_log_id>", methods=["GET"])
@user_required
def mobile_lookup_report_pdf(search_log_id):
    """Re-format an already-paid-for mobile_lookup search as a PDF. No new credit charge,
    no new search_logs row — this reads back a prior search, scoped to the caller."""
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM search_logs WHERE id=%s AND user_id=%s", (search_log_id, user_id))
    log = cursor.fetchone()
    if not log:
        conn.close()
        return jsonify({"error": "Report not found."}), 404
    # credits_used is 0 both for a genuine miss and for a match against a
    # service the admin has marked free — sources_queried is the only field
    # that actually distinguishes "found nothing" from "found it, for free".
    if (log.get("sources_queried") or "").strip().lower() == "no match":
        conn.close()
        return jsonify({"error": "No successful search found for this record — nothing to report."}), 400

    query_value = log.get("query_value") or ""
    cursor.execute("SELECT * FROM subscriber_records WHERE mobile_number=%s LIMIT 1", (query_value,))
    record = cursor.fetchone()
    if not record:
        cursor.execute(
            "SELECT * FROM master_data_records WHERE source_type IN ('subscriber','custom') AND (record_key=%s OR data_json LIKE %s) ORDER BY created_at DESC LIMIT 1",
            (query_value, f"%{query_value}%"),
        )
        fallback = cursor.fetchone()
        if fallback:
            try:
                record = json.loads(fallback.get("data_json") or "{}")
            except Exception:
                record = {}
    conn.close()
    if not record:
        return jsonify({"error": "Underlying subscriber record no longer exists."}), 404

    pdf_bytes = _build_mobile_lookup_pdf(log, record)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=sentinel_mobile_lookup_{search_log_id}.pdf"},
    )


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
@session_required
def event_stream():
    """Server-sent heartbeat that tells admin.html/dashboard.html to refresh
    already-authorized data (see their onmessage handlers) — the payload
    itself is just a sync ping, no sensitive data.

    Was unauthenticated with an unbounded per-connection loop: any client
    could open unlimited sockets that never terminated (connection-exhaustion
    DoS). Now requires a session (either side — the content is identical for
    both) and each connection self-closes after EVENT_STREAM_MAX_SECONDS;
    EventSource reconnects automatically once a stream ends, so a legitimate
    client sees no behavior change beyond a periodic reconnect.
    """
    def gen():
        started = time.monotonic()
        while time.monotonic() - started < EVENT_STREAM_MAX_SECONDS:
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
            credits_required = 0 if is_free else int(service["credits_per_use"])
            credits_charged = 0
            if credits_required:
                # Atomic check-and-deduct — mirrors run_tool_generic()'s guard so two
                # concurrent CDR/IPDR requests can't both pass a stale balance check.
                cursor.execute(
                    "UPDATE bot_users SET credits = credits - %s WHERE id = %s AND credits >= %s",
                    (credits_required, user["id"], credits_required),
                )
                if cursor.rowcount:
                    credits_charged = credits_required
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
@admin_required
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
@admin_required
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

# ─────────────────────────────────────────────
# PLANS, CREDITS AND PAYMENTS
#
# Credits are the only unit of account: a plan is a bundle of credits at a price,
# not a recurring subscription. Buying credits never grants data clearance — that
# comes from LEA verification alone.
#
# Payment providers sit behind PaymentProvider so the gateway can be swapped
# without touching the crediting path. Today the only live provider is `manual`
# (admin confirms an out-of-band transfer). A Razorpay adapter is implemented and
# inert; set PAYMENTS_PROVIDER=razorpay with keys present to activate it. Both
# funnel into credit_payment_order(), so credits are granted in exactly one place.
# ─────────────────────────────────────────────
def _plan_public(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "credits": int(row["credits"]),
        "price_inr": int(row["price_inr"]),
        "description": row.get("description") or "",
        "is_featured": bool(row.get("is_featured")),
        "per_credit": round(int(row["price_inr"]) / int(row["credits"]), 2) if row.get("credits") else 0,
    }


@app.route("/api/plans", methods=["GET"])
def list_plans():
    """Public pricing. Safe to serve unauthenticated — it is a price list."""
    try:
        with db_conn() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT * FROM recharge_plans WHERE is_active=1 ORDER BY sort_order, price_inr"
            )
            plans = [_plan_public(r) for r in cursor.fetchall()]
    except Exception:
        plans = []
    return jsonify({"plans": plans, "provider": active_payment_provider().name})


@app.route("/api/admin/plans", methods=["GET"])
@admin_required
def admin_list_plans():
    with db_conn() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM recharge_plans ORDER BY sort_order, price_inr")
        rows = cursor.fetchall()
    for r in rows:
        r["is_active"] = bool(r.get("is_active"))
        r["is_featured"] = bool(r.get("is_featured"))
    return jsonify(rows)


@app.route("/api/admin/plans", methods=["POST"])
@admin_required
def admin_save_plan():
    """Create or update a plan. Admin owns credits, price and visibility."""
    data = request.json or {}
    plan_id = data.get("id")
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Plan name is required"}), 400
    try:
        credits = int(data.get("credits"))
        price = int(data.get("price_inr"))
    except (TypeError, ValueError):
        return jsonify({"error": "Credits and price must be whole numbers"}), 400
    if credits <= 0 or price < 0:
        return jsonify({"error": "Credits must be positive and price cannot be negative"}), 400

    fields = (
        name, credits, price, (data.get("description") or "").strip() or None,
        int(data.get("sort_order") or 0), 1 if data.get("is_featured") else 0,
        0 if data.get("is_active") is False else 1,
    )
    conn = get_db()
    cursor = conn.cursor()
    try:
        if plan_id:
            cursor.execute(
                """
                UPDATE recharge_plans
                SET name=%s, credits=%s, price_inr=%s, description=%s,
                    sort_order=%s, is_featured=%s, is_active=%s
                WHERE id=%s
                """,
                fields + (int(plan_id),),
            )
        else:
            cursor.execute(
                """
                INSERT INTO recharge_plans
                    (name, credits, price_inr, description, sort_order, is_featured, is_active)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                fields,
            )
            plan_id = cursor.lastrowid
        conn.commit()
    except mysql.connector.Error as exc:
        conn.close()
        return jsonify({"error": f"Could not save plan: {exc}"}), 400
    conn.close()
    log_activity(session.get("admin_id"), "plan_saved", f"Plan '{name}' — {credits} credits at ₹{price}")
    return jsonify({"success": True, "id": plan_id})


@app.route("/api/admin/plans/<int:plan_id>", methods=["DELETE"])
@admin_required
def admin_delete_plan(plan_id):
    """Retire a plan. Never hard-deleted — historic orders reference it."""
    with db_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE recharge_plans SET is_active=0 WHERE id=%s", (plan_id,))
        conn.commit()
    log_activity(session.get("admin_id"), "plan_retired", f"Plan id={plan_id} retired")
    return jsonify({"success": True})


# ── Provider abstraction ──────────────────────
class PaymentProvider:
    """Contract every gateway adapter implements.

    create_order() may return a `checkout` payload the frontend hands to the
    gateway's SDK. verify_webhook() must authenticate the callback before any
    credit is granted.
    """

    name = "base"
    is_live = False

    def create_order(self, order_ref, amount_inr, user):
        raise NotImplementedError

    def verify_webhook(self, raw_body: bytes, headers) -> tuple[bool, dict]:
        raise NotImplementedError


class ManualProvider(PaymentProvider):
    """No gateway. The order is filed as pending and an admin confirms payment
    received out of band, which credits the account through the same path a
    gateway webhook would use."""

    name = "manual"
    is_live = True

    def create_order(self, order_ref, amount_inr, user):
        return {
            "provider": self.name,
            "provider_order_id": order_ref,
            "checkout": None,
            "instructions": get_setting(
                "manual_payment_instructions",
                "Your order has been placed. Transfer the amount using the details "
                "shared by the administrator, quoting your order reference. Credits "
                "are added once payment is confirmed.",
            ),
        }

    def verify_webhook(self, raw_body, headers):
        return False, {}


class RazorpayProvider(PaymentProvider):
    """Razorpay adapter — complete but inert until keys are configured.

    Deliberately uses urllib rather than the razorpay SDK so the dependency list
    does not change before the account exists. To go live:
      1. set RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET in .env
      2. set PAYMENTS_PROVIDER=razorpay (or the payments_provider app setting)
      3. set RAZORPAY_WEBHOOK_SECRET and point the Razorpay dashboard webhook at
         POST /api/payments/webhook/razorpay for the `payment.captured` event
    Nothing else has to change: crediting already runs through
    credit_payment_order().
    """

    name = "razorpay"
    API_BASE = "https://api.razorpay.com/v1"

    def __init__(self):
        self.key_id = os.getenv("RAZORPAY_KEY_ID", "").strip()
        self.key_secret = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
        self.webhook_secret = os.getenv("RAZORPAY_WEBHOOK_SECRET", "").strip()

    @property
    def is_live(self):
        return bool(self.key_id and self.key_secret)

    def _auth_header(self):
        token = base64.b64encode(f"{self.key_id}:{self.key_secret}".encode()).decode()
        return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}

    def create_order(self, order_ref, amount_inr, user):
        if not self.is_live:
            raise RuntimeError("Razorpay keys are not configured")
        payload = {
            "amount": int(amount_inr) * 100,  # Razorpay bills in paise
            "currency": "INR",
            "receipt": order_ref,
            "notes": {"order_ref": order_ref, "user_id": str(user["id"])},
        }
        data = _http_json(f"{self.API_BASE}/orders", payload, self._auth_header(), method="POST", timeout=20)
        return {
            "provider": self.name,
            "provider_order_id": data.get("id"),
            "checkout": {
                "key": self.key_id,
                "order_id": data.get("id"),
                "amount": data.get("amount"),
                "currency": data.get("currency", "INR"),
                "name": "SENTINEL",
                "prefill": {
                    "name": user.get("name") or "",
                    "email": user.get("official_email") or "",
                    "contact": user.get("phone") or "",
                },
            },
            "instructions": "",
        }

    def verify_webhook(self, raw_body, headers):
        signature = headers.get("X-Razorpay-Signature", "")
        if not self.webhook_secret or not signature:
            return False, {}
        expected = hmac.new(self.webhook_secret.encode(), raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return False, {}
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return False, {}
        entity = (body.get("payload", {}).get("payment", {}) or {}).get("entity", {})
        return True, {
            "event": body.get("event"),
            "provider_order_id": entity.get("order_id"),
            "provider_payment_id": entity.get("id"),
            "paid": body.get("event") == "payment.captured",
        }


PAYMENT_PROVIDERS = {"manual": ManualProvider, "razorpay": RazorpayProvider}


def active_payment_provider() -> PaymentProvider:
    """Resolve the configured provider, falling back to manual if it is not usable.

    Falling back rather than erroring means a half-configured gateway degrades to
    'admin confirms the transfer' instead of taking the whole checkout offline.
    """
    choice = (get_setting("payments_provider", os.getenv("PAYMENTS_PROVIDER", "manual")) or "manual").lower()
    provider = PAYMENT_PROVIDERS.get(choice, ManualProvider)()
    if not provider.is_live:
        return ManualProvider()
    return provider


def credit_payment_order(cursor, order_row, provider_payment_id=None, confirmed_by=None) -> bool:
    """Grant the credits for a paid order. The single crediting path.

    Idempotent: an order already marked paid returns False and does nothing, so a
    replayed webhook or a double-click on 'Mark Paid' cannot credit twice.
    """
    if order_row["status"] == "paid":
        return False
    cursor.execute(
        """
        UPDATE payment_orders
        SET status='paid', credited_at=NOW(), provider_payment_id=%s, confirmed_by=%s
        WHERE id=%s AND status<>'paid'
        """,
        (provider_payment_id, confirmed_by, order_row["id"]),
    )
    if cursor.rowcount != 1:
        return False
    cursor.execute(
        "UPDATE bot_users SET credits = credits + %s WHERE id=%s",
        (order_row["credits"], order_row["user_id"]),
    )
    cursor.execute(
        "INSERT INTO credit_transactions (phone, type, amount, reason, razorpay_order_id, status) "
        "VALUES (%s,'credit',%s,%s,%s,'success')",
        (order_row["phone"], order_row["credits"], f"purchase:{order_row['plan_name'] or 'custom'}",
         order_row.get("provider_order_id")),
    )
    return True


@app.route("/api/payments/checkout", methods=["POST"])
@user_required
@rate_limit(max_requests=10, window_seconds=600, per="user")
def payments_checkout():
    """Place an order for a credit plan.

    Available to any signed-in user, verified or not — buying credits is not the
    gated action; using them is.
    """
    data = request.json or {}
    plan_id = data.get("plan_id")
    if not plan_id:
        return jsonify({"error": "plan_id is required"}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    user = load_current_user(cursor)
    if not user:
        conn.close(); session.clear()
        return jsonify({"error": "Authentication required"}), 401

    cursor.execute("SELECT * FROM recharge_plans WHERE id=%s AND is_active=1", (plan_id,))
    plan = cursor.fetchone()
    if not plan:
        conn.close()
        return jsonify({"error": "That plan is not available"}), 404

    provider = active_payment_provider()
    order_ref = f"SNT-{datetime.now():%Y%m%d}-{secrets.token_hex(4).upper()}"
    try:
        provider_payload = provider.create_order(order_ref, plan["price_inr"], user)
    except Exception as exc:
        conn.close()
        return jsonify({"error": f"Could not start checkout: {exc}"}), 502

    cursor.execute(
        """
        INSERT INTO payment_orders
            (order_ref, user_id, phone, plan_id, plan_name, credits, amount_inr,
             provider, provider_order_id, status)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending')
        """,
        (order_ref, user["id"], user["phone"], plan["id"], plan["name"], plan["credits"],
         plan["price_inr"], provider.name, provider_payload.get("provider_order_id")),
    )
    conn.commit()
    conn.close()

    log_activity(user["id"], "payment_order_created",
                 f"{user.get('name')} ordered {plan['name']} ({plan['credits']} credits, ₹{plan['price_inr']}) via {provider.name}")
    return jsonify({
        "success": True,
        "order_ref": order_ref,
        "plan": _plan_public(plan),
        "provider": provider.name,
        "checkout": provider_payload.get("checkout"),
        "instructions": provider_payload.get("instructions", ""),
        "status": "pending",
    }), 201


@app.route("/api/payments/orders", methods=["GET"])
@user_required
def payments_my_orders():
    with db_conn() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT order_ref, plan_name, credits, amount_inr, provider, status, created_at, credited_at
            FROM payment_orders WHERE user_id=%s ORDER BY created_at DESC LIMIT 50
            """,
            (session.get("user_id"),),
        )
        rows = cursor.fetchall()
    for r in rows:
        r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
        r["credited_at"] = r["credited_at"].isoformat() if r.get("credited_at") else None
    return jsonify(rows)


@app.route("/api/payments/webhook/<provider_name>", methods=["POST"])
def payments_webhook(provider_name):
    """Gateway callback. Unauthenticated by necessity — authenticity comes from
    the provider's signature, which is verified before anything is credited."""
    provider_cls = PAYMENT_PROVIDERS.get((provider_name or "").lower())
    if not provider_cls or provider_cls is ManualProvider:
        return jsonify({"error": "Unknown provider"}), 404

    provider = provider_cls()
    ok, event = provider.verify_webhook(request.get_data(), request.headers)
    if not ok:
        log_activity(None, "payment_webhook_rejected", f"Bad signature on {provider_name} webhook from {_client_ip()}")
        return jsonify({"error": "Invalid signature"}), 400
    if not event.get("paid"):
        return jsonify({"success": True, "ignored": event.get("event")})

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM payment_orders WHERE provider=%s AND provider_order_id=%s LIMIT 1",
        (provider.name, event.get("provider_order_id")),
    )
    order = cursor.fetchone()
    if not order:
        conn.close()
        return jsonify({"error": "Unknown order"}), 404

    granted = credit_payment_order(cursor, order, event.get("provider_payment_id"), confirmed_by=provider.name)
    conn.commit()
    conn.close()
    if granted:
        log_activity(order["user_id"], "payment_captured",
                     f"{order['order_ref']} paid via {provider.name} — {order['credits']} credits granted")
    return jsonify({"success": True, "credited": granted})


@app.route("/api/admin/payments/orders", methods=["GET"])
@admin_required
def admin_payment_orders():
    status = (request.args.get("status") or "").strip()
    query = """
        SELECT o.*, u.name AS user_name, u.official_email
        FROM payment_orders o LEFT JOIN bot_users u ON u.id = o.user_id
    """
    params = ()
    if status in {"pending", "paid", "failed", "cancelled"}:
        query += " WHERE o.status=%s"
        params = (status,)
    query += " ORDER BY o.created_at DESC LIMIT 200"
    with db_conn() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        rows = cursor.fetchall()
    for r in rows:
        r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
        r["credited_at"] = r["credited_at"].isoformat() if r.get("credited_at") else None
        r["updated_at"] = r["updated_at"].isoformat() if r.get("updated_at") else None
    return jsonify(rows)


@app.route("/api/admin/payments/orders/<int:order_id>/mark-paid", methods=["POST"])
@admin_required
def admin_mark_order_paid(order_id):
    """Confirm an out-of-band payment and release the credits."""
    note = ((request.json or {}).get("note") or "").strip()
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM payment_orders WHERE id=%s", (order_id,))
    order = cursor.fetchone()
    if not order:
        conn.close()
        return jsonify({"error": "Order not found"}), 404

    granted = credit_payment_order(cursor, order, None, confirmed_by=session.get("admin_name") or "admin")
    if granted and note:
        cursor.execute("UPDATE payment_orders SET notes=%s WHERE id=%s", (note, order_id))
    conn.commit()
    conn.close()

    if not granted:
        return jsonify({"error": "Order is already marked paid.", "credited": False}), 409
    log_activity(session.get("admin_id"), "payment_marked_paid",
                 f"{order['order_ref']} confirmed manually — {order['credits']} credits to {order['phone']}")
    return jsonify({"success": True, "credited": True, "credits": order["credits"]})


@app.route("/api/admin/payments/orders/<int:order_id>/cancel", methods=["POST"])
@admin_required
def admin_cancel_order(order_id):
    with db_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE payment_orders SET status='cancelled' WHERE id=%s AND status='pending'",
            (order_id,),
        )
        changed = cursor.rowcount
        conn.commit()
    if not changed:
        return jsonify({"error": "Only a pending order can be cancelled."}), 409
    log_activity(session.get("admin_id"), "payment_cancelled", f"Order id={order_id} cancelled")
    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
