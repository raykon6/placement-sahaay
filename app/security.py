"""Authentication, sessions, CSRF, RBAC, rate limiting and security headers."""
import base64
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import abort, current_app, g, redirect, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import audit
from .constants import now_iso, parse_ts, utcnow
from .db import execute, query, transaction

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PRE_CSRF_COOKIE = "pg_precsrf"

# ---------------------------------------------------------------------------
# Role-based access control. Permissions are additive and checked server-side
# on every request; templates only hide what the server already forbids.
# ---------------------------------------------------------------------------
PERMISSIONS = {
    "admin": {
        "dashboard", "student.read", "student.contact", "student.comp", "student.write", "student.archive",
        "student.anonymize", "student.import", "student.eligibility", "export", "export.contact",
        "drive.read", "drive.write", "application.write", "offer.read", "offer.write", "attendance.write",
        "attendance.except", "flag.read", "flag.resolve", "policy.read", "policy.edit", "policy.simulate",
        "audit.read", "user.manage", "backup.manage", "registration.review", "outbox.read",
    },
    "officer": {
        "dashboard", "student.read", "student.contact", "student.comp", "student.write", "student.archive",
        "student.import", "student.eligibility", "export", "drive.read", "drive.write", "application.write",
        "offer.read", "offer.write", "attendance.write", "attendance.except", "flag.read", "flag.resolve",
        "policy.read", "policy.simulate", "audit.read", "registration.review",
    },
    # Scoped to users.course_scope in object-level checks.
    "coordinator": {
        "dashboard", "student.read", "student.contact", "student.comp", "student.eligibility",
        "drive.read", "offer.read", "flag.read", "policy.read", "policy.simulate", "registration.review",
    },
    # Scoped to users.company_id: sees only applicants to its own drives.
    "recruiter": {"recruiter.portal", "policy.read"},
    "student": {"self.portal", "policy.read"},
}

COMMON_PASSWORDS = {
    "password", "password123", "123456789012", "qwertyuiop12", "letmein12345", "welcome12345",
    "admin1234567", "iloveyou1234", "placement2026", "nfsu12345678", "changeme1234", "p@ssw0rd1234",
}


def has_perm(perm: str, user=None) -> bool:
    user = user if user is not None else g.get("user")
    return bool(user) and perm in PERMISSIONS.get(user["role"], set())


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            return redirect(url_for("auth.login", next=_safe_next(request.full_path)))
        if g.user["must_change_password"] and request.endpoint not in ("auth.account", "auth.change_password", "auth.logout"):
            flash("You must set a new password before continuing.", "warning")
            return redirect(url_for("auth.account"))
        return view(*args, **kwargs)
    return wrapped


def require(*perms):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if not all(has_perm(p) for p in perms):
                deny("permission", {"required": list(perms)})
            return view(*args, **kwargs)
        return wrapped
    return decorator


def deny(reason: str, detail: dict | None = None):
    """Log and refuse. 403 is used for authenticated access violations."""
    with transaction():
        audit.record("authz.denied", "request", request.path,
                     {"reason": reason, "method": request.method, **(detail or {})})
    abort(403)


def can_access_student(student, user=None) -> bool:
    """Object-level authorisation (prevents IDOR)."""
    user = user if user is not None else g.user
    role = user["role"]
    if role in ("admin", "officer"):
        return True
    if role == "coordinator":
        return student["course"] == user["course_scope"]
    if role == "recruiter":
        return query(
            "SELECT 1 FROM applications a JOIN drives d ON d.id = a.drive_id"
            " WHERE a.student_id = ? AND d.company_id = ?", (student["id"], user["company_id"]), one=True) is not None
    if role == "student":
        return student["id"] == user["student_id"]
    return False


def _safe_next(target: str | None) -> str | None:
    """Only allow same-site relative redirects (prevents open redirects)."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    return target.rstrip("?") or None


safe_next = _safe_next

# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
_DUMMY_HASH = generate_password_hash("timing-equaliser-not-a-password")


def hash_password(pw: str) -> str:
    return generate_password_hash(pw, method="scrypt")  # memory-hard KDF, per-hash salt


def verify_password(stored_hash: str | None, pw: str) -> bool:
    # Always run the KDF so response time does not reveal whether a user exists.
    return check_password_hash(stored_hash or _DUMMY_HASH, pw) and stored_hash is not None


def password_problems(pw: str, username: str = "") -> list:
    problems = []
    if len(pw) < 12:
        problems.append("Use at least 12 characters.")
    if len(pw) > 128:
        problems.append("Use at most 128 characters.")
    if pw.lower() in COMMON_PASSWORDS:
        problems.append("This password is too common.")
    if username and username.lower() in pw.lower():
        problems.append("Do not include your username.")
    if len(set(pw)) < 6:
        problems.append("Use a less repetitive password.")
    return problems


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) multi-factor authentication
# ---------------------------------------------------------------------------
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_code(secret_b32: str, at: float | None = None) -> str:
    return _hotp(secret_b32, int((at or time.time()) // 30))


def verify_totp(secret_b32: str, code: str, last_step: int) -> int | None:
    """Return the matched time step, or None. Accepts ±1 step of clock drift
    and rejects reuse of an already-consumed step (replay protection)."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    now_step = int(time.time() // 30)
    for step in (now_step - 1, now_step, now_step + 1):
        if step > last_step and hmac.compare_digest(_hotp(secret_b32, step), code):
            return step
    return None


# ---------------------------------------------------------------------------
# Server-side sessions. The cookie holds a random token; the database stores
# only its SHA-256, so a leaked database does not yield live sessions.
# ---------------------------------------------------------------------------
def cookie_name() -> str:
    return "__Host-pg_session" if current_app.config["HTTPS"] else "pg_session"


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _ua_hash() -> str:
    return hashlib.sha256((request.headers.get("User-Agent") or "").encode("utf-8")).hexdigest()


def start_session(user_id: int, stage: str) -> None:
    """Create a fresh session (new identifier on every privilege change,
    which defeats session fixation)."""
    if g.get("sess"):
        execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (g.sess["id"],))
    token = secrets.token_urlsafe(32)
    now = now_iso()
    execute(
        "INSERT INTO sessions (token_hash, user_id, stage, csrf_token, ua_hash, ip, created_at, last_seen_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (_token_hash(token), user_id, stage, secrets.token_urlsafe(32), _ua_hash(), request.remote_addr, now, now),
    )
    g.new_session_token = token


def end_session() -> None:
    if g.get("sess"):
        execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (g.sess["id"],))
    g.clear_session_cookie = True
    g.sess = None
    g.user = None


def revoke_user_sessions(user_id: int) -> None:
    execute("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (user_id,))


def _load_session():
    g.user = None
    g.sess = None
    g.pending_user = None
    token = request.cookies.get(cookie_name())
    if not token:
        return
    sess = query("SELECT * FROM sessions WHERE token_hash = ? AND revoked = 0", (_token_hash(token),), one=True)
    if sess is None:
        g.clear_session_cookie = True
        return
    cfg = current_app.config
    now = utcnow()
    expired = (now - parse_ts(sess["last_seen_at"]) > timedelta(minutes=cfg["SESSION_IDLE_MINUTES"])
               or now - parse_ts(sess["created_at"]) > timedelta(hours=cfg["SESSION_ABSOLUTE_HOURS"]))
    hijack_suspect = not hmac.compare_digest(sess["ua_hash"], _ua_hash())
    user = query("SELECT * FROM users WHERE id = ? AND active = 1", (sess["user_id"],), one=True)
    if expired or hijack_suspect or user is None:
        with transaction():
            execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (sess["id"],))
            if hijack_suspect:
                audit.record("session.binding_mismatch", "session", sess["id"], {}, actor=user)
        g.clear_session_cookie = True
        g.session_expired = expired
        return
    g.sess = sess
    if sess["stage"] == "full":
        g.user = user
        # Touch at most once a minute to limit write load.
        if (now - parse_ts(sess["last_seen_at"])).total_seconds() > 60:
            execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (now_iso(), sess["id"]))
    else:
        g.pending_user = user


# ---------------------------------------------------------------------------
# Flash messages (stored server-side on the session row)
# ---------------------------------------------------------------------------
def flash(message: str, category: str = "info") -> None:
    g.setdefault("_pending_flash", []).append([category, message])


def pop_flashes() -> list:
    messages = list(g.get("_pending_flash", []))
    g._pending_flash = []
    if g.get("sess") and not g.get("_flash_popped"):
        stored = json.loads(g.sess["flash"] or "[]")
        if stored:
            execute("UPDATE sessions SET flash = '[]' WHERE id = ?", (g.sess["id"],))
        messages = stored + messages
        g._flash_popped = True
    return messages


def _persist_flashes(response):
    """Messages raised before a redirect are saved for the next request."""
    pending = g.get("_pending_flash")
    if not pending or response.status_code not in (301, 302, 303, 307, 308):
        return
    token = g.get("new_session_token")
    if token:
        row = query("SELECT id, flash FROM sessions WHERE token_hash = ?", (_token_hash(token),), one=True)
    elif g.get("sess"):
        row = query("SELECT id, flash FROM sessions WHERE id = ?", (g.sess["id"],), one=True)
    else:
        return
    if row:
        execute("UPDATE sessions SET flash = ? WHERE id = ?", (json.dumps(json.loads(row["flash"]) + pending), row["id"]))


# ---------------------------------------------------------------------------
# CSRF: synchroniser token bound to the session; for anonymous forms (login)
# a double-submit cookie. Origin/Referer is also checked on unsafe methods.
# ---------------------------------------------------------------------------
def csrf_token() -> str:
    if g.get("sess"):
        return g.sess["csrf_token"]
    token = request.cookies.get(PRE_CSRF_COOKIE) or g.get("new_pre_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        g.new_pre_csrf = token
    return token


def _check_csrf():
    origin = request.headers.get("Origin") or request.headers.get("Referer")
    if origin:
        o = urlparse(origin)
        if o.netloc and o.netloc != request.host:
            abort(400, description="Cross-origin request rejected.")
    expected = g.sess["csrf_token"] if g.get("sess") else request.cookies.get(PRE_CSRF_COOKIE)
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description="Security token missing or invalid. Reload the page and try again.")


# ---------------------------------------------------------------------------
# Rate limiting (per client IP, sliding window, in-process)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


limiter = RateLimiter()


def rate_limit(bucket: str, limit: int | None = None):
    limit = limit or current_app.config["LOGIN_RATE_PER_MINUTE"]
    if not limiter.allow(f"{bucket}:{request.remote_addr}", limit):
        abort(429)


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


def init_app(app):
    @app.before_request
    def _before():
        if request.endpoint == "static":
            return
        _load_session()
        if request.method not in SAFE_METHODS:
            _check_csrf()

    @app.after_request
    def _after(response):
        if request.endpoint != "static":
            _persist_flashes(response)
        secure = app.config["HTTPS"]
        name = cookie_name()
        if g.get("new_session_token"):
            response.set_cookie(name, g.new_session_token, httponly=True, secure=secure, samesite="Strict", path="/")
        elif g.get("clear_session_cookie"):
            response.delete_cookie(name, path="/", secure=secure, httponly=True, samesite="Strict")
        if g.get("new_pre_csrf"):
            response.set_cookie(PRE_CSRF_COOKIE, g.new_pre_csrf, httponly=True, secure=secure, samesite="Strict",
                                path="/", max_age=3600)
        h = response.headers
        h["Content-Security-Policy"] = CSP
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        if secure:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            h["Cache-Control"] = "no-store"  # sensitive pages must not be cached
        h.pop("Server", None)
        return response

    app.jinja_env.globals.update(csrf_token=csrf_token, has_perm=has_perm, pop_flashes=pop_flashes)
