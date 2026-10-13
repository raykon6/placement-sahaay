"""Login, MFA, logout and self-service account security."""
from datetime import timedelta

from flask import Blueprint, current_app, g, redirect, render_template, request, url_for

from .. import audit
from ..constants import now_iso, parse_ts, utcnow, TS_FMT
from ..crypto import decrypt_field, encrypt_field
from ..db import execute, query, transaction
from ..security import (end_session, flash, hash_password, login_required, new_totp_secret, password_problems,
                        rate_limit, revoke_user_sessions, safe_next, start_session, verify_password, verify_totp)

bp = Blueprint("auth", __name__)
GENERIC_LOGIN_ERROR = "Incorrect username or password."


def _home_for(user) -> str:
    return {"recruiter": "main.recruiter", "student": "main.me"}.get(user["role"], "main.dashboard")


def _totp_aad(user_id: int) -> str:
    return f"users:{user_id}:totp"


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for(_home_for(g.user)))
    next_url = safe_next(request.values.get("next"))
    if request.method == "GET":
        return render_template("login.html", next=next_url, expired=request.args.get("expired"))

    rate_limit("login")
    username = (request.form.get("username") or "").strip().lower()[:64]
    password = request.form.get("password") or ""
    user = query("SELECT * FROM users WHERE username = ?", (username,), one=True)
    cfg = current_app.config

    if user and user["locked_until"] and parse_ts(user["locked_until"]) > utcnow():
        verify_password(None, password)  # keep timing uniform
        with transaction():
            audit.record("auth.login_locked", "user", user["id"], {}, actor=user)
        return render_template("login.html", next=next_url, username=username,
                               error="This account is temporarily locked after repeated failed attempts. Try again later."), 401

    if not verify_password(user["password_hash"] if user else None, password) or not user or not user["active"]:
        with transaction():
            if user:
                failures = user["failed_attempts"] + 1
                locked = None
                if failures >= cfg["LOGIN_MAX_FAILURES"]:
                    locked = (utcnow() + timedelta(minutes=cfg["LOCKOUT_MINUTES"])).strftime(TS_FMT)
                    failures = 0
                execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", (failures, locked, user["id"]))
                audit.record("auth.login_failed", "user", user["id"], {"locked": bool(locked)}, actor=user)
            else:
                audit.record("auth.login_failed", "user", None, {"username_attempted": username[:32]})
        return render_template("login.html", next=next_url, username=username, error=GENERIC_LOGIN_ERROR), 401

    with transaction():
        execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        if user["mfa_enabled"]:
            start_session(user["id"], "mfa")
            audit.record("auth.password_ok_mfa_pending", "user", user["id"], {}, actor=user)
        else:
            start_session(user["id"], "full")
            execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_iso(), user["id"]))
            audit.record("auth.login", "user", user["id"], {"mfa": False}, actor=user)
    if user["mfa_enabled"]:
        return redirect(url_for("auth.mfa", next=next_url))
    if user["role"] in ("admin", "officer"):
        flash("Multi-factor authentication is not enabled for this privileged account. Enable it under Account security.", "warning")
    return redirect(next_url or url_for(_home_for(user)))


@bp.route("/login/mfa", methods=["GET", "POST"])
def mfa():
    user = g.get("pending_user")
    if user is None:
        return redirect(url_for("auth.login"))
    next_url = safe_next(request.values.get("next"))
    if request.method == "GET":
        return render_template("mfa.html", next=next_url)
    rate_limit("mfa")
    secret = decrypt_field(user["totp_secret_enc"], _totp_aad(user["id"]))
    step = verify_totp(secret, request.form.get("code", ""), user["last_totp_step"])
    if step is None:
        with transaction():
            audit.record("auth.mfa_failed", "user", user["id"], {}, actor=user)
        return render_template("mfa.html", next=next_url, error="That code is not valid. Enter the current 6-digit code."), 401
    with transaction():
        execute("UPDATE users SET last_totp_step = ?, last_login_at = ? WHERE id = ?", (step, now_iso(), user["id"]))
        start_session(user["id"], "full")
        audit.record("auth.login", "user", user["id"], {"mfa": True}, actor=user)
    return redirect(next_url or url_for(_home_for(user)))


@bp.route("/logout", methods=["POST"])
def logout():
    user = g.get("user") or g.get("pending_user")
    with transaction():
        if user:
            audit.record("auth.logout", "user", user["id"], {}, actor=user)
        end_session()
    return redirect(url_for("auth.login"))


@bp.route("/account")
@login_required
def account():
    return render_template("account.html", enrolling=None)


@bp.route("/account/password", methods=["POST"])
@login_required
def change_password():
    user = g.user
    current = request.form.get("current_password") or ""
    new = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""
    errors = {}
    if not verify_password(user["password_hash"], current):
        errors["current_password"] = "Current password is incorrect."
    problems = password_problems(new, user["username"])
    if problems:
        errors["new_password"] = " ".join(problems)
    elif new != confirm:
        errors["confirm_password"] = "Passwords do not match."
    elif verify_password(user["password_hash"], new):
        errors["new_password"] = "Choose a password different from the current one."
    if errors:
        return render_template("account.html", errors=errors, enrolling=None), 422
    with transaction():
        execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?", (hash_password(new), user["id"]))
        revoke_user_sessions(user["id"])  # sign out every other device
        start_session(user["id"], "full")
        audit.record("auth.password_changed", "user", user["id"], {})
    flash("Password updated. Other sessions have been signed out.", "success")
    return redirect(url_for("auth.account"))


@bp.route("/account/mfa/start", methods=["POST"])
@login_required
def mfa_start():
    if g.user["mfa_enabled"]:
        return redirect(url_for("auth.account"))
    secret = new_totp_secret()
    with transaction():
        execute("UPDATE users SET totp_secret_enc = ? WHERE id = ?", (encrypt_field(secret, _totp_aad(g.user["id"])), g.user["id"]))
    issuer = "PlacementSahaay"
    uri = f"otpauth://totp/{issuer}:{g.user['username']}?secret={secret}&issuer={issuer}&digits=6&period=30"
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return render_template("account.html", enrolling={"secret": grouped, "uri": uri})


@bp.route("/account/mfa/confirm", methods=["POST"])
@login_required
def mfa_confirm():
    user = g.user
    if not user["totp_secret_enc"] or user["mfa_enabled"]:
        return redirect(url_for("auth.account"))
    secret = decrypt_field(user["totp_secret_enc"], _totp_aad(user["id"]))
    step = verify_totp(secret, request.form.get("code", ""), user["last_totp_step"])
    if step is None:
        grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
        uri = f"otpauth://totp/PlacementSahaay:{user['username']}?secret={secret}&issuer=PlacementSahaay&digits=6&period=30"
        return render_template("account.html", enrolling={"secret": grouped, "uri": uri},
                               errors={"code": "That code did not match. Check the time on your device and retry."}), 422
    with transaction():
        execute("UPDATE users SET mfa_enabled = 1, last_totp_step = ? WHERE id = ?", (step, user["id"]))
        audit.record("auth.mfa_enabled", "user", user["id"], {})
    flash("Multi-factor authentication is now required at sign-in.", "success")
    return redirect(url_for("auth.account"))


@bp.route("/account/mfa/disable", methods=["POST"])
@login_required
def mfa_disable():
    user = g.user
    if not verify_password(user["password_hash"], request.form.get("current_password") or ""):
        return render_template("account.html", enrolling=None,
                               errors={"disable_password": "Current password is incorrect."}), 422
    with transaction():
        execute("UPDATE users SET mfa_enabled = 0, totp_secret_enc = NULL WHERE id = ?", (user["id"],))
        audit.record("auth.mfa_disabled", "user", user["id"], {})
    flash("Multi-factor authentication has been turned off.", "warning")
    return redirect(url_for("auth.account"))
