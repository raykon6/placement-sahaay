"""Placement Sahaay — secure, policy-driven student placement management."""
import os

from flask import Flask, render_template

from . import db, security
from .config import Config, load_keys
from .constants import (ACCEPTANCE, APPLICATION, ATTENDANCE, COURSE_SHORT, COURSES, ELIGIBILITY, EVENTS,
                        FLAG_KINDS, IST, JOINING, NOC, OFFER_TYPE_SHORT, OFFER_TYPES, PLACEMENT_STATUS, PPO,
                        REGISTRATION, REQUEST_STATUS, ROLES, parse_ts)

ERROR_TEXT = {
    400: ("Request rejected", "The request could not be processed."),
    403: ("Access denied", "Your role does not permit this action. The attempt has been recorded."),
    404: ("Not found", "The page or record you requested does not exist."),
    405: ("Method not allowed", "This action is not available here."),
    409: ("Record changed", "Someone else updated this record. Reload and try again."),
    413: ("File too large", "Uploads are limited to 1 MB."),
    429: ("Too many attempts", "Please wait a minute before trying again."),
    500: ("Something went wrong", "An unexpected error occurred. No details are shown for security reasons."),
}


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    os.makedirs(app.config["INSTANCE_DIR"], exist_ok=True)
    keys = load_keys(app.config["INSTANCE_DIR"])
    app.extensions["pg_keys"] = keys
    app.config["SECRET_KEY"] = keys["secret_key"]
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_SECURE"] = app.config["HTTPS"]

    db.init_app(app)
    with app.app_context():
        db.init_schema(db.get_db())
    security.init_app(app)

    from .routes import admin, auth, drives, main, offers, policy_views, register, reports, students
    for bp in (auth.bp, main.bp, students.bp, drives.bp, offers.bp, policy_views.bp, reports.bp, admin.bp, register.bp):
        app.register_blueprint(bp)

    _register_filters(app)

    @app.context_processor
    def _nav_counts():
        from flask import g
        from . import mailer, registration
        from .security import has_perm
        user = g.get("user")
        if not user or not has_perm("registration.review", user):
            return {}
        return {"pending_registrations": registration.pending_count(user),
                "outbox_enabled": mailer.outbox_enabled()}

    for code, (title, message) in ERROR_TEXT.items():
        def handler(err, code=code, title=title, message=message):
            detail = getattr(err, "description", None) if code == 400 else None
            return render_template("error.html", code=code, title=title, message=detail or message), code
        app.register_error_handler(code, handler)
    return app


def _register_filters(app):
    vocab = {"course": COURSE_SHORT, "course_long": COURSES, "registration": REGISTRATION, "eligibility": ELIGIBILITY,
             "offer_type": OFFER_TYPE_SHORT, "offer_type_long": OFFER_TYPES, "acceptance": ACCEPTANCE,
             "joining": JOINING, "ppo": PPO, "noc": NOC, "application": APPLICATION, "event": EVENTS,
             "attendance": ATTENDANCE, "flag_kind": FLAG_KINDS, "role": ROLES, "placement": PLACEMENT_STATUS,
             "request_status": REQUEST_STATUS}

    @app.template_filter("label")
    def label(value, kind):
        return vocab[kind].get(value, value or "—")

    @app.template_filter("ist")
    def ist(value, fmt="%d %b %Y, %H:%M"):
        if not value:
            return "—"
        return parse_ts(value).astimezone(IST).strftime(fmt) + " IST"

    @app.template_filter("lpa")
    def lpa(value):
        return "—" if value is None else f"₹{value:g} LPA"

    @app.template_filter("inr")
    def inr(value):
        if value is None:
            return "—"
        s = f"{int(round(value)):d}"
        head, tail = s[:-3], s[-3:]
        parts = []
        while len(head) > 2:
            parts.insert(0, head[-2:])
            head = head[:-2]
        if head:
            parts.insert(0, head)
        return "₹" + ",".join(parts + [tail]) if parts else "₹" + tail

    app.jinja_env.globals.update(COURSES=COURSES, COURSE_SHORT=COURSE_SHORT, REGISTRATION=REGISTRATION,
                                 ELIGIBILITY=ELIGIBILITY, OFFER_TYPES=OFFER_TYPES, ACCEPTANCE=ACCEPTANCE,
                                 JOINING=JOINING, PPO=PPO, NOC=NOC, EVENTS=EVENTS, ATTENDANCE=ATTENDANCE,
                                 APPLICATION=APPLICATION, ROLES=ROLES, PLACEMENT_STATUS=PLACEMENT_STATUS,
                                 FLAG_KINDS=FLAG_KINDS)
