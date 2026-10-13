"""Public self-registration (with optional e-mail OTP) and the staff review queue."""
import smtplib

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .. import mailer, registration
from ..constants import COURSES, REQUEST_STATUS
from ..db import query
from ..security import deny, flash, hash_password, password_problems, rate_limit, require
from ..validators import ValidationError, reason, registration_fields

bp = Blueprint("register", __name__)


def _status_page(req, token, **extra):
    return render_template("register_status.html", req=req, token=token, outbox=mailer.outbox_enabled(),
                           require_verification=current_app.config["REQUIRE_EMAIL_VERIFICATION"], **extra)


# ------------------------------------------------------------------ applicant
@bp.route("/register", methods=["GET", "POST"])
def form():
    if g.user:
        return redirect(url_for("main.index"))
    domains = current_app.config["OFFICIAL_EMAIL_DOMAINS"]
    if request.method == "GET":
        return render_template("register.html", form={}, errors={}, domains=domains)

    rate_limit("register", 5)
    if request.form.get("website"):  # honeypot field, invisible to people
        abort(400, description="Request rejected.")
    errors = {}
    try:
        data = registration_fields(request.form, domains)
    except ValidationError as exc:
        errors, data = exc.errors, None
    if data:
        problems = password_problems(data["password"], data["enrollment_no"])
        if problems:
            errors["password"] = " ".join(problems)
    if errors:
        return render_template("register.html", form=request.form, errors=errors, domains=domains), 422
    try:
        rid, token = registration.create_request(data, hash_password(data["password"]))
    except ValidationError as exc:
        return render_template("register.html", form=request.form, errors=exc.errors, domains=domains), 422

    req = registration.get(rid)
    try:
        delivery = registration.issue_otp(req, token)
        flash("Request submitted. A verification code has been sent to your official e-mail."
              + (" (Development mode: the message was saved to the local outbox.)" if delivery == "outbox" else ""), "success")
    except (registration.OtpError, OSError, smtplib.SMTPException):
        flash("Request submitted. The verification code could not be sent right now; you can resend it below.", "warning")
    return redirect(url_for("register.status", token=token))


@bp.route("/register/status/<token>")
def status(token):
    req = registration.get_by_token(token)
    if req is None:
        abort(404)
    return _status_page(req, token)


@bp.route("/register/status/<token>/verify", methods=["POST"])
def verify(token):
    rate_limit("register-otp", 10)
    req = registration.get_by_token(token)
    if req is None:
        abort(404)
    try:
        registration.verify_otp(req, request.form.get("code", ""))
    except registration.OtpError as exc:
        return _status_page(registration.get(req["id"]), token, otp_error=str(exc)), 422
    flash("E-mail address verified. Your request is now with the Placement Cell.", "success")
    return redirect(url_for("register.status", token=token))


@bp.route("/register/status/<token>/resend", methods=["POST"])
def resend(token):
    rate_limit("register-otp", 10)
    req = registration.get_by_token(token)
    if req is None:
        abort(404)
    try:
        delivery = registration.issue_otp(req, token)
    except registration.OtpError as exc:
        return _status_page(req, token, otp_error=str(exc)), 429
    except (OSError, smtplib.SMTPException):
        return _status_page(req, token, otp_error="The code could not be sent. Try again later."), 503
    flash("A new code has been sent." + (" (Development mode: saved to the local outbox.)" if delivery == "outbox" else ""),
          "success")
    return redirect(url_for("register.status", token=token))


# ------------------------------------------------------------------ staff review
def _load(request_id):
    req = registration.get(request_id)
    if req is None:
        abort(404)
    if g.user["role"] == "coordinator" and req["course"] != g.user["course_scope"]:
        deny("registration_out_of_scope", {"request_id": request_id})
    return req


@bp.route("/registrations")
@require("registration.review")
def queue():
    status_filter = request.args.get("status") or "pending"
    if status_filter not in REQUEST_STATUS:
        abort(400, description="Unknown filter value.")
    sql = ("SELECT r.*, u.username AS reviewer FROM registration_requests r LEFT JOIN users u ON u.id = r.reviewed_by"
           " WHERE r.status = ?")
    params = [status_filter]
    if g.user["role"] == "coordinator":
        sql += " AND r.course = ?"
        params.append(g.user["course_scope"])
    rows = query(sql + " ORDER BY r.created_at", params)
    items = []
    for r in rows:
        conflicts = {}
        if r["status"] == "pending":
            c = registration.contact_of(r)
            conflicts = registration.identity_conflicts(r["enrollment_no"], c["email"], c["mobile"], exclude_request=r["id"])
        items.append({"req": r, "conflicts": conflicts})
    return render_template("registrations.html", items=items, status=status_filter, statuses=REQUEST_STATUS,
                           require_verification=current_app.config["REQUIRE_EMAIL_VERIFICATION"])


@bp.route("/registrations/<int:request_id>/approve", methods=["POST"])
@require("registration.review")
def approve(request_id):
    req = _load(request_id)
    note = (request.form.get("note") or "").strip()[:300] or None
    try:
        registration.approve(req, g.user, note)
    except ValidationError as exc:
        flash("Not approved: " + " ".join(exc.errors.values()), "error")
        return redirect(url_for("register.queue"))
    flash(f"{req['full_name']} approved. A student record and login were created.", "success")
    return redirect(url_for("register.queue"))


@bp.route("/registrations/<int:request_id>/reject", methods=["POST"])
@require("registration.review")
def reject(request_id):
    req = _load(request_id)
    try:
        why = reason(request.form, label="the reason shared with the applicant")
        registration.reject(req, g.user, why)
    except ValidationError as exc:
        flash(" ".join(exc.errors.values()), "error")
        return redirect(url_for("register.queue"))
    flash(f"Request from {req['full_name']} rejected and the applicant notified.", "success")
    return redirect(url_for("register.queue"))


@bp.route("/admin/outbox")
@require("outbox.read")
def outbox():
    if not mailer.outbox_enabled():
        abort(404)
    return render_template("admin/outbox.html", mails=mailer.list_outbox())
