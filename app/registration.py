"""Self-service student registration with optional e-mail OTP verification
and Placement Cell approval.

Lifecycle: pending → approved (student record + login account created) or
rejected. Identity is anchored on two unique keys: the enrollment number and
the official e-mail address (compared through a keyed blind index, because the
address itself is stored encrypted).
"""
import hashlib
import hmac
import re
import secrets
from datetime import timedelta

from flask import current_app, url_for

from . import audit, mailer, services
from .constants import COURSE_CODE, COURSES, TS_FMT, now_iso, parse_ts, utcnow
from .crypto import blind_index, decrypt_field, encrypt_field, mask_email, mask_mobile
from .db import execute, query, transaction
from .validators import ValidationError


class OtpError(Exception):
    pass


# ------------------------------------------------------------------ helpers
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _aad(enrollment_no: str, field: str) -> str:
    return f"registration:{enrollment_no}:{field}"


def _otp_mac(request_id: int, code: str) -> str:
    key = current_app.extensions["pg_keys"]["secret_key"]
    return hmac.new(key, f"otp:{request_id}:{code}".encode(), hashlib.sha256).hexdigest()


def contact_of(req) -> dict:
    return {"email": decrypt_field(req["email_enc"], _aad(req["enrollment_no"], "email")),
            "mobile": decrypt_field(req["mobile_enc"], _aad(req["enrollment_no"], "mobile"))}


def get_by_token(token: str):
    if not token or len(token) > 100:
        return None
    return query("SELECT * FROM registration_requests WHERE ref_hash = ?", (_token_hash(token),), one=True)


def get(request_id: int):
    return query("SELECT * FROM registration_requests WHERE id = ?", (request_id,), one=True)


def identity_conflicts(enrollment_no: str, email: str, mobile: str, exclude_request: int | None = None) -> dict:
    """Uniqueness across students, accounts and other pending requests."""
    ex = exclude_request or -1
    errors = {}
    if (query("SELECT 1 FROM students WHERE enrollment_no = ?", (enrollment_no,), one=True)
            or query("SELECT 1 FROM users WHERE username = ?", (enrollment_no.lower(),), one=True)):
        errors["enrollment_no"] = "This enrollment number is already registered on the platform."
    elif query("SELECT 1 FROM registration_requests WHERE enrollment_no = ? AND status = 'pending' AND id != ?",
               (enrollment_no, ex), one=True):
        errors["enrollment_no"] = "A registration request for this enrollment number is already awaiting review."
    e_idx = blind_index(email, "email")
    if query("SELECT 1 FROM students WHERE email_index = ?", (e_idx,), one=True):
        errors["email"] = "This e-mail address is already linked to a student on the platform."
    elif query("SELECT 1 FROM registration_requests WHERE email_index = ? AND status = 'pending' AND id != ?",
               (e_idx, ex), one=True):
        errors["email"] = "A registration request for this e-mail address is already awaiting review."
    m_idx = blind_index(mobile, "mobile")
    if query("SELECT 1 FROM students WHERE mobile_index = ?", (m_idx,), one=True):
        errors["mobile"] = "This mobile number is already linked to a student on the platform."
    return errors


# ------------------------------------------------------------------ create
def create_request(data: dict, password_hash: str) -> tuple[int, str]:
    errors = identity_conflicts(data["enrollment_no"], data["email"], data["mobile"])
    if errors:
        raise ValidationError(errors)
    token = secrets.token_urlsafe(32)
    enrol = data["enrollment_no"]
    now = now_iso()
    with transaction():
        rid = execute(
            "INSERT INTO registration_requests (ref_hash, enrollment_no, full_name, email_enc, email_index, email_masked,"
            " mobile_enc, mobile_index, mobile_masked, course, batch, cgpa, password_hash, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (_token_hash(token), enrol, data["full_name"],
             encrypt_field(data["email"], _aad(enrol, "email")), blind_index(data["email"], "email"), mask_email(data["email"]),
             encrypt_field(data["mobile"], _aad(enrol, "mobile")), blind_index(data["mobile"], "mobile"), mask_mobile(data["mobile"]),
             data["course"], data["batch"], data.get("cgpa"), password_hash, now, now)).lastrowid
        audit.record("registration.submit", "registration", rid,
                     {"enrollment_no": enrol, "course": data["course"], "batch": data["batch"],
                      "email": mask_email(data["email"])}, actor={})
    return rid, token


# ------------------------------------------------------------------ OTP
def issue_otp(req, token: str) -> str:
    """Generate, store (hashed) and send a 6-digit code. Enforces a resend
    cooldown and a per-request send limit."""
    cfg = current_app.config
    if req["status"] != "pending" or req["email_verified"]:
        raise OtpError("This request does not need e-mail verification.")
    if req["otp_sends"] >= cfg["OTP_MAX_SENDS"]:
        raise OtpError("Too many codes have been sent for this request. Contact the Placement Cell.")
    if req["otp_sent_at"] and (utcnow() - parse_ts(req["otp_sent_at"])).total_seconds() < cfg["OTP_RESEND_SECONDS"]:
        raise OtpError(f"Please wait {cfg['OTP_RESEND_SECONDS']} seconds before requesting another code.")
    code = f"{secrets.randbelow(10 ** 6):06d}"
    expires = (utcnow() + timedelta(minutes=cfg["OTP_TTL_MINUTES"])).strftime(TS_FMT)
    with transaction():
        execute("UPDATE registration_requests SET otp_hash = ?, otp_expires_at = ?, otp_attempts = 0, otp_sent_at = ?,"
                " otp_sends = otp_sends + 1, updated_at = ? WHERE id = ?",
                (_otp_mac(req["id"], code), expires, now_iso(), now_iso(), req["id"]))
        audit.record("registration.otp_sent", "registration", req["id"], {"send": req["otp_sends"] + 1}, actor={})
    status_url = url_for("register.status", token=token, _external=True)
    body = (f"Dear {req['full_name']},\n\n"
            f"Your verification code for Placement Sahaay is: {code}\n\n"
            f"It expires in {cfg['OTP_TTL_MINUTES']} minutes and can be used once. Do not share it with anyone; "
            "the Placement Cell will never ask for it.\n\n"
            f"Track your registration request: {status_url}\n\n"
            "If you did not request this, ignore this message.\n\n"
            "Student Placement Cell, NFSU Gandhinagar")
    return mailer.send_mail(contact_of(req)["email"], "Your Placement Sahaay verification code", body)


def verify_otp(req, code: str) -> None:
    cfg = current_app.config
    code = (code or "").strip().replace(" ", "")
    if req["email_verified"]:
        return
    if not req["otp_hash"] or not req["otp_expires_at"]:
        raise OtpError("Request a verification code first.")
    if req["otp_attempts"] >= cfg["OTP_MAX_ATTEMPTS"]:
        raise OtpError("Too many incorrect attempts. Request a new code.")
    if parse_ts(req["otp_expires_at"]) < utcnow():
        raise OtpError("This code has expired. Request a new code.")
    ok = bool(re.fullmatch(r"\d{6}", code)) and hmac.compare_digest(req["otp_hash"], _otp_mac(req["id"], code))
    with transaction():
        if ok:
            execute("UPDATE registration_requests SET email_verified = 1, otp_hash = NULL, otp_expires_at = NULL,"
                    " updated_at = ? WHERE id = ?", (now_iso(), req["id"]))
            audit.record("registration.email_verified", "registration", req["id"], {}, actor={})
        else:
            execute("UPDATE registration_requests SET otp_attempts = otp_attempts + 1, updated_at = ? WHERE id = ?",
                    (now_iso(), req["id"]))
            audit.record("registration.otp_failed", "registration", req["id"],
                         {"attempt": req["otp_attempts"] + 1}, actor={})
    if not ok:
        left = cfg["OTP_MAX_ATTEMPTS"] - req["otp_attempts"] - 1
        raise OtpError(f"That code is not correct. {max(left, 0)} attempt(s) left.")


# ------------------------------------------------------------------ review
def next_placement_id(course: str, batch: str) -> str:
    prefix = f"NFSU-{batch[2:4]}-{COURSE_CODE[course]}-"
    taken = [r["placement_id"] for r in query("SELECT placement_id FROM students WHERE placement_id LIKE ?",
                                               (prefix + "%",))]
    nums = [int(p[len(prefix):]) for p in taken if p[len(prefix):].isdigit()]
    return f"{prefix}{(max(nums) + 1 if nums else 1):03d}"


def approve(req, reviewer, note: str | None) -> int:
    if req["status"] != "pending":
        raise ValidationError({"request": "This request has already been decided."})
    if current_app.config["REQUIRE_EMAIL_VERIFICATION"] and not req["email_verified"]:
        raise ValidationError({"request": "The applicant has not verified their official e-mail address yet."})
    contact = contact_of(req)
    conflicts = identity_conflicts(req["enrollment_no"], contact["email"], contact["mobile"], exclude_request=req["id"])
    if conflicts:
        raise ValidationError(conflicts)
    with transaction():
        pid = next_placement_id(req["course"], req["batch"])
        sid = services.insert_student({
            "placement_id": pid, "enrollment_no": req["enrollment_no"], "full_name": req["full_name"],
            "mobile": contact["mobile"], "email": contact["email"], "course": req["course"], "batch": req["batch"],
            "registration_status": "registered", "eligibility_status": "pending", "cgpa": req["cgpa"],
            "remarks": None})
        uid = execute("INSERT INTO users (username, display_name, password_hash, role, student_id, created_at)"
                      " VALUES (?,?,?,?,?,?)",
                      (req["enrollment_no"].lower(), req["full_name"], req["password_hash"], "student", sid,
                       now_iso())).lastrowid
        execute("UPDATE registration_requests SET status = 'approved', reviewed_by = ?, reviewed_at = ?, decision_note = ?,"
                " student_id = ?, password_hash = '', otp_hash = NULL, updated_at = ? WHERE id = ? AND status = 'pending'",
                (reviewer["id"], now_iso(), note, sid, now_iso(), req["id"]))
        audit.record("registration.approve", "registration", req["id"],
                     {"student_id": sid, "user_id": uid, "placement_id": pid, "enrollment_no": req["enrollment_no"],
                      "email_verified": bool(req["email_verified"]), "note": note})
    mailer.try_send(contact["email"], "Your Placement Sahaay registration is approved",
                     f"Dear {req['full_name']},\n\nYour registration has been approved by the Student Placement Cell.\n\n"
                     f"Placement ID: {pid}\nSign in with your enrollment number ({req['enrollment_no']}) or this e-mail "
                     "address, and the password you chose when registering.\n\n"
                     "Your academic eligibility will be verified by your course coordinator.\n\n"
                     "Student Placement Cell, NFSU Gandhinagar")
    return sid


def reject(req, reviewer, note: str) -> None:
    if req["status"] != "pending":
        raise ValidationError({"request": "This request has already been decided."})
    email = contact_of(req)["email"]
    with transaction():
        execute("UPDATE registration_requests SET status = 'rejected', reviewed_by = ?, reviewed_at = ?, decision_note = ?,"
                " password_hash = '', otp_hash = NULL, updated_at = ? WHERE id = ? AND status = 'pending'",
                (reviewer["id"], now_iso(), note, now_iso(), req["id"]))
        audit.record("registration.reject", "registration", req["id"], {"reason": note})
    mailer.try_send(email, "Your Placement Sahaay registration request",
                     f"Dear {req['full_name']},\n\nYour registration request could not be approved.\n\n"
                     f"Reason given by the Placement Cell: {note}\n\n"
                     "You may submit a corrected request, or contact the Student Placement Cell.\n\n"
                     "Student Placement Cell, NFSU Gandhinagar")


def pending_count(user) -> int:
    if user["role"] == "coordinator":
        return query("SELECT COUNT(*) AS n FROM registration_requests WHERE status = 'pending' AND course = ?",
                     (user["course_scope"],), one=True)["n"]
    return query("SELECT COUNT(*) AS n FROM registration_requests WHERE status = 'pending'", one=True)["n"]


assert set(COURSE_CODE) == set(COURSES)
