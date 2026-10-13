"""Self-registration, e-mail OTP verification and coordinator approval."""
import re
import sqlite3
from datetime import timedelta

import pytest

from app.constants import TS_FMT, utcnow
from conftest import csrf_from, db_query, login

GOOD = {
    "enrollment_no": "2505990001", "full_name": "Asha Verma", "email": "asha.verma@students.nfsu.ac.in",
    "mobile": "9812345670", "course": "MSC_DFIS", "batch": "2025-27", "cgpa": "8.4",
    "password": "Forensic-Lab-2026!", "confirm_password": "Forensic-Lab-2026!", "consent": "1",
}


def register(client, **overrides):
    data = {**GOOD, **overrides, "csrf_token": csrf_from(client, "/register")}
    return client.post("/register", data=data)


def token_of(response):
    return response.headers["Location"].rsplit("/", 1)[-1]


def last_code(app):
    body = app.extensions["pg_outbox"][-1]["body"]
    return re.search(r"code for Placement Sahaay is: (\d{6})", body).group(1)


def request_row(app, enrollment="2505990001"):
    return db_query(app, "SELECT * FROM registration_requests WHERE enrollment_no = ? ORDER BY id DESC", (enrollment,))[0]


# --- submission ---------------------------------------------------------------
def test_registration_creates_pending_request_with_protected_data(app, client):
    r = register(client)
    assert r.status_code == 302 and "/register/status/" in r.headers["Location"]
    row = request_row(app)
    assert row["status"] == "pending" and row["email_verified"] == 0
    assert row["password_hash"].startswith("scrypt:")
    assert "asha" not in row["email_enc"] and row["email_enc"].startswith("v1:")
    assert row["otp_hash"] and len(app.extensions["pg_outbox"]) == 1  # code sent to the official address
    assert app.extensions["pg_outbox"][0]["to"] == GOOD["email"]
    raw = open(app.config["DATABASE"], "rb").read()
    assert GOOD["email"].encode() not in raw and b"Forensic-Lab-2026!" not in raw


def test_status_page_requires_valid_token(app, client):
    r = register(client)
    assert client.get(r.headers["Location"]).status_code == 200
    assert client.get("/register/status/not-a-real-token").status_code == 404


@pytest.mark.parametrize("field,value", [
    ("email", "asha@gmail.com"), ("email", "asha@evilnfsu.ac.in"), ("enrollment_no", "12"),
    ("enrollment_no", "2505<script>"), ("mobile", "12345"), ("consent", ""), ("confirm_password", "different-pass-1"),
    ("password", "short"), ("full_name", "<b>x</b>"),
])
def test_invalid_submissions_rejected(app, client, field, value):
    assert register(client, **{field: value}).status_code == 422
    assert not db_query(app, "SELECT 1 FROM registration_requests")


def test_enrollment_number_is_unique_across_platform(app, client):
    existing = db_query(app, "SELECT enrollment_no FROM students WHERE enrollment_no IS NOT NULL LIMIT 1")[0]["enrollment_no"]
    r = register(client, enrollment_no=existing)
    assert r.status_code == 422 and b"already registered" in r.data


def test_email_is_unique_and_one_pending_request_per_identity(app, client):
    register(client)
    r = register(app.test_client(), enrollment_no="2505990002", mobile="9812345671")  # same e-mail
    assert r.status_code == 422 and b"already awaiting review" in r.data
    r = register(app.test_client(), email="other@students.nfsu.ac.in", mobile="9812345671")  # same enrollment
    assert r.status_code == 422 and b"already awaiting review" in r.data


def test_existing_student_email_cannot_be_reused(app, client, as_role):
    c, _ = as_role("officer")
    sid = db_query(app, "SELECT id FROM students WHERE placement_id = 'NFSU-25-CS-002'")[0]["id"]
    email = c.get(f"/students/{sid}/edit").get_data(as_text=True).split('name="email" type="email" value="')[1].split('"')[0]
    r = register(client, email=email)
    assert r.status_code == 422 and b"already linked" in r.data


def test_honeypot_blocks_bots(app, client):
    assert register(client, website="http://spam.example").status_code == 400
    assert not db_query(app, "SELECT 1 FROM registration_requests")


def test_registration_rate_limited(app):
    codes = [register(app.test_client(), enrollment_no=f"25059900{i:02d}", email=f"u{i}@nfsu.ac.in",
                      mobile=f"98123456{i:02d}").status_code for i in range(7)]
    assert 429 in codes


# --- OTP ------------------------------------------------------------------------
def test_otp_verifies_email(app, client):
    token = token_of(register(client))
    t = csrf_from(client, f"/register/status/{token}")
    r = client.post(f"/register/status/{token}/verify", data={"csrf_token": t, "code": last_code(app)})
    assert r.status_code == 302 and request_row(app)["email_verified"] == 1
    assert request_row(app)["otp_hash"] is None  # code consumed


def test_wrong_otp_counts_attempts_and_locks(app, client):
    token = token_of(register(client))
    code = last_code(app)
    wrong = f"{(int(code) + 1) % 10 ** 6:06d}"
    t = csrf_from(client, f"/register/status/{token}")
    for _ in range(5):
        assert client.post(f"/register/status/{token}/verify", data={"csrf_token": t, "code": wrong}).status_code == 422
    r = client.post(f"/register/status/{token}/verify", data={"csrf_token": t, "code": code})  # right code, too late
    assert r.status_code == 422 and b"Too many incorrect attempts" in r.data
    assert request_row(app)["email_verified"] == 0


def test_expired_otp_rejected(app, client):
    token = token_of(register(client))
    code = last_code(app)
    raw = sqlite3.connect(app.config["DATABASE"])
    raw.execute("UPDATE registration_requests SET otp_expires_at = ?", ((utcnow() - timedelta(minutes=1)).strftime(TS_FMT),))
    raw.commit()
    t = csrf_from(client, f"/register/status/{token}")
    r = client.post(f"/register/status/{token}/verify", data={"csrf_token": t, "code": code})
    assert r.status_code == 422 and b"expired" in r.data


def test_otp_resend_has_cooldown(app, client):
    token = token_of(register(client))
    t = csrf_from(client, f"/register/status/{token}")
    r = client.post(f"/register/status/{token}/resend", data={"csrf_token": t})
    assert r.status_code == 429 and b"wait" in r.data
    raw = sqlite3.connect(app.config["DATABASE"])
    raw.execute("UPDATE registration_requests SET otp_sent_at = ?", ((utcnow() - timedelta(minutes=2)).strftime(TS_FMT),))
    raw.commit()
    assert client.post(f"/register/status/{token}/resend", data={"csrf_token": t}).status_code == 302
    assert len(app.extensions["pg_outbox"]) == 2


def test_otp_is_stored_only_as_a_mac(app, client):
    register(client)
    assert last_code(app) not in request_row(app)["otp_hash"]


# --- review ----------------------------------------------------------------------
def test_coordinator_approves_own_programme_and_student_can_sign_in(app, client, as_role):
    register(client)
    req = request_row(app)
    c, t = as_role("coord.dfis")
    assert b"Asha Verma" in c.get("/registrations").data
    r = c.post(f"/registrations/{req['id']}/approve", data={"csrf_token": t, "note": "Verified against roll list"})
    assert r.status_code == 302
    st = db_query(app, "SELECT * FROM students WHERE enrollment_no = '2505990001'")[0]
    assert st["placement_id"].startswith("NFSU-25-DFIS-") and st["registration_status"] == "registered"
    assert st["eligibility_status"] == "pending"
    user = db_query(app, "SELECT * FROM users WHERE username = '2505990001'")[0]
    assert user["role"] == "student" and user["student_id"] == st["id"]
    assert request_row(app)["password_hash"] == ""  # no longer kept on the request
    # Sign in with the enrollment number, then with the official e-mail.
    assert login(app.test_client(), "2505990001", GOOD["password"]).headers["Location"] == "/me"
    assert login(app.test_client(), GOOD["email"].upper(), GOOD["password"]).headers["Location"] == "/me"
    assert db_query(app, "SELECT 1 FROM audit_log WHERE action = 'registration.approve'")


def test_coordinator_cannot_review_other_programmes(app, client, as_role):
    register(client, course="MTECH_CS")
    req = request_row(app)
    c, t = as_role("coord.dfis")
    assert b"Asha Verma" not in c.get("/registrations").data
    assert c.post(f"/registrations/{req['id']}/approve", data={"csrf_token": t}).status_code == 403
    assert request_row(app)["status"] == "pending"


def test_students_and_recruiters_cannot_review(app, client, as_role):
    register(client)
    req = request_row(app)
    for user in ("student.cs003", "recruiter.microsoft"):
        c, t = as_role(user)
        assert c.get("/registrations").status_code == 403
        assert c.post(f"/registrations/{req['id']}/approve", data={"csrf_token": t}).status_code == 403


def test_reject_requires_reason_and_blocks_sign_in(app, client, as_role):
    register(client)
    req = request_row(app)
    c, t = as_role("officer")
    c.post(f"/registrations/{req['id']}/reject", data={"csrf_token": t, "reason": "no"})
    assert request_row(app)["status"] == "pending"
    c.post(f"/registrations/{req['id']}/reject", data={"csrf_token": t, "reason": "Enrollment number not on roll list"})
    assert request_row(app)["status"] == "rejected"
    assert login(app.test_client(), "2505990001", GOOD["password"]).status_code == 401
    # A corrected request may be submitted afterwards.
    assert register(app.test_client()).status_code == 302


def test_decided_request_cannot_be_approved_twice(app, client, as_role):
    register(client)
    req = request_row(app)
    c, t = as_role("officer")
    c.post(f"/registrations/{req['id']}/approve", data={"csrf_token": t})
    c.post(f"/registrations/{req['id']}/approve", data={"csrf_token": t})
    assert len(db_query(app, "SELECT 1 FROM students WHERE enrollment_no = '2505990001'")) == 1


def test_verification_can_be_made_mandatory(app, client, as_role):
    app.config["REQUIRE_EMAIL_VERIFICATION"] = True
    register(client)
    req = request_row(app)
    c, t = as_role("officer")
    c.post(f"/registrations/{req['id']}/approve", data={"csrf_token": t})
    assert request_row(app)["status"] == "pending"


def test_dev_outbox_admin_only(app, client, as_role):
    register(client)
    c, _ = as_role("admin")
    assert b"verification code" in c.get("/admin/outbox").data
    c, _ = as_role("officer")
    assert c.get("/admin/outbox").status_code == 403
