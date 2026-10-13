"""Security controls and resistance to common web-application attacks."""
import io
import sqlite3
import time
from datetime import timedelta

import pytest

from app.constants import TS_FMT, utcnow
from conftest import CSRF_RE, csrf_from, db_query, drive_id, login, student_id


# --- authentication -----------------------------------------------------------
def test_passwords_stored_with_memory_hard_kdf(app):
    for u in db_query(app, "SELECT password_hash FROM users"):
        assert u["password_hash"].startswith("scrypt:")


def test_generic_error_and_lockout_after_five_failures(client, app):
    for _ in range(5):
        r = login(client, "officer", "wrong-password-123")
        assert r.status_code == 401 and b"Incorrect username or password" in r.data
    r = login(client, "officer")  # correct password, but now locked
    assert r.status_code == 401 and b"temporarily locked" in r.data


def test_unknown_user_gets_same_error(client):
    r = login(client, "no-such-user", "whatever-123456")
    assert r.status_code == 401 and b"Incorrect username or password" in r.data


def test_login_rate_limited(client):
    codes = [login(client, "ghost", "x" * 12).status_code for _ in range(12)]
    assert 429 in codes


def test_sql_injection_in_login_is_inert(client):
    for payload in ("admin' OR '1'='1", "admin'--", "' UNION SELECT * FROM users--"):
        assert login(client, payload, "x' OR '1'='1").status_code == 401


def test_mfa_enrolment_login_and_replay(app, as_role):
    from app.security import totp_code
    c, token = as_role("officer")
    r = c.post("/account/mfa/start", data={"csrf_token": token})
    secret = CSRF_RE.pattern and r.get_data(as_text=True).split('aria-label="Setup key">')[1].split("<")[0].replace(" ", "")
    code = totp_code(secret)
    assert c.post("/account/mfa/confirm", data={"csrf_token": token, "code": code}).status_code == 302
    # New login now requires the second factor.
    c2 = app.test_client()
    r = login(c2, "officer")
    assert r.headers["Location"].startswith("/login/mfa")
    assert c2.get("/dashboard").status_code == 302  # not yet authenticated
    t2 = csrf_from(c2, "/login/mfa")
    assert c2.post("/login/mfa", data={"csrf_token": t2, "code": code}).status_code == 401  # replayed step
    time.sleep(0)  # same 30 s window: next step's code is accepted
    next_code = totp_code(secret, time.time() + 30)
    assert c2.post("/login/mfa", data={"csrf_token": t2, "code": next_code}).status_code == 302
    assert c2.get("/dashboard").status_code == 200


# --- sessions -----------------------------------------------------------------
def test_session_cookie_flags(client):
    r = login(client, "officer")
    cookie = r.headers.get("Set-Cookie")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_logout_revokes_server_side_session(as_role):
    c, token = as_role("officer")
    stolen = c.get_cookie("pg_session").value
    c.post("/logout", data={"csrf_token": token})
    c.set_cookie("pg_session", stolen)  # replay the old cookie
    assert c.get("/dashboard").status_code == 302


def test_idle_timeout(app, as_role):
    c, _ = as_role("officer")
    from app.db import execute
    old = (utcnow() - timedelta(minutes=30)).strftime(TS_FMT)
    with app.app_context():
        execute("UPDATE sessions SET last_seen_at = ?", (old,))
    assert c.get("/dashboard").status_code == 302


def test_session_bound_to_user_agent(as_role):
    c, _ = as_role("officer")
    assert c.get("/dashboard", headers={"User-Agent": "attacker-browser"}).status_code == 302


def test_session_fixation_prevented(app):
    c = app.test_client()
    c.set_cookie("pg_session", "attacker-chosen-session-id")
    login(c, "officer")
    assert c.get_cookie("pg_session").value != "attacker-chosen-session-id"
    assert c.get("/dashboard").status_code == 200


def test_open_redirect_rejected(client):
    token = csrf_from(client)
    r = client.post("/login", data={"username": "officer", "password": "Demo-Placement-2026", "csrf_token": token,
                                    "next": "//evil.example/phish"})
    assert r.headers["Location"] == "/dashboard"


# --- CSRF ---------------------------------------------------------------------
def test_post_without_csrf_token_rejected(as_role, app):
    c, _ = as_role("officer")
    sid = student_id(app, "NFSU-25-CS-002")
    assert c.post(f"/students/{sid}/archive", data={"reason": "testing csrf protection"}).status_code == 400


def test_cross_origin_post_rejected(as_role, app):
    c, token = as_role("officer")
    sid = student_id(app, "NFSU-25-CS-002")
    r = c.post(f"/students/{sid}/archive", data={"reason": "testing csrf protection", "csrf_token": token},
               headers={"Origin": "https://evil.example"})
    assert r.status_code == 400


# --- authorisation: the problem statement's "security challenge" ---------------
def test_student_cannot_view_another_students_record(as_role, app):
    c, _ = as_role("student.cs003")
    other = student_id(app, "NFSU-25-CS-004")
    assert c.get(f"/students/{other}").status_code == 403
    assert c.get("/students").status_code == 403


def test_student_cannot_change_own_status_or_package(as_role, app):
    c, token = as_role("student.cs003")
    own = student_id(app, "NFSU-25-CS-003")
    offer = db_query(app, "SELECT id FROM offers WHERE student_id = ?", (own,))[0]["id"]
    assert c.post(f"/students/{own}/edit", data={"csrf_token": token, "registration_status": "registered",
                                                 "eligibility_status": "eligible"}).status_code == 403
    assert c.post(f"/offers/{offer}/status", data={"csrf_token": token, "acceptance": "declined", "joining": "pending",
                                                   "ppo_status": "na", "noc_status": "na", "note": "self edit"}).status_code == 403
    assert c.post("/offers/new", data={"csrf_token": token, "placement_id": "NFSU-25-CS-003"}).status_code == 403
    assert db_query(app, "SELECT acceptance FROM offers WHERE id = ?", (offer,))[0]["acceptance"] == "accepted"


def test_student_cannot_bypass_switching_rules(as_role, app):
    """CS-003 holds a B offer at 7.5 LPA; Accenture (9.0 LPA) is below 1.5x.
    A forged POST is re-evaluated server-side and refused."""
    c, token = as_role("student.cs003")
    accenture = drive_id(app, "Accenture")
    c.post(f"/me/apply/{accenture}", data={"csrf_token": token})
    assert not db_query(app, "SELECT 1 FROM applications WHERE drive_id = ? AND student_id = ?",
                        (accenture, student_id(app, "NFSU-25-CS-003")))
    assert db_query(app, "SELECT 1 FROM audit_log WHERE action = 'application.refused'")


def test_student_cannot_apply_on_behalf_of_another(as_role, app):
    c, token = as_role("student.cs003")
    victim = student_id(app, "NFSU-25-CS-002")
    microsoft = drive_id(app, "Cisco")
    c.post(f"/me/apply/{microsoft}", data={"csrf_token": token, "student_id": victim, "placement_id": "NFSU-25-CS-002"})
    rows = db_query(app, "SELECT student_id FROM applications WHERE drive_id = ?", (microsoft,))
    assert victim not in [r["student_id"] for r in rows]


def test_denied_access_is_audited(as_role, app):
    c, _ = as_role("student.cs003")
    c.get("/admin/users")
    assert db_query(app, "SELECT 1 FROM audit_log WHERE action = 'authz.denied'")


def test_coordinator_scoped_to_own_programme(as_role, app):
    c, _ = as_role("coord.dfis")
    assert c.get(f"/students/{student_id(app, 'NFSU-25-CS-002')}").status_code == 403
    assert c.get(f"/students/{student_id(app, 'NFSU-25-DFIS-001')}").status_code == 200
    assert b"NFSU-25-CS-" not in c.get("/students").data


def test_mass_assignment_prevented_for_coordinator(as_role, app):
    c, token = as_role("coord.dfis")
    sid = student_id(app, "NFSU-25-DFIS-001")
    before = db_query(app, "SELECT * FROM students WHERE id = ?", (sid,))[0]
    c.post(f"/students/{sid}/edit", data={"csrf_token": token, "eligibility_status": "pending", "cgpa": "8.1",
                                         "full_name": "Hacked Name", "registration_status": "deregistered",
                                         "placement_id": "EVIL-001"})
    after = db_query(app, "SELECT * FROM students WHERE id = ?", (sid,))[0]
    assert after["eligibility_status"] == "pending"
    assert (after["full_name"], after["registration_status"], after["placement_id"]) == \
           (before["full_name"], before["registration_status"], before["placement_id"])


def test_recruiter_isolated_to_own_company(as_role, app):
    c, _ = as_role("recruiter.microsoft")
    assert c.get(f"/recruiter/drives/{drive_id(app, 'Google')}").status_code == 403
    assert c.get("/students").status_code == 403
    assert c.get("/offers").status_code == 403
    page = c.get(f"/recruiter/drives/{drive_id(app, 'Microsoft')}").get_data(as_text=True)
    assert "students.nfsu.ac.in" in page and "•••@" in page  # masked email only
    assert "+91 9" not in page  # no mobile numbers


def test_privilege_escalation_endpoints_admin_only(as_role):
    c, token = as_role("officer")
    assert c.get("/admin/users").status_code == 403
    assert c.post("/policy/settings", data={"csrf_token": token}).status_code == 403
    assert c.post("/admin/users", data={"csrf_token": token, "username": "x", "role": "admin"}).status_code == 403


# --- input handling -------------------------------------------------------------
def test_sql_injection_in_search_and_filters(as_role):
    c, _ = as_role("officer")
    r = c.get("/students", query_string={"q": "' OR 1=1 --"})
    assert r.status_code == 200 and b"No students found" in r.data
    assert c.get("/students", query_string={"course": "MSC_DFIS' OR '1'='1"}).status_code == 400


def test_stored_xss_is_escaped(as_role, app):
    c, token = as_role("officer")
    sid = student_id(app, "NFSU-25-CS-002")
    page = c.get(f"/students/{sid}/edit").get_data(as_text=True)
    mobile = page.split('name="mobile" type="tel" value="')[1].split('"')[0]
    email = page.split('name="email" type="email" value="')[1].split('"')[0]
    payload = '<script>alert("x")</script><img src=x onerror=alert(1)>'
    st = db_query(app, "SELECT * FROM students WHERE id = ?", (sid,))[0]
    c.post(f"/students/{sid}/edit", data={"csrf_token": token, "full_name": st["full_name"], "mobile": mobile,
                                         "email": email, "course": st["course"], "batch": st["batch"],
                                         "registration_status": st["registration_status"],
                                         "eligibility_status": st["eligibility_status"], "remarks": payload})
    html = c.get(f"/students/{sid}").get_data(as_text=True)
    assert "<script>alert" not in html and "&lt;script&gt;" in html


def test_name_validation_rejects_markup(as_role):
    c, token = as_role("officer")
    r = c.post("/students/new", data={"csrf_token": token, "placement_id": "NFSU-25-CS-099",
                                      "full_name": "<b>Bad</b>", "mobile": "9876500000", "email": "a@b.co",
                                      "course": "MTECH_CS", "batch": "2025-27", "registration_status": "registered",
                                      "eligibility_status": "eligible"})
    assert r.status_code == 422


def test_duplicate_placement_id_and_email_rejected(as_role, app):
    c, token = as_role("officer")
    base = {"csrf_token": token, "full_name": "New Person", "mobile": "9000000001", "course": "MTECH_CS",
            "batch": "2025-27", "registration_status": "registered", "eligibility_status": "eligible"}
    r = c.post("/students/new", data=base | {"placement_id": "NFSU-25-CS-001", "email": "fresh@example.com"})
    assert r.status_code == 422 and b"already exists" in r.data
    existing_email = c.get(f"/students/{student_id(app, 'NFSU-25-CS-002')}/edit").get_data(as_text=True) \
        .split('name="email" type="email" value="')[1].split('"')[0]
    r = c.post("/students/new", data=base | {"placement_id": "NFSU-25-CS-098", "email": existing_email.upper()})
    assert r.status_code == 422 and b"already registered" in r.data


def test_csv_import_is_all_or_nothing(as_role, app):
    c, token = as_role("officer")
    before = db_query(app, "SELECT COUNT(*) AS n FROM students")[0]["n"]
    csv_body = ("placement_id,full_name,mobile,email,course,batch,registration_status,eligibility_status,cgpa\n"
                "NFSU-26-CS-001,Valid Person,9123456780,valid@x.com,MTECH_CS,2026-28,registered,eligible,8.2\n"
                "NFSU-26-CS-002,=HYPERLINK(1),12345,not-an-email,UNKNOWN,2026-28,registered,eligible,11\n")
    r = c.post("/students/import", data={"csrf_token": token, "file": (io.BytesIO(csv_body.encode()), "s.csv")},
               content_type="multipart/form-data")
    assert r.status_code == 422
    assert db_query(app, "SELECT COUNT(*) AS n FROM students")[0]["n"] == before


def test_upload_size_limit(as_role):
    c, token = as_role("officer")
    big = io.BytesIO(b"a" * (2 * 1024 * 1024))
    r = c.post("/students/import", data={"csrf_token": token, "file": (big, "big.csv")}, content_type="multipart/form-data")
    assert r.status_code in (400, 413)


# --- confidentiality ------------------------------------------------------------
def test_contact_details_encrypted_at_rest(app):
    raw = sqlite3.connect(app.config["DATABASE"])
    for mobile_enc, email_enc in raw.execute("SELECT mobile_enc, email_enc FROM students"):
        assert mobile_enc.startswith("v1:") and "@" not in email_enc
    raw.close()
    dump = open(app.config["DATABASE"], "rb").read()
    from app import services
    with app.app_context():
        for st in [services.get_student(i) for i in (1, 2, 3)]:
            contact = services.contact_of(st)
            assert contact["email"].encode() not in dump and contact["mobile"].encode() not in dump


def test_ciphertext_cannot_be_swapped_between_records(app):
    from app import services
    with app.app_context():
        a = services.get_student(1)
        b = dict(services.get_student(2))
        b["mobile_enc"] = a["mobile_enc"]  # attacker copies another student's ciphertext
        with pytest.raises(ValueError):
            services.contact_of(b)


def test_contact_reveal_is_logged(as_role, app):
    c, token = as_role("officer")
    sid = student_id(app, "NFSU-25-CS-002")
    assert b"Reveal contact details" in c.get(f"/students/{sid}").data
    r = c.post(f"/students/{sid}/contact", data={"csrf_token": token})
    assert b"Access logged" in r.data
    assert db_query(app, "SELECT 1 FROM audit_log WHERE action = 'student.contact_view' AND entity_id = ?", (str(sid),))


def test_export_requires_role_reason_and_is_audited(as_role, app):
    c, token = as_role("coord.dfis")
    assert c.get("/reports/export").status_code == 403
    c, token = as_role("officer")
    assert c.post("/reports/export", data={"csrf_token": token, "dataset": "offers", "reason": "short"}).status_code == 422
    r = c.post("/reports/export", data={"csrf_token": token, "dataset": "students", "include_contact": "1",
                                        "reason": "Annual placement statistics"})
    assert r.status_code == 422  # officers may not export contact details
    r = c.post("/reports/export", data={"csrf_token": token, "dataset": "offers", "reason": "Annual placement statistics"})
    assert r.status_code == 200 and r.mimetype == "text/csv"
    entry = db_query(app, "SELECT detail FROM audit_log WHERE action = 'export.csv'")[0]
    assert r.headers["X-Export-SHA256"] in entry["detail"]


def test_csv_formula_injection_neutralised():
    from app.routes.reports import _cell
    assert _cell("=HYPERLINK(\"http://x\")").startswith("'")
    assert _cell("+1") == "'+1" and _cell("Plain") == "Plain"


# --- integrity ------------------------------------------------------------------
def test_audit_log_is_append_only(app):
    raw = sqlite3.connect(app.config["DATABASE"])
    with pytest.raises(sqlite3.DatabaseError):
        raw.execute("UPDATE audit_log SET actor = 'nobody' WHERE id = 1")
    with pytest.raises(sqlite3.DatabaseError):
        raw.execute("DELETE FROM audit_log WHERE id = 1")


def test_audit_chain_detects_tampering(app):
    from app.audit import verify_chain
    from app.db import get_db
    with app.app_context():
        assert verify_chain()["ok"]
    raw = sqlite3.connect(app.config["DATABASE"])
    raw.execute("DROP TRIGGER audit_log_no_update")  # an attacker with file access
    raw.execute("UPDATE audit_log SET detail = '{\"forged\":true}' WHERE id = 5")
    raw.commit()
    with app.app_context():
        get_db()
        result = verify_chain()
    assert not result["ok"] and result["bad_id"] == 5


def test_security_headers(client):
    h = client.get("/login").headers
    assert "script-src 'self'" in h["Content-Security-Policy"] and "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    assert h["Cache-Control"] == "no-store" and h["Referrer-Policy"] == "no-referrer"


def test_errors_do_not_leak_internals(as_role):
    c, _ = as_role("officer")
    r = c.get("/students/999999")
    assert r.status_code == 404 and b"Traceback" not in r.data


# --- backup and recovery --------------------------------------------------------
def test_encrypted_backup_and_restore_verification(app, tmp_path):
    from app import backup
    keys = app.extensions["pg_keys"]
    info = backup.create_backup(app.config["DATABASE"], str(tmp_path), keys["backup_key"])
    path = tmp_path / "backups" / info["name"]
    assert b"SQLite format" not in path.read_bytes()  # encrypted
    result = backup.verify_backup(path, keys["backup_key"], keys["audit_key"])
    assert result["ok"] and result["counts"]["students"] == 44
    blob = bytearray(path.read_bytes())
    blob[-5] ^= 0xFF  # corrupt one byte
    path.write_bytes(bytes(blob))
    assert not backup.verify_backup(path, keys["backup_key"], keys["audit_key"])["ok"]


def test_backup_name_path_traversal_rejected(app):
    from app import backup
    with pytest.raises(ValueError):
        backup.resolve(app.config["INSTANCE_DIR"], "../keys.json")
