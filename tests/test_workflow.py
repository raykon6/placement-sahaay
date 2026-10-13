"""End-to-end placement workflows through the web layer."""
from datetime import timedelta

from app.constants import TS_FMT, utcnow
from conftest import db_query, drive_id, student_id


def test_officer_registration_respects_policy(as_role, app):
    c, token = as_role("officer")
    cisco = drive_id(app, "Cisco")
    # A+ holder is blocked outright.
    r = c.post(f"/drives/{cisco}/register", data={"csrf_token": token, "placement_id": "NFSU-25-DFIS-002"}, follow_redirects=True)
    assert b"Blocked by policy" in r.data
    # Unplaced, eligible student is registered.
    c.post(f"/drives/{cisco}/register", data={"csrf_token": token, "placement_id": "NFSU-25-DFIS-001"})
    assert db_query(app, "SELECT 1 FROM applications WHERE drive_id = ? AND student_id = ?",
                    (cisco, student_id(app, "NFSU-25-DFIS-001")))


def test_review_case_needs_recorded_approval(as_role, app):
    c, token = as_role("officer")
    qh = drive_id(app, "Quick Heal")  # F, 12.5 LPA
    pid = "NFSU-25-DFIS-006"  # holds F (Infosys 7.5 B) -> F->F conflict -> review
    c.post(f"/drives/{qh}/register", data={"csrf_token": token, "placement_id": pid})
    sid = student_id(app, pid)
    assert not db_query(app, "SELECT 1 FROM applications WHERE drive_id = ? AND student_id = ?", (qh, sid))
    c.post(f"/drives/{qh}/register", data={"csrf_token": token, "placement_id": pid,
                                           "override_reason": "Approved by Placement Cell meeting 12 Oct"})
    row = db_query(app, "SELECT decision FROM applications WHERE drive_id = ? AND student_id = ?", (qh, sid))
    assert row and "Approved by Placement Cell" in row[0]["decision"]


def test_absence_debars_next_three_drives(app):
    from app import services
    with app.app_context():
        st = services.get_student(student_id(app, "NFSU-25-DFIS-003"))
        barred = [services.evaluate(st, services.get_drive(drive_id(app, n))).outcome for n in
                  ("Mastercard", "Microsoft", "Accenture", "EY", "Quick Heal")]
    # Mastercard is not open to DFIS, so the next three eligible drives are Microsoft, Accenture, EY.
    assert barred[1:4] == ["block", "block", "block"] and barred[4] == "allow"


def test_excused_absence_requires_reason_and_lifts_bar(as_role, app):
    c, token = as_role("officer")
    tcs = drive_id(app, "TCS")
    sid = student_id(app, "NFSU-25-DFIS-003")
    c.post(f"/drives/{tcs}/attendance", data={"csrf_token": token, "event": "test", f"status_{sid}": "excused"})
    assert db_query(app, "SELECT status FROM attendance WHERE student_id = ?", (sid,))[0]["status"] == "absent"
    c.post(f"/drives/{tcs}/attendance", data={"csrf_token": token, "event": "test", f"status_{sid}": "excused",
                                             f"reason_{sid}": "Medical emergency, certificate verified"})
    assert db_query(app, "SELECT status FROM attendance WHERE student_id = ?", (sid,))[0]["status"] == "excused"
    from app import services
    with app.app_context():
        assert services.evaluate(services.get_student(sid), services.get_drive(drive_id(app, "Microsoft"))).outcome == "allow"


def test_offer_entry_flags_violation_and_derives_category(as_role, app):
    c, token = as_role("officer")
    accenture = drive_id(app, "Accenture")  # 9.0 LPA, B
    r = c.post("/offers/new", data={"csrf_token": token, "placement_id": "NFSU-25-CS-003", "drive_id": str(accenture),
                                    "offer_date": "2026-10-13", "response_hours": "72", "category": "A+", "ctc_lpa": "99"})
    assert r.status_code == 302
    o = db_query(app, "SELECT * FROM offers ORDER BY id DESC LIMIT 1")[0]
    assert (o["category"], o["ctc_lpa"], o["policy_outcome"]) == ("B", 9.0, "block")  # form values ignored
    assert db_query(app, "SELECT 1 FROM flags WHERE offer_id = ? AND kind = 'policy_violation'", (o["id"],))


def test_acceptance_deadline_is_earlier_of_24h_or_company(as_role, app):
    c, token = as_role("officer")
    c.post("/offers/new", data={"csrf_token": token, "placement_id": "NFSU-25-DFIS-001", "drive_id": "",
                                "company_name": "Fast Corp", "offer_type": "F", "ctc_lpa": "8", "offer_date": "2026-10-13",
                                "response_hours": "6"})
    o = db_query(app, "SELECT * FROM offers ORDER BY id DESC LIMIT 1")[0]
    from app.constants import parse_ts
    hours = (parse_ts(o["deadline_at"]) - parse_ts(o["created_at"])).total_seconds() / 3600
    assert round(hours) == 6 and o["off_campus"] == 1 and o["noc_status"] == "requested"


def test_expired_offer_cannot_be_accepted_and_is_flagged(as_role, app):
    from app.db import execute
    c, token = as_role("officer")
    pending = db_query(app, "SELECT id, student_id FROM offers WHERE acceptance = 'pending'")[0]
    with app.app_context():
        execute("UPDATE offers SET deadline_at = ? WHERE id = ?", ((utcnow() - timedelta(hours=1)).strftime(TS_FMT), pending["id"]))
    r = c.post(f"/offers/{pending['id']}/status", data={"csrf_token": token, "acceptance": "accepted", "joining": "pending",
                                                        "ppo_status": "na", "noc_status": "na", "note": "student replied"})
    assert r.status_code == 422
    assert db_query(app, "SELECT acceptance FROM offers WHERE id = ?", (pending["id"],))[0]["acceptance"] == "expired"
    assert db_query(app, "SELECT 1 FROM flags WHERE offer_id = ? AND kind = 'offer_expired'", (pending["id"],))


def test_reneging_is_flagged_and_history_preserved(as_role, app):
    c, token = as_role("officer")
    sid = student_id(app, "NFSU-25-AIDS-001")
    offer = db_query(app, "SELECT id FROM offers WHERE student_id = ?", (sid,))[0]["id"]
    c.post(f"/offers/{offer}/status", data={"csrf_token": token, "acceptance": "declined", "joining": "pending",
                                            "ppo_status": "na", "noc_status": "na", "note": "Student withdrew acceptance"})
    assert db_query(app, "SELECT 1 FROM flags WHERE offer_id = ? AND kind = 'policy_violation'", (offer,))
    hist = db_query(app, "SELECT detail FROM audit_log WHERE action = 'offer.update' AND entity_id = ?", (str(offer),))
    assert '"before": {"acceptance": "accepted"}' in hist[0]["detail"]


def test_reports_count_unique_students_separately_from_offers(app):
    from app import services
    with app.app_context():
        s = services.dashboard_stats()
    assert s["total_offers"] > s["unique_students_with_offers"]  # DFIS-006 holds two offers
    assert s["fte"]["highest"] == 18.0 and s["stipend"]["highest"] == 50000


def test_policy_change_is_audited_with_before_after(as_role, app):
    c, token = as_role("admin")
    form = {"csrf_token": token, "a_plus_min_lpa": "18", "a_min_lpa": "10", "b_min_lpa": "6", "b_switch_multiplier": "1.5",
            "absence_debar_drives": "3", "acceptance_window_hours": "24", "declined_offers_count": "1",
            "conflict_mode": "review", "retention_years": "5", "reason": "Guidelines amendment 2026/07"}
    assert c.post("/policy/settings", data=form).status_code == 302
    entry = db_query(app, "SELECT detail FROM audit_log WHERE action = 'policy.update'")[0]["detail"]
    assert '"a_plus_min_lpa": 16.0' in entry and '"a_plus_min_lpa": 18.0' in entry
    bad = form | {"a_plus_min_lpa": "5"}
    assert c.post("/policy/settings", data=bad).status_code == 422


def test_archive_and_anonymise_preserve_statistics(as_role, app):
    c, token = as_role("admin")
    sid = student_id(app, "NFSU-25-CSE-001")
    offers_before = db_query(app, "SELECT COUNT(*) AS n FROM offers")[0]["n"]
    c.post(f"/students/{sid}/archive", data={"csrf_token": token, "reason": "Graduated batch beyond retention"})
    c.post(f"/students/{sid}/anonymize", data={"csrf_token": token, "reason": "Retention period of five years ended"})
    st = db_query(app, "SELECT * FROM students WHERE id = ?", (sid,))[0]
    assert st["anonymized"] == 1 and st["full_name"] == "Anonymised student" and st["mobile_masked"] == "—"
    assert db_query(app, "SELECT COUNT(*) AS n FROM offers")[0]["n"] == offers_before


def test_every_role_can_open_the_guide(as_role):
    for user in ("admin", "officer", "coord.dfis", "recruiter.microsoft", "student.cs003"):
        c, _ = as_role(user)
        page = c.get("/guide")
        assert page.status_code == 200 and b"How Placement Sahaay works" in page.data
