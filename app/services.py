"""Domain services: persistence plus policy orchestration. Routes call these;
these call the pure policy engine and write audit records."""
import json
import secrets
import statistics
from datetime import timedelta

from flask import g

from . import audit, policy
from .constants import now_iso, parse_ts, utcnow, TS_FMT
from .crypto import blind_index, decrypt_field, encrypt_field, mask_email, mask_mobile
from .db import execute, query, transaction
from .validators import ValidationError

STUDENT_COLUMNS_AUDITED = ("full_name", "course", "batch", "registration_status", "eligibility_status",
                           "cgpa", "remarks")


# ---------------------------------------------------------------- settings
def get_settings() -> dict:
    s = dict(policy.DEFAULT_SETTINGS)
    for row in query("SELECT key, value FROM policy_settings"):
        if row["key"] in s:
            s[row["key"]] = json.loads(row["value"])
    return s


# ---------------------------------------------------------------- students
def get_student(student_id: int):
    return query("SELECT * FROM students WHERE id = ?", (student_id,), one=True)


def contact_of(student) -> dict:
    aad = "students:" + student["placement_id"]
    return {"mobile": decrypt_field(student["mobile_enc"], aad + ":mobile"),
            "email": decrypt_field(student["email_enc"], aad + ":email")}


def _contact_columns(placement_id: str, mobile: str, email: str) -> dict:
    aad = "students:" + placement_id
    return {
        "mobile_enc": encrypt_field(mobile, aad + ":mobile"),
        "mobile_index": blind_index(mobile, "mobile"),
        "mobile_masked": mask_mobile(mobile),
        "email_enc": encrypt_field(email, aad + ":email"),
        "email_index": blind_index(email, "email"),
        "email_masked": mask_email(email),
    }


def duplicate_errors(data: dict, exclude_id: int | None = None) -> dict:
    errors = {}
    ex = exclude_id or -1
    if "placement_id" in data and query("SELECT 1 FROM students WHERE placement_id = ? AND id != ?",
                                        (data["placement_id"], ex), one=True):
        errors["placement_id"] = "A student with this Placement ID already exists."
    if "mobile" in data and query("SELECT 1 FROM students WHERE mobile_index = ? AND id != ?",
                                  (blind_index(data["mobile"], "mobile"), ex), one=True):
        errors["mobile"] = "This mobile number is already registered to another student."
    if "email" in data and query("SELECT 1 FROM students WHERE email_index = ? AND id != ?",
                                 (blind_index(data["email"], "email"), ex), one=True):
        errors["email"] = "This email address is already registered to another student."
    return errors


def insert_student(data: dict) -> int:
    """Caller must hold a transaction and have validated `data`."""
    errors = duplicate_errors(data)
    if errors:
        raise ValidationError(errors)
    now = now_iso()
    cols = _contact_columns(data["placement_id"], data["mobile"], data["email"])
    cur = execute(
        "INSERT INTO students (placement_id, full_name, mobile_enc, mobile_index, mobile_masked, email_enc,"
        " email_index, email_masked, course, batch, registration_status, eligibility_status, cgpa, remarks,"
        " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (data["placement_id"], data["full_name"], cols["mobile_enc"], cols["mobile_index"], cols["mobile_masked"],
         cols["email_enc"], cols["email_index"], cols["email_masked"], data["course"], data["batch"],
         data["registration_status"], data["eligibility_status"], data.get("cgpa"), data.get("remarks"), now, now),
    )
    return cur.lastrowid


def create_student(data: dict) -> int:
    with transaction():
        sid = insert_student(data)
        audit.record("student.create", "student", sid, {
            "placement_id": data["placement_id"], "course": data["course"], "batch": data["batch"],
            "registration_status": data["registration_status"], "eligibility_status": data["eligibility_status"]})
    return sid


def update_student(student, data: dict) -> list:
    """Apply validated, role-filtered changes; returns the changed fields."""
    errors = duplicate_errors(data, exclude_id=student["id"])
    if errors:
        raise ValidationError(errors)
    sets, params, before, after = [], [], {}, {}
    for col in STUDENT_COLUMNS_AUDITED:
        if col in data and data[col] != student[col]:
            sets.append(f"{col} = ?")  # column names come from a fixed allow-list
            params.append(data[col])
            before[col], after[col] = student[col], data[col]
    if "mobile" in data or "email" in data:
        current = contact_of(student)
        mobile = data.get("mobile", current["mobile"])
        email = data.get("email", current["email"])
        if mobile != current["mobile"] or email != current["email"]:
            cols = _contact_columns(student["placement_id"], mobile, email)
            for col, val in cols.items():
                sets.append(f"{col} = ?")
                params.append(val)
            if mobile != current["mobile"]:
                before["mobile"], after["mobile"] = student["mobile_masked"], cols["mobile_masked"]
            if email != current["email"]:
                before["email"], after["email"] = student["email_masked"], cols["email_masked"]
    if not sets:
        return []
    sets.append("updated_at = ?")
    params += [now_iso(), student["id"]]
    with transaction():
        execute(f"UPDATE students SET {', '.join(sets)} WHERE id = ?", params)
        audit.record("student.update", "student", student["id"], {"before": before, "after": after})
    return list(after)


def anonymize_student(student, reason: str):
    """Retention end-of-life: remove direct identifiers but keep the record
    (and its offers) so historical statistics stay correct."""
    token = "ANON-" + secrets.token_hex(4).upper()
    filler = secrets.token_hex(16)
    with transaction():
        execute(
            "UPDATE students SET full_name = ?, mobile_enc = ?, mobile_index = ?, mobile_masked = ?, email_enc = ?,"
            " email_index = ?, email_masked = ?, remarks = NULL, anonymized = 1, updated_at = ? WHERE id = ?",
            ("Anonymised student", "v1:", "anon:" + filler, "—", "v1:", "anon:" + filler + "e", "—", now_iso(), student["id"]))
        execute("UPDATE users SET active = 0 WHERE student_id = ?", (student["id"],))
        audit.record("student.anonymize", "student", student["id"], {"reason": reason, "token": token})


# ---------------------------------------------------------------- offers / status
def offers_for(student_id: int) -> list:
    rows = query("SELECT o.*, c.name AS company_name FROM offers o JOIN companies c ON c.id = o.company_id"
                 " WHERE o.student_id = ? ORDER BY o.offer_date, o.id", (student_id,))
    return [dict(r) for r in rows]


def placement_status(offers: list) -> str:
    types = {policy.effective_type(o) for o in offers if o["acceptance"] == "accepted"}
    if "IF" in types or {"I", "F"} <= types:
        return "internship_fte"
    if "F" in types:
        return "fte"
    if "I" in types:
        return "internship"
    return "unplaced"


def offer_deadline(response_hours: int, s: dict, issued=None) -> str:
    """24 hours (configurable) or the company's timeline, whichever is earlier,
    counted from the time the offer is issued."""
    issued = issued or utcnow()
    hours = min(int(s["acceptance_window_hours"]), int(response_hours))
    return (issued + timedelta(hours=hours)).strftime(TS_FMT)


def get_or_create_company(name: str) -> int:
    row = query("SELECT id FROM companies WHERE name = ?", (name,), one=True)
    if row:
        return row["id"]
    return execute("INSERT INTO companies (name, created_at) VALUES (?, ?)", (name, now_iso())).lastrowid


def add_flag(student_id: int, kind: str, detail: str, offer_id=None, drive_id=None):
    if query("SELECT 1 FROM flags WHERE student_id = ? AND kind = ? AND status = 'open'"
             " AND IFNULL(offer_id, 0) = IFNULL(?, 0) AND IFNULL(drive_id, 0) = IFNULL(?, 0)",
             (student_id, kind, offer_id, drive_id), one=True):
        return
    fid = execute("INSERT INTO flags (student_id, offer_id, drive_id, kind, detail, created_at) VALUES (?,?,?,?,?,?)",
                  (student_id, offer_id, drive_id, kind, detail, now_iso())).lastrowid
    audit.record("flag.raise", "flag", fid, {"student_id": student_id, "kind": kind, "detail": detail})


def sweep_expired_offers():
    """Pending offers past their acceptance deadline become 'expired'."""
    now = now_iso()
    rows = query("SELECT id, student_id FROM offers WHERE acceptance = 'pending' AND deadline_at < ?", (now,))
    if not rows:
        return 0
    with transaction():
        for r in rows:
            execute("UPDATE offers SET acceptance = 'expired', updated_at = ? WHERE id = ? AND acceptance = 'pending'",
                    (now, r["id"]))
            audit.record("offer.expire", "offer", r["id"], {"before": "pending", "after": "expired"}, actor={})
            add_flag(r["student_id"], "offer_expired", "Offer acceptance deadline passed without a response.", offer_id=r["id"])
    return len(rows)


# ---------------------------------------------------------------- drives / policy
def drive_view(drive) -> dict:
    s = get_settings()
    d = dict(drive)
    if "company_name" not in d:
        d["company_name"] = query("SELECT name FROM companies WHERE id = ?", (drive["company_id"],), one=True)["name"]
    d["eligible_courses"] = [c for c in drive["eligible_courses"].split(",") if c]
    d["category"] = policy.categorize(drive["ctc_lpa"], s) if drive["offer_type"] != "I" else None
    return d


def get_drive(drive_id: int):
    return query("SELECT d.*, c.name AS company_name FROM drives d JOIN companies c ON c.id = d.company_id"
                 " WHERE d.id = ?", (drive_id,), one=True)


def debarment(student, drive, s: dict):
    n = int(s["absence_debar_drives"])
    if n <= 0:
        return None
    absences = query(
        "SELECT a.drive_id, d.drive_date, c.name AS company_name FROM attendance a"
        " JOIN drives d ON d.id = a.drive_id JOIN companies c ON c.id = d.company_id"
        " WHERE a.student_id = ? AND a.status = 'absent' GROUP BY a.drive_id ORDER BY d.drive_date", (student["id"],))
    if not absences:
        return None
    later = query("SELECT id, drive_date, eligible_courses FROM drives ORDER BY drive_date, id")
    for ab in absences:
        following = [d["id"] for d in later
                     if d["drive_date"] > ab["drive_date"] and student["course"] in d["eligible_courses"].split(",")][:n]
        if drive["id"] in following:
            return dict(ab)
    return None


def evaluate(student, drive, s: dict | None = None) -> policy.Decision:
    s = s or get_settings()
    dv = drive_view(drive)
    return policy.evaluate(dict(student), dv, offers_for(student["id"]), debarment(student, dv, s), s)


# ---------------------------------------------------------------- reporting
def dashboard_stats(course: str | None = None) -> dict:
    s = get_settings()
    where, params = "WHERE archived = 0", []
    if course:
        where += " AND course = ?"
        params.append(course)
    students = [dict(r) for r in query(f"SELECT * FROM students {where}", params)]
    all_offers = [dict(r) for r in query(
        "SELECT o.*, c.name AS company_name, s.course, s.batch FROM offers o"
        " JOIN companies c ON c.id = o.company_id JOIN students s ON s.id = o.student_id"
        " WHERE s.archived = 0" + (" AND s.course = ?" if course else ""), params)]
    by_student = {}
    for o in all_offers:
        by_student.setdefault(o["student_id"], []).append(o)

    status_counts = {"unplaced": 0, "internship": 0, "fte": 0, "internship_fte": 0}
    groups = {}
    switch_counts = {}
    for st in students:
        offers = by_student.get(st["id"], [])
        ps = placement_status(offers)
        st["placement_status"] = ps
        if st["registration_status"] == "registered":
            status_counts[ps] += 1
        key = (st["course"], st["batch"])
        grp = groups.setdefault(key, {"course": st["course"], "batch": st["batch"], "registered": 0, "placed": 0,
                                      "offers": 0, "internship": 0, "fte": 0, "internship_fte": 0})
        if st["registration_status"] == "registered":
            grp["registered"] += 1
            if ps != "unplaced":
                grp["placed"] += 1
                grp[ps] += 1
        grp["offers"] += len(offers)
        if offers and st["registration_status"] == "registered":
            w = policy.switching_window(offers, s)
            switch_counts[w["label"]] = switch_counts.get(w["label"], 0) + 1

    registered = [x for x in students if x["registration_status"] == "registered"]
    placed = [x for x in registered if x["placement_status"] != "unplaced"]
    fte_ctc = sorted(o["ctc_lpa"] for o in all_offers if o["offer_type"] in ("F", "IF") and o["ctc_lpa"]
                     and o["acceptance"] != "declined")
    stipends = sorted(o["stipend_amount"] for o in all_offers
                      if o["offer_type"] in ("I", "IF") and o["stipend_amount"] and o["stipend_period"] == "month")

    companies = {}
    for o in all_offers:
        c = companies.setdefault(o["company_name"], {"name": o["company_name"], "offers": 0, "categories": set(),
                                                     "max_ctc": None, "types": set()})
        c["offers"] += 1
        c["types"].add(o["offer_type"])
        if o["category"]:
            c["categories"].add(o["category"])
        if o["ctc_lpa"]:
            c["max_ctc"] = max(c["max_ctc"] or 0, o["ctc_lpa"])
    company_rows = sorted(companies.values(), key=lambda c: (-c["offers"], c["name"]))

    return {
        "total": len(students),
        "registered": len(registered),
        "eligible": sum(1 for x in students if x["eligibility_status"] == "eligible"),
        "ineligible": sum(1 for x in students if x["eligibility_status"] == "ineligible"),
        "pending_verification": sum(1 for x in students if x["eligibility_status"] == "pending"),
        "placed": len(placed),
        "unplaced": len(registered) - len(placed),
        "status_counts": status_counts,
        "total_offers": len(all_offers),
        "unique_students_with_offers": len(by_student),
        "fte": {"count": len(fte_ctc), "highest": max(fte_ctc) if fte_ctc else None,
                "average": round(statistics.mean(fte_ctc), 2) if fte_ctc else None,
                "median": round(statistics.median(fte_ctc), 2) if fte_ctc else None},
        "stipend": {"count": len(stipends), "highest": max(stipends) if stipends else None,
                    "average": round(statistics.mean(stipends)) if stipends else None,
                    "median": round(statistics.median(stipends)) if stipends else None},
        "groups": sorted(groups.values(), key=lambda x: (x["course"], x["batch"])),
        "companies": company_rows,
        "switching": sorted(switch_counts.items(), key=lambda kv: -kv[1]),
        "pending_acceptance": sum(1 for o in all_offers if o["acceptance"] == "pending"),
        "pending_joining": sum(1 for o in all_offers if o["acceptance"] == "accepted" and o["joining"] == "pending"),
        "open_flags": query("SELECT COUNT(*) AS n FROM flags f JOIN students s ON s.id = f.student_id WHERE f.status = 'open'"
                            + (" AND s.course = ?" if course else ""), params, one=True)["n"],
    }


def time_left(deadline_iso: str) -> str:
    delta = parse_ts(deadline_iso) - utcnow()
    secs = int(delta.total_seconds())
    if secs <= 0:
        return "Past deadline"
    h, rem = divmod(secs, 3600)
    return f"{h} h {rem // 60} min left"
