"""Recruitment drives, applications and attendance."""
import json

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import audit, services
from ..constants import APPLICATION, now_iso
from ..db import execute, query, transaction
from ..policy import categorize
from ..security import flash, has_perm, require
from ..validators import ValidationError, drive_fields, event_choice

bp = Blueprint("drives", __name__, url_prefix="/drives")


def _scoped_drives_sql():
    if g.user["role"] == "coordinator":
        return " WHERE (',' || d.eligible_courses || ',') LIKE ?", ("%," + g.user["course_scope"] + ",%",)
    return "", ()


@bp.route("")
@require("drive.read")
def index():
    where, params = _scoped_drives_sql()
    rows = query("SELECT d.*, c.name AS company_name,"
                 " (SELECT COUNT(*) FROM applications a WHERE a.drive_id = d.id) AS applicants,"
                 " (SELECT COUNT(*) FROM offers o WHERE o.drive_id = d.id) AS offers"
                 " FROM drives d JOIN companies c ON c.id = d.company_id" + where + " ORDER BY d.drive_date DESC", params)
    return render_template("drives/list.html", drives=[services.drive_view(r) | {"applicants": r["applicants"],
                                                                                 "offers": r["offers"]} for r in rows])


@bp.route("/new", methods=["GET", "POST"])
@require("drive.write")
def create():
    if request.method == "POST":
        try:
            d = drive_fields(request.form)
        except ValidationError as exc:
            return render_template("drives/form.html", form=request.form, errors=exc.errors,
                                   selected=request.form.getlist("eligible_courses")), 422
        s = services.get_settings()
        with transaction():
            company_id = services.get_or_create_company(d["company_name"])
            category = categorize(d["ctc_lpa"], s) if d["offer_type"] != "I" else None
            did = execute(
                "INSERT INTO drives (company_id, title, offer_type, ctc_lpa, stipend_amount, stipend_period, category,"
                " eligible_courses, min_cgpa, drive_date, response_hours, created_by, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (company_id, d["title"], d["offer_type"], d["ctc_lpa"], d["stipend_amount"], d["stipend_period"],
                 category, d["eligible_courses"], d["min_cgpa"], d["drive_date"], d["response_hours"], g.user["id"],
                 now_iso())).lastrowid
            audit.record("drive.create", "drive", did, {k: d[k] for k in ("company_name", "title", "offer_type", "ctc_lpa",
                                                                           "eligible_courses", "drive_date")} | {"category": category})
        flash("Drive created. Category is derived from the CTC by the policy engine.", "success")
        return redirect(url_for("drives.detail", drive_id=did))
    return render_template("drives/form.html", form={"response_hours": 24}, errors={}, selected=[])


def load_drive(drive_id):
    drive = services.get_drive(drive_id)
    if drive is None:
        abort(404)
    if g.user["role"] == "coordinator" and g.user["course_scope"] not in drive["eligible_courses"].split(","):
        abort(404)
    return drive


@bp.route("/<int:drive_id>")
@require("drive.read")
def detail(drive_id):
    drive = load_drive(drive_id)
    s = services.get_settings()
    scope = " AND s.course = ?" if g.user["role"] == "coordinator" else ""
    params = (drive_id, g.user["course_scope"]) if scope else (drive_id,)
    apps = query("SELECT a.*, s.full_name, s.placement_id, s.course, s.batch FROM applications a"
                 " JOIN students s ON s.id = a.student_id WHERE a.drive_id = ?" + scope + " ORDER BY s.full_name", params)
    rows = []
    for a in apps:
        st = services.get_student(a["student_id"])
        rows.append({"app": a, "decision": services.evaluate(st, drive, s), "snapshot": json.loads(a["decision"])})
    att = {}
    for r in query("SELECT * FROM attendance WHERE drive_id = ?", (drive_id,)):
        att.setdefault(r["student_id"], {})[r["event"]] = r
    return render_template("drives/detail.html", drive=services.drive_view(drive), rows=rows, att=att,
                           statuses=APPLICATION)


@bp.route("/<int:drive_id>/status", methods=["POST"])
@require("drive.write")
def toggle(drive_id):
    drive = load_drive(drive_id)
    new = "closed" if drive["status"] == "open" else "open"
    with transaction():
        execute("UPDATE drives SET status = ? WHERE id = ?", (new, drive_id))
        audit.record("drive.status", "drive", drive_id, {"before": drive["status"], "after": new})
    flash(f"Drive {new}.", "success")
    return redirect(url_for("drives.detail", drive_id=drive_id))


@bp.route("/<int:drive_id>/register", methods=["POST"])
@require("application.write")
def register(drive_id):
    """Officer registers a student for a drive. The policy engine decides:
    'block' is refused; 'review' needs a recorded Placement Cell approval."""
    drive = load_drive(drive_id)
    pid = (request.form.get("placement_id") or "").strip().upper()[:24]
    st = query("SELECT * FROM students WHERE placement_id = ?", (pid,), one=True)
    if st is None:
        flash("No student with that Placement ID.", "error")
        return redirect(url_for("drives.detail", drive_id=drive_id))
    if query("SELECT 1 FROM applications WHERE drive_id = ? AND student_id = ?", (drive_id, st["id"]), one=True):
        flash("Student is already registered for this drive.", "info")
        return redirect(url_for("drives.detail", drive_id=drive_id))
    decision = services.evaluate(st, drive)
    override = (request.form.get("override_reason") or "").strip()[:300]
    if decision.outcome == "block":
        with transaction():
            audit.record("application.refused", "drive", drive_id, {"student_id": st["id"], "reason": decision.headline})
        flash(f"Blocked by policy: {decision.headline}", "error")
        return redirect(url_for("drives.detail", drive_id=drive_id))
    if decision.outcome == "review" and len(override) < 10:
        flash(f"Manual review required: {decision.headline} Record the Placement Cell approval (at least 10 characters) to proceed.", "warning")
        return redirect(url_for("drives.detail", drive_id=drive_id, review=pid))
    now = now_iso()
    snapshot = decision.to_dict() | ({"override": override, "approved_by": g.user["username"]} if decision.outcome == "review" else {})
    with transaction():
        aid = execute("INSERT INTO applications (drive_id, student_id, status, decision, created_at, updated_at)"
                      " VALUES (?,?,?,?,?,?)", (drive_id, st["id"], "applied", json.dumps(snapshot), now, now)).lastrowid
        audit.record("application.create", "application", aid,
                     {"drive_id": drive_id, "student_id": st["id"], "outcome": decision.outcome, "override": override or None})
    flash(f"{st['full_name']} registered for the drive.", "success")
    return redirect(url_for("drives.detail", drive_id=drive_id))


@bp.route("/applications/<int:app_id>", methods=["POST"])
@require("application.write")
def application_status(app_id):
    row = query("SELECT * FROM applications WHERE id = ?", (app_id,), one=True)
    if row is None:
        abort(404)
    status = request.form.get("status")
    if status not in APPLICATION:
        abort(400, description="Unsupported status.")
    with transaction():
        execute("UPDATE applications SET status = ?, updated_at = ? WHERE id = ?", (status, now_iso(), app_id))
        audit.record("application.status", "application", app_id, {"before": row["status"], "after": status})
    flash("Application status updated.", "success")
    return redirect(url_for("drives.detail", drive_id=row["drive_id"]))


@bp.route("/<int:drive_id>/attendance", methods=["POST"])
@require("attendance.write")
def attendance(drive_id):
    drive = load_drive(drive_id)
    errors = {}
    event = event_choice(request.form, errors)
    if errors:
        flash("Select the recruitment event.", "error")
        return redirect(url_for("drives.detail", drive_id=drive_id))
    s = services.get_settings()
    applicant_ids = sorted(r["student_id"] for r in query("SELECT student_id FROM applications WHERE drive_id = ?", (drive_id,)))
    entries = []  # validate everything first so a bad row cannot leave a partial write
    for sid in applicant_ids:
        status = request.form.get(f"status_{sid}")
        if not status:
            continue
        if status not in ("present", "absent", "excused"):
            abort(400, description="Unsupported attendance value.")
        note = (request.form.get(f"reason_{sid}") or "").strip()[:300] or None
        if status == "excused":
            if not has_perm("attendance.except"):
                abort(403)
            if not note or len(note) < 10:
                flash("An emergency exception needs a documented reason (at least 10 characters). Nothing was saved.", "error")
                return redirect(url_for("drives.detail", drive_id=drive_id))
        entries.append((sid, status, note))
    with transaction():
        for sid, status, note in entries:
            prev = query("SELECT status FROM attendance WHERE drive_id = ? AND student_id = ? AND event = ?",
                         (drive_id, sid, event), one=True)
            execute("INSERT INTO attendance (drive_id, student_id, event, status, exception_reason, recorded_by, recorded_at)"
                    " VALUES (?,?,?,?,?,?,?) ON CONFLICT(drive_id, student_id, event) DO UPDATE SET"
                    " status = excluded.status, exception_reason = excluded.exception_reason,"
                    " recorded_by = excluded.recorded_by, recorded_at = excluded.recorded_at",
                    (drive_id, sid, event, status, note, g.user["id"], now_iso()))
            audit.record("attendance.record", "student", sid, {"drive_id": drive_id, "event": event,
                                                              "before": prev["status"] if prev else None, "after": status,
                                                              "reason": note})
            if status == "absent":
                services.add_flag(sid, "absenteeism",
                                  f"Absent from {event} at {drive['company_name']} ({drive['drive_date']}); "
                                  f"barred from the next {s['absence_debar_drives']} drives unless an exception is approved.",
                                  drive_id=drive_id)
    if entries:
        flash(f"Attendance recorded for {len(entries)} student(s).", "success")
    return redirect(url_for("drives.detail", drive_id=drive_id))
