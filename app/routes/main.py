"""Dashboard, student self-service portal and recruiter portal."""
import json

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import audit, services
from ..constants import COURSES, now_iso
from ..db import execute, query, transaction
from ..security import deny, flash, has_perm, login_required, require

bp = Blueprint("main", __name__)


@bp.route("/")
@login_required
def index():
    role = g.user["role"]
    if role == "student":
        return redirect(url_for("main.me"))
    if role == "recruiter":
        return redirect(url_for("main.recruiter"))
    return redirect(url_for("main.dashboard"))


@bp.route("/dashboard")
@require("dashboard")
def dashboard():
    services.sweep_expired_offers()
    course = g.user["course_scope"] if g.user["role"] == "coordinator" else request.args.get("course") or None
    if course and course not in COURSES:
        abort(404)
    stats = services.dashboard_stats(course)
    pending = query(
        "SELECT o.id, o.deadline_at, o.offer_type, s.full_name, s.placement_id, s.id AS student_id, c.name AS company"
        " FROM offers o JOIN students s ON s.id = o.student_id JOIN companies c ON c.id = o.company_id"
        " WHERE o.acceptance = 'pending' AND s.archived = 0" + (" AND s.course = ?" if course else "")
        + " ORDER BY o.deadline_at LIMIT 8", (course,) if course else ())
    return render_template("dashboard.html", stats=stats, course=course, pending=pending,
                           time_left=services.time_left)


# ------------------------------------------------------------ student portal
def _own_student():
    """The student record bound to the signed-in account. The identifier is
    taken from the server-side session, never from the request."""
    sid = g.user["student_id"]
    st = services.get_student(sid) if sid else None
    if st is None:
        abort(404)
    return st


@bp.route("/me")
@require("self.portal")
def me():
    services.sweep_expired_offers()
    st = _own_student()
    offers = services.offers_for(st["id"])
    s = services.get_settings()
    open_drives = query("SELECT d.*, c.name AS company_name FROM drives d JOIN companies c ON c.id = d.company_id"
                        " WHERE d.status = 'open' ORDER BY d.drive_date")
    applied = {r["drive_id"]: r for r in query("SELECT * FROM applications WHERE student_id = ?", (st["id"],))}
    drives = []
    for d in open_drives:
        dv = services.drive_view(d)
        if st["course"] not in dv["eligible_courses"]:
            continue
        drives.append({"drive": dv, "decision": services.evaluate(st, d, s), "application": applied.get(d["id"])})
    from ..policy import switching_window
    return render_template("me.html", st=st, contact=services.contact_of(st), offers=offers, drives=drives,
                           status=services.placement_status(offers), window=switching_window(offers, s),
                           time_left=services.time_left)


@bp.route("/me/apply/<int:drive_id>", methods=["POST"])
@require("self.portal")
def apply(drive_id):
    st = _own_student()
    drive = services.get_drive(drive_id)
    if drive is None or drive["status"] != "open":
        abort(404)
    if query("SELECT 1 FROM applications WHERE drive_id = ? AND student_id = ?", (drive_id, st["id"]), one=True):
        flash("You have already applied to this drive.", "info")
        return redirect(url_for("main.me"))
    decision = services.evaluate(st, drive)  # re-evaluated server-side; the UI button is not trusted
    if decision.outcome != "allow":
        with transaction():
            audit.record("application.refused", "drive", drive_id, {"student_id": st["id"], "outcome": decision.outcome,
                                                                   "reason": decision.headline})
        flash("Application not submitted: " + decision.headline, "error")
        return redirect(url_for("main.me"))
    now = now_iso()
    with transaction():
        aid = execute("INSERT INTO applications (drive_id, student_id, status, decision, created_at, updated_at)"
                      " VALUES (?,?,?,?,?,?)", (drive_id, st["id"], "applied", json.dumps(decision.to_dict()), now, now)).lastrowid
        audit.record("application.create", "application", aid, {"drive_id": drive_id, "student_id": st["id"], "by": "self"})
    flash(f"Application submitted to {drive['company_name']}.", "success")
    return redirect(url_for("main.me"))


# ------------------------------------------------------------ recruiter portal
@bp.route("/recruiter")
@require("recruiter.portal")
def recruiter():
    company_id = g.user["company_id"]
    drives = query("SELECT d.*, c.name AS company_name, (SELECT COUNT(*) FROM applications a WHERE a.drive_id = d.id) AS applicants"
                   " FROM drives d JOIN companies c ON c.id = d.company_id WHERE d.company_id = ? ORDER BY d.drive_date DESC",
                   (company_id,))
    return render_template("recruiter.html", drives=[dict(d) | {"eligible_courses": d["eligible_courses"].split(",")} for d in drives])


@bp.route("/recruiter/drives/<int:drive_id>")
@require("recruiter.portal")
def recruiter_drive(drive_id):
    drive = services.get_drive(drive_id)
    if drive is None:
        abort(404)
    if drive["company_id"] != g.user["company_id"]:
        deny("recruiter_foreign_drive", {"drive_id": drive_id})
    # Data minimisation: recruiters see name, programme, batch and a masked
    # email only — never mobile numbers, packages from other companies or
    # placement history.
    applicants = query(
        "SELECT a.id, a.status, s.placement_id, s.full_name, s.course, s.batch, s.email_masked"
        " FROM applications a JOIN students s ON s.id = a.student_id WHERE a.drive_id = ? ORDER BY s.full_name", (drive_id,))
    return render_template("recruiter_drive.html", drive=services.drive_view(drive), applicants=applicants)


@bp.route("/recruiter/applications/<int:app_id>", methods=["POST"])
@require("recruiter.portal")
def recruiter_update(app_id):
    row = query("SELECT a.*, d.company_id FROM applications a JOIN drives d ON d.id = a.drive_id WHERE a.id = ?",
                (app_id,), one=True)
    if row is None:
        abort(404)
    if row["company_id"] != g.user["company_id"]:
        deny("recruiter_foreign_application", {"application_id": app_id})
    status = request.form.get("status")
    if status not in ("shortlisted", "selected", "rejected"):
        abort(400, description="Unsupported status.")
    with transaction():
        execute("UPDATE applications SET status = ?, updated_at = ? WHERE id = ?", (status, now_iso(), app_id))
        audit.record("application.status", "application", app_id, {"before": row["status"], "after": status})
    flash("Candidate status updated. Offers are recorded by the Placement Cell.", "success")
    return redirect(url_for("main.recruiter_drive", drive_id=row["drive_id"]))


@bp.route("/guide")
@login_required
def guide():
    return render_template("guide.html", s=services.get_settings())
