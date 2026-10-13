"""Offer management (I, F, I+F), including off-campus offers, PPOs, NOCs,
acceptance deadlines and joining."""
from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import audit, services
from ..constants import COURSES, now_iso, parse_ts, utcnow
from ..db import execute, query, transaction
from ..policy import categorize
from ..security import flash, require
from ..validators import ValidationError, company_name, offer_fields, offer_status_fields

bp = Blueprint("offers", __name__, url_prefix="/offers")

ACCEPTANCE_TRANSITIONS = {
    "pending": {"pending", "accepted", "declined"},
    "accepted": {"accepted", "declined"},  # reneging is possible but flagged
    "declined": {"declined"},
    "expired": {"expired"},
}


@bp.route("")
@require("offer.read")
def index():
    services.sweep_expired_offers()
    where, params = ["s.archived = 0"], []
    course = g.user["course_scope"] if g.user["role"] == "coordinator" else (request.args.get("course") or "")
    if course:
        if course not in COURSES:
            abort(400, description="Unknown programme filter.")
        where.append("s.course = ?")
        params.append(course)
    acc = request.args.get("acceptance") or ""
    if acc:
        if acc not in ACCEPTANCE_TRANSITIONS:
            abort(400, description="Unknown filter value.")
        where.append("o.acceptance = ?")
        params.append(acc)
    otype = request.args.get("type") or ""
    if otype:
        if otype not in ("I", "F", "IF"):
            abort(400, description="Unknown filter value.")
        where.append("o.offer_type = ?")
        params.append(otype)
    rows = query("SELECT o.*, c.name AS company_name, s.full_name, s.placement_id, s.course FROM offers o"
                 " JOIN companies c ON c.id = o.company_id JOIN students s ON s.id = o.student_id"
                 f" WHERE {' AND '.join(where)} ORDER BY o.offer_date DESC, o.id DESC", params)
    return render_template("offers/list.html", offers=rows, filters=request.args, course=course,
                           time_left=services.time_left)


@bp.route("/new", methods=["GET", "POST"])
@require("offer.write")
def create():
    drives = query("SELECT d.*, c.name AS company_name FROM drives d JOIN companies c ON c.id = d.company_id ORDER BY d.drive_date DESC")
    form = request.form if request.method == "POST" else {"response_hours": 24, "offer_date": now_iso()[:10],
                                                           "placement_id": request.args.get("pid", ""),
                                                           "drive_id": request.args.get("drive", "")}
    if request.method == "GET":
        return render_template("offers/form.html", form=form, errors={}, drives=drives)

    errors = {}
    pid = (request.form.get("placement_id") or "").strip().upper()[:24]
    st = query("SELECT * FROM students WHERE placement_id = ?", (pid,), one=True)
    if st is None:
        errors["placement_id"] = "No student with that Placement ID."
    elif st["archived"]:
        errors["placement_id"] = "This student record is archived."
    drive = None
    drive_id = request.form.get("drive_id") or ""
    if drive_id:
        if not drive_id.isdigit() or not (drive := services.get_drive(int(drive_id))):
            errors["drive_id"] = "Select a valid drive."
    submitted = request.form.copy()
    if drive:  # commercial terms of campus offers come from the drive record
        submitted["offer_type"] = drive["offer_type"]
        submitted["ctc_lpa"] = "" if drive["ctc_lpa"] is None else str(drive["ctc_lpa"])
    try:
        d = offer_fields(submitted)
    except ValidationError as exc:
        errors.update(exc.errors)
        d = None
    cname = None
    if not drive:
        cname = company_name(request.form.get("company_name"), errors)
    if errors:
        return render_template("offers/form.html", form=request.form, errors=errors, drives=drives), 422

    s = services.get_settings()
    if drive:
        # Commercial terms come from the drive record, not from the form.
        d["offer_type"], d["ctc_lpa"] = drive["offer_type"], drive["ctc_lpa"]
        d["stipend_amount"] = drive["stipend_amount"] if drive["stipend_amount"] is not None else d["stipend_amount"]
        d["stipend_period"] = drive["stipend_period"] or d["stipend_period"]
        d["response_hours"] = min(d["response_hours"], drive["response_hours"])
        target = drive
    else:
        target = {"id": -1, "company_id": -1, "company_name": cname, "offer_type": d["offer_type"],
                  "ctc_lpa": d["ctc_lpa"], "eligible_courses": st["course"], "min_cgpa": None,
                  "drive_date": d["offer_date"]}
    category = categorize(d["ctc_lpa"], s) if d["offer_type"] != "I" else None
    off_campus = drive is None

    with transaction():
        company_id = drive["company_id"] if drive else services.get_or_create_company(cname)
        if not drive:
            target["company_id"] = company_id
        decision = services.evaluate(st, target, s)
        deadline = services.offer_deadline(d["response_hours"], s)
        now = now_iso()
        oid = execute(
            "INSERT INTO offers (student_id, drive_id, company_id, offer_type, category, ctc_lpa, stipend_amount, stipend_period,"
            " offer_date, deadline_at, ppo_status, off_campus, noc_status, policy_outcome, remarks, created_by, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (st["id"], drive["id"] if drive else None, company_id, d["offer_type"], category, d["ctc_lpa"], d["stipend_amount"],
             d["stipend_period"], d["offer_date"], deadline, "pending" if d["offer_type"] == "I" else "na",
             int(off_campus), "requested" if off_campus else "na", decision.outcome, d["remarks"], g.user["id"], now, now)).lastrowid
        audit.record("offer.create", "offer", oid, {"student_id": st["id"], "company_id": company_id, "type": d["offer_type"],
                                                   "category": category, "ctc_lpa": d["ctc_lpa"], "stipend": d["stipend_amount"],
                                                   "off_campus": off_campus, "policy": decision.outcome})
        if decision.outcome == "block":
            services.add_flag(st["id"], "policy_violation", "Offer recorded although policy blocks it: " + decision.headline, offer_id=oid)
        elif decision.outcome == "review":
            services.add_flag(st["id"], "policy_conflict", "Offer needs Placement Cell review: " + decision.headline, offer_id=oid)
        if drive:
            execute("UPDATE applications SET status = 'selected', updated_at = ? WHERE drive_id = ? AND student_id = ?",
                    (now, drive["id"], st["id"]))
    if decision.outcome == "allow":
        flash("Offer recorded. Acceptance deadline set to the earlier of 24 hours or the company timeline.", "success")
    else:
        flash("Offer recorded and flagged for review: " + decision.headline, "warning")
    return redirect(url_for("offers.detail", offer_id=oid))


def load_offer(offer_id):
    row = query("SELECT o.*, c.name AS company_name, s.full_name, s.placement_id, s.course FROM offers o"
                " JOIN companies c ON c.id = o.company_id JOIN students s ON s.id = o.student_id WHERE o.id = ?",
                (offer_id,), one=True)
    if row is None:
        abort(404)
    if g.user["role"] == "coordinator" and row["course"] != g.user["course_scope"]:
        abort(404)
    return dict(row)


@bp.route("/<int:offer_id>")
@require("offer.read")
def detail(offer_id):
    services.sweep_expired_offers()
    offer = load_offer(offer_id)
    history = query("SELECT * FROM audit_log WHERE entity = 'offer' AND entity_id = ? ORDER BY id DESC", (str(offer_id),))
    return render_template("offers/detail.html", offer=offer, history=history, errors={}, time_left=services.time_left)


@bp.route("/<int:offer_id>/status", methods=["POST"])
@require("offer.write")
def update_status(offer_id):
    services.sweep_expired_offers()
    offer = load_offer(offer_id)
    try:
        d = offer_status_fields(request.form)
    except ValidationError as exc:
        history = query("SELECT * FROM audit_log WHERE entity = 'offer' AND entity_id = ? ORDER BY id DESC", (str(offer_id),))
        return render_template("offers/detail.html", offer=offer, history=history, errors=exc.errors,
                               time_left=services.time_left), 422
    errors = {}
    if d["acceptance"] not in ACCEPTANCE_TRANSITIONS[offer["acceptance"]]:
        errors["acceptance"] = f"An offer cannot move from {offer['acceptance']} to {d['acceptance']}."
    if d["acceptance"] == "accepted" and offer["acceptance"] == "pending" and parse_ts(offer["deadline_at"]) < utcnow():
        errors["acceptance"] = "The acceptance deadline has passed."
    if d["joining"] != "pending" and d["acceptance"] != "accepted":
        errors["joining"] = "Joining can only be recorded for an accepted offer."
    if offer["offer_type"] != "I" and d["ppo_status"] != "na":
        errors["ppo_status"] = "PPO status applies only to internship offers."
    if not offer["off_campus"] and d["noc_status"] != "na":
        errors["noc_status"] = "NOC status applies only to off-campus offers."
    if errors:
        history = query("SELECT * FROM audit_log WHERE entity = 'offer' AND entity_id = ? ORDER BY id DESC", (str(offer_id),))
        return render_template("offers/detail.html", offer=offer, history=history, errors=errors,
                               time_left=services.time_left), 422
    fields = ("acceptance", "joining", "ppo_status", "noc_status")
    before = {f: offer[f] for f in fields if offer[f] != d[f]}
    after = {f: d[f] for f in before}
    if not before:
        flash("No changes to save.", "info")
        return redirect(url_for("offers.detail", offer_id=offer_id))
    with transaction():
        # Optimistic concurrency: only update if nobody changed it meanwhile.
        cur = execute("UPDATE offers SET acceptance = ?, joining = ?, ppo_status = ?, noc_status = ?, updated_at = ?"
                      " WHERE id = ? AND acceptance = ? AND joining = ? AND ppo_status = ? AND noc_status = ?",
                      (d["acceptance"], d["joining"], d["ppo_status"], d["noc_status"], now_iso(), offer_id,
                       offer["acceptance"], offer["joining"], offer["ppo_status"], offer["noc_status"]))
        if cur.rowcount != 1:
            abort(409)
        audit.record("offer.update", "offer", offer_id, {"before": before, "after": after, "note": d["note"]})
        if offer["acceptance"] == "accepted" and d["acceptance"] == "declined":
            services.add_flag(offer["student_id"], "policy_violation",
                              f"Accepted offer from {offer['company_name']} was later declined (reneged).", offer_id=offer_id)
    flash("Offer updated.", "success")
    return redirect(url_for("offers.detail", offer_id=offer_id))
