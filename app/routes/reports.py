"""Course-wise and university-level reports; controlled CSV export."""
import csv
import hashlib
import io

from flask import Blueprint, Response, abort, g, render_template, request

from .. import audit, services
from ..constants import COURSES, now_iso
from ..db import query, transaction
from ..security import has_perm, require
from ..validators import ValidationError, reason

bp = Blueprint("reports", __name__, url_prefix="/reports")
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


@bp.route("")
@require("dashboard")
def index():
    courses = [g.user["course_scope"]] if g.user["role"] == "coordinator" else list(COURSES)
    per_course = [(c, services.dashboard_stats(c)) for c in courses]
    overall = services.dashboard_stats(g.user["course_scope"] if g.user["role"] == "coordinator" else None)
    return render_template("reports/index.html", per_course=per_course, overall=overall)


def _cell(value) -> str:
    """Neutralise spreadsheet formula injection (CSV injection)."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


@bp.route("/export", methods=["GET", "POST"])
@require("export")
def export():
    if request.method == "GET":
        return render_template("reports/export.html", errors={}, form={})
    dataset = request.form.get("dataset")
    if dataset not in ("students", "offers"):
        abort(400, description="Unknown dataset.")
    include_contact = request.form.get("include_contact") == "1"
    errors = {}
    if include_contact and not has_perm("export.contact"):
        errors["include_contact"] = "Only the Placement Administrator may export contact details."
    try:
        why = reason(request.form, label="the purpose of this export")
    except ValidationError as exc:
        errors.update(exc.errors)
    if errors:
        return render_template("reports/export.html", errors=errors, form=request.form), 422

    buf = io.StringIO()
    w = csv.writer(buf)
    if dataset == "students":
        header = ["placement_id", "full_name", "course", "batch", "registration_status", "eligibility_status",
                  "placement_status", "offers"]
        if include_contact:
            header += ["mobile", "email"]
        w.writerow(header)
        rows = query("SELECT * FROM students WHERE archived = 0 ORDER BY course, batch, placement_id")
        for st in rows:
            offers = services.offers_for(st["id"])
            line = [st["placement_id"], st["full_name"], st["course"], st["batch"], st["registration_status"],
                    st["eligibility_status"], services.placement_status(offers), len(offers)]
            if include_contact and not st["anonymized"]:
                c = services.contact_of(st)
                line += [c["mobile"], c["email"]]
            elif include_contact:
                line += ["", ""]
            w.writerow([_cell(v) for v in line])
    else:
        w.writerow(["placement_id", "full_name", "course", "company", "offer_type", "category", "fte_ctc_lpa",
                    "stipend_inr", "stipend_period", "offer_date", "acceptance", "joining", "ppo_status",
                    "off_campus", "noc_status"])
        rows = query("SELECT o.*, c.name AS company, s.placement_id, s.full_name, s.course FROM offers o"
                     " JOIN companies c ON c.id = o.company_id JOIN students s ON s.id = o.student_id"
                     " WHERE s.archived = 0 ORDER BY s.course, o.offer_date")
        for o in rows:
            w.writerow([_cell(v) for v in (o["placement_id"], o["full_name"], o["course"], o["company"],
                                           o["offer_type"], o["category"], o["ctc_lpa"], o["stipend_amount"],
                                           o["stipend_period"], o["offer_date"], o["acceptance"], o["joining"],
                                           o["ppo_status"], o["off_campus"], o["noc_status"])])
    body = buf.getvalue()
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    with transaction():
        audit.record("export.csv", "export", dataset, {"rows": len(rows), "include_contact": include_contact,
                                                       "reason": why, "sha256": digest})
    stamp = now_iso().replace(":", "").replace("-", "")
    return Response(body, mimetype="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="placement-{dataset}-{stamp}.csv"',
        "X-Export-SHA256": digest,
    })
