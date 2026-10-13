"""Student database: search, create, update, archive, anonymise, import."""
import csv
import hashlib
import io

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import audit, services
from ..constants import COURSES, ELIGIBILITY, PLACEMENT_STATUS, REGISTRATION
from ..db import execute, query, transaction
from ..policy import switching_window
from ..security import can_access_student, deny, flash, has_perm, require
from ..validators import ValidationError, reason, student_fields

bp = Blueprint("students", __name__, url_prefix="/students")
PAGE_SIZE = 25
ALL_FIELDS = {"placement_id", "enrollment_no", "full_name", "mobile", "email", "course", "batch", "registration_status",
              "eligibility_status", "cgpa", "remarks"}
IMPORT_COLUMNS = ["placement_id", "full_name", "mobile", "email", "course", "batch",
                  "registration_status", "eligibility_status", "cgpa"]


def editable_fields(user) -> set:
    """Field allow-list per role (server-side mass-assignment protection)."""
    if has_perm("student.write", user):
        return ALL_FIELDS - {"placement_id", "enrollment_no"}  # identity keys are immutable once issued
    if has_perm("student.eligibility", user):
        return {"eligibility_status", "cgpa"}
    return set()


def load_student(student_id: int):
    st = services.get_student(student_id)
    if st is None:
        abort(404)
    if not can_access_student(st):
        deny("student_out_of_scope", {"student_id": student_id})
    return st


@bp.route("")
@require("student.read")
def index():
    args = request.args
    where, params = ["1 = 1"], []
    course = args.get("course") or ""
    if g.user["role"] == "coordinator":
        course = g.user["course_scope"]
    if course:
        if course not in COURSES:
            abort(400, description="Unknown programme filter.")
        where.append("course = ?")
        params.append(course)
    for key, vocab in (("registration_status", REGISTRATION), ("eligibility_status", ELIGIBILITY)):
        val = args.get(key) or ""
        if val:
            if val not in vocab:
                abort(400, description="Unknown filter value.")
            where.append(f"{key} = ?")
            params.append(val)
    batch = (args.get("batch") or "").strip()[:9]
    if batch:
        where.append("batch = ?")
        params.append(batch)
    q = (args.get("q") or "").strip()[:60]
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("(full_name LIKE ? ESCAPE '\\' OR placement_id LIKE ? ESCAPE '\\' OR enrollment_no LIKE ? ESCAPE '\\')")
        params += [like, like, like]
    archived = args.get("archived") == "1"
    where.append("archived = ?")
    params.append(1 if archived else 0)

    rows = [dict(r) for r in query(f"SELECT * FROM students WHERE {' AND '.join(where)} ORDER BY course, batch, full_name", params)]
    s = services.get_settings()
    status_filter = args.get("placement") or ""
    if status_filter and status_filter not in PLACEMENT_STATUS:
        abort(400, description="Unknown filter value.")
    out = []
    for r in rows:
        offers = services.offers_for(r["id"])
        r["placement_status"] = services.placement_status(offers)
        r["offer_count"] = len(offers)
        r["window"] = switching_window(offers, s)
        if not status_filter or r["placement_status"] == status_filter:
            out.append(r)
    try:
        page = max(1, int(args.get("page", 1)))
    except ValueError:
        page = 1
    total = len(out)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, pages)
    batches = [r["batch"] for r in query("SELECT DISTINCT batch FROM students ORDER BY batch")]
    return render_template("students/list.html", students=out[(page - 1) * PAGE_SIZE: page * PAGE_SIZE],
                           total=total, page=page, pages=pages, batches=batches, filters=args, course=course,
                           archived=archived)


@bp.route("/new", methods=["GET", "POST"])
@require("student.write")
def create():
    if request.method == "POST":
        try:
            data = student_fields(request.form, creating=True, allowed=ALL_FIELDS)
            sid = services.create_student(data)
        except ValidationError as exc:
            return render_template("students/form.html", st=None, form=request.form, errors=exc.errors,
                                   fields=ALL_FIELDS), 422
        flash(f"Student {data['placement_id']} created.", "success")
        return redirect(url_for("students.detail", student_id=sid))
    return render_template("students/form.html", st=None, form={}, errors={}, fields=ALL_FIELDS)


def _detail_context(st, contact=None) -> dict:
    offers = services.offers_for(st["id"])
    s = services.get_settings()
    drives = query("SELECT d.*, c.name AS company_name FROM drives d JOIN companies c ON c.id = d.company_id"
                   " WHERE d.status = 'open' ORDER BY d.drive_date")
    checks = []
    for d in drives:
        dv = services.drive_view(d)
        if st["course"] in dv["eligible_courses"]:
            checks.append({"drive": dv, "decision": services.evaluate(st, d, s)})
    attendance = query("SELECT a.*, c.name AS company_name, d.drive_date FROM attendance a JOIN drives d ON d.id = a.drive_id"
                       " JOIN companies c ON c.id = d.company_id WHERE a.student_id = ? ORDER BY d.drive_date DESC", (st["id"],))
    applications = query("SELECT a.*, d.title, d.offer_type, c.name AS company_name FROM applications a"
                         " JOIN drives d ON d.id = a.drive_id JOIN companies c ON c.id = d.company_id"
                         " WHERE a.student_id = ? ORDER BY a.created_at DESC", (st["id"],))
    flags = query("SELECT * FROM flags WHERE student_id = ? ORDER BY created_at DESC", (st["id"],))
    history = query("SELECT * FROM audit_log WHERE entity = 'student' AND entity_id = ? ORDER BY id DESC LIMIT 15",
                    (str(st["id"]),)) if has_perm("audit.read") else []
    return dict(st=st, offers=offers, checks=checks, attendance=attendance, applications=applications, flags=flags,
                history=history, contact=contact, status=services.placement_status(offers),
                window=switching_window(offers, s), time_left=services.time_left,
                can_edit=bool(editable_fields(g.user)) and not st["anonymized"])


@bp.route("/<int:student_id>")
@require("student.read")
def detail(student_id):
    return render_template("students/detail.html", **_detail_context(load_student(student_id)))


@bp.route("/<int:student_id>/contact", methods=["POST"])
@require("student.contact")
def reveal_contact(student_id):
    """Contact details are masked by default; revealing them is a recorded,
    deliberate action (sensitive-access logging)."""
    st = load_student(student_id)
    if st["anonymized"]:
        abort(404)
    with transaction():
        audit.record("student.contact_view", "student", st["id"], {"placement_id": st["placement_id"]})
    return render_template("students/detail.html", **_detail_context(st, services.contact_of(st)))


@bp.route("/<int:student_id>/edit", methods=["GET", "POST"])
@require("student.read")
def edit(student_id):
    st = load_student(student_id)
    fields = editable_fields(g.user)
    if not fields or st["anonymized"]:
        deny("student_edit_forbidden", {"student_id": student_id})
    if request.method == "POST":
        try:
            data = student_fields(request.form, creating=False, allowed=fields)
            changed = services.update_student(st, data)
        except ValidationError as exc:
            return render_template("students/form.html", st=st, form=request.form, errors=exc.errors, fields=fields), 422
        flash("Changes saved." if changed else "No changes to save.", "success" if changed else "info")
        return redirect(url_for("students.detail", student_id=st["id"]))
    form = dict(st)
    if {"mobile", "email"} & fields:
        form.update(services.contact_of(st))
    return render_template("students/form.html", st=st, form=form, errors={}, fields=fields)


@bp.route("/<int:student_id>/archive", methods=["POST"])
@require("student.archive")
def archive(student_id):
    st = load_student(student_id)
    target = 0 if st["archived"] else 1
    try:
        why = reason(request.form)
    except ValidationError as exc:
        flash(exc.errors["reason"], "error")
        return redirect(url_for("students.detail", student_id=st["id"]))
    with transaction():
        execute("UPDATE students SET archived = ? WHERE id = ?", (target, st["id"]))
        audit.record("student.archive" if target else "student.unarchive", "student", st["id"], {"reason": why})
    flash("Record archived." if target else "Record restored.", "success")
    return redirect(url_for("students.detail", student_id=st["id"]))


@bp.route("/<int:student_id>/anonymize", methods=["POST"])
@require("student.anonymize")
def anonymize(student_id):
    st = load_student(student_id)
    if not st["archived"] or st["anonymized"]:
        flash("Only archived, not-yet-anonymised records can be anonymised.", "error")
        return redirect(url_for("students.detail", student_id=st["id"]))
    try:
        why = reason(request.form)
    except ValidationError as exc:
        flash(exc.errors["reason"], "error")
        return redirect(url_for("students.detail", student_id=st["id"]))
    services.anonymize_student(st, why)
    flash("Personal identifiers removed. Placement statistics are preserved.", "success")
    return redirect(url_for("students.detail", student_id=st["id"]))


@bp.route("/import", methods=["GET", "POST"])
@require("student.import")
def import_csv():
    if request.method == "GET":
        return render_template("students/import.html", errors=None, columns=IMPORT_COLUMNS)
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return render_template("students/import.html", errors=[(0, "file", "Choose a CSV file.")], columns=IMPORT_COLUMNS), 422
    if not upload.filename.lower().endswith(".csv"):
        return render_template("students/import.html", errors=[(0, "file", "Only .csv files are accepted.")], columns=IMPORT_COLUMNS), 422
    raw = upload.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return render_template("students/import.html", errors=[(0, "file", "File must be UTF-8 encoded.")], columns=IMPORT_COLUMNS), 422
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None or [c.strip() for c in reader.fieldnames] != IMPORT_COLUMNS:
        return render_template("students/import.html", columns=IMPORT_COLUMNS,
                               errors=[(1, "header", "Header must be exactly: " + ",".join(IMPORT_COLUMNS))]), 422
    errors, rows, seen = [], [], {"placement_id": set(), "mobile": set(), "email": set()}
    for n, row in enumerate(reader, start=2):
        if n > 2001:
            errors.append((n, "file", "Imports are limited to 2,000 rows."))
            break
        try:
            data = student_fields(row, creating=True, allowed=ALL_FIELDS)
        except ValidationError as exc:
            errors += [(n, k, v) for k, v in exc.errors.items()]
            continue
        for key in seen:
            if data[key] in seen[key]:
                errors.append((n, key, "Duplicate of an earlier row in this file."))
            seen[key].add(data[key])
        errors += [(n, k, v) for k, v in services.duplicate_errors(data).items()]
        rows.append(data)
    if errors:
        return render_template("students/import.html", errors=errors, columns=IMPORT_COLUMNS), 422
    if not rows:
        return render_template("students/import.html", errors=[(0, "file", "The file has no data rows.")], columns=IMPORT_COLUMNS), 422
    with transaction():  # all-or-nothing
        for data in rows:
            services.insert_student(data)
        audit.record("student.import", "student", None, {"rows": len(rows), "file_sha256": hashlib.sha256(raw).hexdigest()})
    flash(f"Imported {len(rows)} student records.", "success")
    return redirect(url_for("students.index"))
