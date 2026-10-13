"""User administration, audit trail and backups."""
import secrets

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .. import audit, backup
from ..constants import COURSES, ROLES, now_iso
from ..db import execute, query, transaction
from ..security import flash, hash_password, require, revoke_user_sessions
from ..validators import USERNAME_RE

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _temp_password() -> str:
    return secrets.token_urlsafe(12)


@bp.route("/users")
@require("user.manage")
def users():
    rows = query("SELECT u.*, c.name AS company_name, s.placement_id FROM users u LEFT JOIN companies c ON c.id = u.company_id"
                 " LEFT JOIN students s ON s.id = u.student_id ORDER BY u.role, u.username")
    companies = query("SELECT id, name FROM companies ORDER BY name")
    return render_template("admin/users.html", users=rows, companies=companies, errors={}, form={}, issued=None)


@bp.route("/users", methods=["POST"])
@require("user.manage")
def create_user():
    f = request.form
    errors = {}
    username = (f.get("username") or "").strip().lower()
    if not USERNAME_RE.match(username):
        errors["username"] = "3–32 characters: lowercase letters, digits, dot, hyphen or underscore."
    elif query("SELECT 1 FROM users WHERE username = ?", (username,), one=True):
        errors["username"] = "That username is taken."
    display = (f.get("display_name") or "").strip()[:80]
    if len(display) < 2:
        errors["display_name"] = "Enter a display name."
    role = f.get("role")
    if role not in ROLES:
        errors["role"] = "Select a role."
    course_scope = company_id = student_id = None
    if role == "coordinator":
        course_scope = f.get("course_scope")
        if course_scope not in COURSES:
            errors["course_scope"] = "Coordinators must be scoped to one programme."
    if role == "recruiter":
        cid = f.get("company_id") or ""
        if not cid.isdigit() or not query("SELECT 1 FROM companies WHERE id = ?", (int(cid),), one=True):
            errors["company_id"] = "Recruiters must be linked to a company."
        else:
            company_id = int(cid)
    if role == "student":
        pid = (f.get("placement_id") or "").strip().upper()
        st = query("SELECT id FROM students WHERE placement_id = ?", (pid,), one=True)
        if st is None:
            errors["placement_id"] = "Student accounts must be linked to an existing Placement ID."
        elif query("SELECT 1 FROM users WHERE student_id = ?", (st["id"],), one=True):
            errors["placement_id"] = "That student already has an account."
        else:
            student_id = st["id"]
    if errors:
        rows = query("SELECT u.*, c.name AS company_name, s.placement_id FROM users u LEFT JOIN companies c ON c.id = u.company_id"
                     " LEFT JOIN students s ON s.id = u.student_id ORDER BY u.role, u.username")
        return render_template("admin/users.html", users=rows, companies=query("SELECT id, name FROM companies ORDER BY name"),
                               errors=errors, form=f, issued=None), 422
    temp = _temp_password()
    with transaction():
        uid = execute("INSERT INTO users (username, display_name, password_hash, role, course_scope, company_id, student_id,"
                      " must_change_password, created_at) VALUES (?,?,?,?,?,?,?,1,?)",
                      (username, display, hash_password(temp), role, course_scope, company_id, student_id, now_iso())).lastrowid
        audit.record("user.create", "user", uid, {"username": username, "role": role, "course_scope": course_scope,
                                                 "company_id": company_id, "student_id": student_id})
    rows = query("SELECT u.*, c.name AS company_name, s.placement_id FROM users u LEFT JOIN companies c ON c.id = u.company_id"
                 " LEFT JOIN students s ON s.id = u.student_id ORDER BY u.role, u.username")
    # The temporary password is shown exactly once and never stored in plaintext.
    return render_template("admin/users.html", users=rows, companies=query("SELECT id, name FROM companies ORDER BY name"),
                           errors={}, form={}, issued={"username": username, "password": temp})


@bp.route("/users/<int:user_id>/<action>", methods=["POST"])
@require("user.manage")
def user_action(user_id, action):
    user = query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if user is None:
        abort(404)
    if action not in ("reset", "toggle", "unlock"):
        abort(404)
    if user_id == g.user["id"] and action == "toggle":
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("admin.users"))
    issued = None
    with transaction():
        if action == "reset":
            temp = _temp_password()
            execute("UPDATE users SET password_hash = ?, must_change_password = 1, failed_attempts = 0, locked_until = NULL"
                    " WHERE id = ?", (hash_password(temp), user_id))
            revoke_user_sessions(user_id)
            issued = {"username": user["username"], "password": temp}
        elif action == "toggle":
            execute("UPDATE users SET active = ? WHERE id = ?", (0 if user["active"] else 1, user_id))
            revoke_user_sessions(user_id)
        else:
            execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
        audit.record("user." + action, "user", user_id, {"username": user["username"]})
    if issued:
        rows = query("SELECT u.*, c.name AS company_name, s.placement_id FROM users u LEFT JOIN companies c ON c.id = u.company_id"
                     " LEFT JOIN students s ON s.id = u.student_id ORDER BY u.role, u.username")
        return render_template("admin/users.html", users=rows, companies=query("SELECT id, name FROM companies ORDER BY name"),
                               errors={}, form={}, issued=issued)
    flash("Account updated.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/audit")
@require("audit.read")
def audit_log():
    action = (request.args.get("action") or "").strip()[:40]
    actor = (request.args.get("actor") or "").strip()[:40]
    where, params = ["1 = 1"], []
    if action:
        where.append("action LIKE ? ESCAPE '\\'")
        params.append(action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if actor:
        where.append("actor = ?")
        params.append(actor)
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    total = query(f"SELECT COUNT(*) AS n FROM audit_log WHERE {' AND '.join(where)}", params, one=True)["n"]
    rows = query(f"SELECT * FROM audit_log WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT 50 OFFSET ?",
                 params + [(page - 1) * 50])
    return render_template("admin/audit.html", rows=rows, total=total, page=page, pages=max(1, (total + 49) // 50),
                           action=action, actor=actor, verification=None)


@bp.route("/audit/verify", methods=["POST"])
@require("audit.read")
def audit_verify():
    result = audit.verify_chain()
    with transaction():
        audit.record("audit.verify", "audit_log", None, {"ok": result["ok"], "checked": result["checked"]})
    rows = query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 50")
    total = query("SELECT COUNT(*) AS n FROM audit_log", one=True)["n"]
    return render_template("admin/audit.html", rows=rows, total=total, page=1, pages=max(1, (total + 49) // 50),
                           action="", actor="", verification=result)


@bp.route("/backups")
@require("backup.manage")
def backups():
    return render_template("admin/backups.html", backups=backup.list_backups(current_app.config["INSTANCE_DIR"]), result=None)


@bp.route("/backups", methods=["POST"])
@require("backup.manage")
def create_backup():
    keys = current_app.extensions["pg_keys"]
    with transaction():
        audit.record("backup.create", "backup", None, {})
    info = backup.create_backup(current_app.config["DATABASE"], current_app.config["INSTANCE_DIR"], keys["backup_key"])
    with transaction():
        audit.record("backup.created", "backup", info["name"], {"bytes": info["bytes"], "sha256": info["sha256"]})
    flash(f"Encrypted backup {info['name']} created.", "success")
    return redirect(url_for("admin.backups"))


@bp.route("/backups/verify", methods=["POST"])
@require("backup.manage")
def verify_backup():
    keys = current_app.extensions["pg_keys"]
    try:
        path = backup.resolve(current_app.config["INSTANCE_DIR"], request.form.get("name", ""))
    except ValueError:
        abort(404)
    result = backup.verify_backup(path, keys["backup_key"], keys["audit_key"])
    with transaction():
        audit.record("backup.verify", "backup", path.name, {"ok": result["ok"]})
    return render_template("admin/backups.html", backups=backup.list_backups(current_app.config["INSTANCE_DIR"]),
                           result=result | {"name": path.name})
