"""Policy catalogue, configurable thresholds, simulator and review queue."""
import json

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import audit, policy, services
from ..constants import FLAG_KINDS, now_iso
from ..db import execute, query, transaction
from ..security import flash, require
from ..validators import ValidationError, reason

bp = Blueprint("policy", __name__, url_prefix="/policy")


@bp.route("")
@require("policy.read")
def rules():
    return render_template("policy/rules.html", s=services.get_settings())


@bp.route("/settings", methods=["GET", "POST"])
@require("policy.edit")
def settings():
    current = services.get_settings()
    if request.method == "GET":
        return render_template("policy/settings.html", s=current, specs=policy.SETTING_SPECS, errors={}, form=current)
    errors, new = {}, {}
    for key, (label, typ, lo, hi) in policy.SETTING_SPECS.items():
        raw = (request.form.get(key) or "").strip()
        try:
            if typ is bool:
                val = raw == "1"
            elif typ is str:
                if raw not in lo:
                    raise ValueError
                val = raw
            else:
                val = typ(raw)
                if not (lo <= val <= hi):
                    raise ValueError
        except ValueError:
            errors[key] = f"Enter a valid value for {label.lower()}."
            continue
        new[key] = val
    if not errors and not (new["a_plus_min_lpa"] > new["a_min_lpa"] > new["b_min_lpa"]):
        errors["a_plus_min_lpa"] = "Thresholds must satisfy A+ > A > B."
    try:
        why = reason(request.form, label="the policy reference or reason for the change")
    except ValidationError as exc:
        errors.update(exc.errors)
    if errors:
        return render_template("policy/settings.html", s=current, specs=policy.SETTING_SPECS, errors=errors,
                               form=request.form), 422
    changed = {k: (current[k], v) for k, v in new.items() if current[k] != v}
    if changed:
        with transaction():
            for k, (_, v) in changed.items():
                execute("INSERT INTO policy_settings (key, value, updated_at, updated_by) VALUES (?,?,?,?)"
                        " ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at,"
                        " updated_by = excluded.updated_by", (k, json.dumps(v), now_iso(), g.user["id"]))
            audit.record("policy.update", "policy", None, {"before": {k: b for k, (b, _) in changed.items()},
                                                          "after": {k: a for k, (_, a) in changed.items()}, "reason": why})
        flash(f"Policy updated ({len(changed)} setting(s)). The change is recorded in the audit trail.", "success")
    else:
        flash("No settings changed.", "info")
    return redirect(url_for("policy.settings"))


@bp.route("/simulate", methods=["GET", "POST"])
@require("policy.simulate")
def simulate():
    """What-if: run the engine for a student against an existing drive or a
    hypothetical opportunity, without writing anything."""
    s = services.get_settings()
    drives = query("SELECT d.*, c.name AS company_name FROM drives d JOIN companies c ON c.id = d.company_id ORDER BY d.drive_date DESC")
    result, st, target, errors = None, None, None, {}
    form = request.form if request.method == "POST" else {"mode": "hypothetical", "offer_type": "F", "ctc_lpa": "12"}
    if request.method == "POST":
        pid = (request.form.get("placement_id") or "").strip().upper()[:24]
        st = query("SELECT * FROM students WHERE placement_id = ?", (pid,), one=True)
        if st is None or (g.user["role"] == "coordinator" and st["course"] != g.user["course_scope"]):
            errors["placement_id"] = "No student with that Placement ID in your scope."
        mode = request.form.get("mode")
        if mode == "drive":
            did = request.form.get("drive_id") or ""
            drive = services.get_drive(int(did)) if did.isdigit() else None
            if drive is None:
                errors["drive_id"] = "Select a drive."
            target = drive
        else:
            otype = request.form.get("offer_type")
            if otype not in ("I", "F", "IF"):
                errors["offer_type"] = "Select an offer type."
            ctc = None
            if otype in ("F", "IF"):
                try:
                    ctc = float(request.form.get("ctc_lpa") or "")
                    if not (0.5 <= ctc <= 500):
                        raise ValueError
                except ValueError:
                    errors["ctc_lpa"] = "Enter a CTC between 0.5 and 500 LPA."
            if st is not None and not errors:
                target = {"id": -1, "company_id": -1, "company_name": "Hypothetical company", "offer_type": otype,
                          "ctc_lpa": ctc, "eligible_courses": st["course"], "min_cgpa": None, "drive_date": "9999-12-31"}
        if not errors:
            result = services.evaluate(st, target, s)
            target = services.drive_view(target)
    return render_template("policy/simulate.html", drives=drives, form=form, errors=errors, result=result,
                           st=st, target=target, offers=services.offers_for(st["id"]) if st and not errors else [])


@bp.route("/flags")
@require("flag.read")
def flags():
    status = request.args.get("status") or "open"
    if status not in ("open", "resolved", "dismissed"):
        abort(400, description="Unknown filter value.")
    scope, params = "", [status]
    if g.user["role"] == "coordinator":
        scope = " AND s.course = ?"
        params.append(g.user["course_scope"])
    rows = query("SELECT f.*, s.full_name, s.placement_id, s.course, u.username AS resolver FROM flags f"
                 " JOIN students s ON s.id = f.student_id LEFT JOIN users u ON u.id = f.resolved_by"
                 " WHERE f.status = ?" + scope + " ORDER BY f.created_at DESC", params)
    return render_template("policy/flags.html", flags=rows, status=status, kinds=FLAG_KINDS)


@bp.route("/flags/<int:flag_id>", methods=["POST"])
@require("flag.resolve")
def resolve_flag(flag_id):
    flag = query("SELECT * FROM flags WHERE id = ?", (flag_id,), one=True)
    if flag is None:
        abort(404)
    action = request.form.get("action")
    if action not in ("resolved", "dismissed") or flag["status"] != "open":
        abort(400, description="This flag cannot be updated.")
    try:
        why = reason(request.form, label="the Placement Cell decision")
    except ValidationError as exc:
        flash(exc.errors["reason"], "error")
        return redirect(url_for("policy.flags"))
    with transaction():
        execute("UPDATE flags SET status = ?, resolved_by = ?, resolved_at = ?, resolution = ? WHERE id = ?",
                (action, g.user["id"], now_iso(), why, flag_id))
        audit.record("flag.resolve" if action == "resolved" else "flag.dismiss", "flag", flag_id,
                     {"student_id": flag["student_id"], "kind": flag["kind"], "resolution": why})
    flash("Flag " + action + ".", "success")
    return redirect(url_for("policy.flags"))
