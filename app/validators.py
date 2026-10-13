"""Server-side input validation. Client-side checks are a convenience only;
every value is re-validated here against an allow-list before use."""
import re
from datetime import date

from .constants import (ACCEPTANCE, COURSES, ELIGIBILITY, EVENTS, JOINING, NOC, OFFER_TYPES, PPO,
                        REGISTRATION)

PLACEMENT_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{3,23}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]{1,99}$")
MOBILE_RE = re.compile(r"^[6-9]\d{9}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")
BATCH_RE = re.compile(r"^20\d{2}-(?:20)?\d{2}$")
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
COMPANY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 &.,()'\-]{1,79}$")


class ValidationError(Exception):
    def __init__(self, errors: dict):
        super().__init__("Validation failed")
        self.errors = errors


def _text(form, key, max_len=200) -> str:
    return (form.get(key) or "").strip()[:max_len + 1]


def normalise_mobile(raw: str) -> str:
    digits = re.sub(r"[\s\-()]", "", raw or "")
    if digits.startswith("+91"):
        digits = digits[3:]
    elif digits.startswith("0") and len(digits) == 11:
        digits = digits[1:]
    return digits


def choice(form, key, options, errors, label, required=True):
    value = _text(form, key, 40)
    if not value and not required:
        return None
    if value not in options:
        errors[key] = f"Select a valid {label}."
        return None
    return value


def number(form, key, errors, label, lo, hi, required=False, integer=False):
    raw = _text(form, key, 20)
    if raw == "":
        if required:
            errors[key] = f"Enter {label}."
        return None
    try:
        value = int(raw) if integer else float(raw)
    except ValueError:
        errors[key] = f"{label.capitalize()} must be a number."
        return None
    if value != value or not (lo <= value <= hi):  # NaN-safe range check
        errors[key] = f"{label.capitalize()} must be between {lo:g} and {hi:g}."
        return None
    return value


def iso_date(form, key, errors, label, required=True):
    raw = _text(form, key, 10)
    if not raw:
        if required:
            errors[key] = f"Enter {label}."
        return None
    try:
        d = date.fromisoformat(raw)
    except ValueError:
        errors[key] = f"{label.capitalize()} must be a valid date (YYYY-MM-DD)."
        return None
    if not (2020 <= d.year <= 2035):
        errors[key] = f"{label.capitalize()} is outside the supported range."
        return None
    return d.isoformat()


def student_fields(form, creating: bool, allowed: set) -> dict:
    """Validate a student form. `allowed` is the role's field allow-list;
    anything else in the request is ignored (prevents mass assignment)."""
    errors, data = {}, {}
    if creating and "placement_id" in allowed:
        pid = _text(form, "placement_id", 24).upper()
        if not PLACEMENT_ID_RE.match(pid):
            errors["placement_id"] = "Placement ID must be 4–24 characters: A–Z, 0–9 and hyphens."
        data["placement_id"] = pid
    if "full_name" in allowed:
        name = re.sub(r"\s+", " ", _text(form, "full_name", 100))
        if not NAME_RE.match(name):
            errors["full_name"] = "Enter the full name using letters, spaces, apostrophes, hyphens or periods."
        data["full_name"] = name
    if "mobile" in allowed:
        mobile = normalise_mobile(_text(form, "mobile", 20))
        if not MOBILE_RE.match(mobile):
            errors["mobile"] = "Enter a valid 10-digit Indian mobile number."
        data["mobile"] = mobile
    if "email" in allowed:
        email = _text(form, "email", 254).lower()
        if not EMAIL_RE.match(email):
            errors["email"] = "Enter a valid email address."
        data["email"] = email
    if "course" in allowed:
        data["course"] = choice(form, "course", COURSES, errors, "programme")
    if "batch" in allowed:
        batch = _text(form, "batch", 9)
        if not BATCH_RE.match(batch):
            errors["batch"] = "Batch must look like 2025-27 or 2025-2027."
        data["batch"] = batch
    if "registration_status" in allowed:
        data["registration_status"] = choice(form, "registration_status", REGISTRATION, errors, "registration status")
    if "eligibility_status" in allowed:
        data["eligibility_status"] = choice(form, "eligibility_status", ELIGIBILITY, errors, "eligibility status")
    if "cgpa" in allowed:
        data["cgpa"] = number(form, "cgpa", errors, "CGPA", 0, 10)
    if "remarks" in allowed:
        remarks = _text(form, "remarks", 500)
        if len(remarks) > 500:
            errors["remarks"] = "Remarks must be at most 500 characters."
        data["remarks"] = remarks or None
    if errors:
        raise ValidationError(errors)
    return data


def company_name(raw: str, errors: dict, key="company_name") -> str:
    name = re.sub(r"\s+", " ", (raw or "").strip())
    if not COMPANY_RE.match(name):
        errors[key] = "Enter a company name (2–80 characters)."
    return name


def drive_fields(form) -> dict:
    errors, d = {}, {}
    d["company_name"] = company_name(form.get("company_name"), errors)
    d["title"] = _text(form, "title", 120)
    if not (2 <= len(d["title"]) <= 120):
        errors["title"] = "Enter a role title (2–120 characters)."
    d["offer_type"] = choice(form, "offer_type", OFFER_TYPES, errors, "offer type")
    d["ctc_lpa"] = number(form, "ctc_lpa", errors, "CTC", 0.5, 500)
    d["stipend_amount"] = number(form, "stipend_amount", errors, "stipend", 0, 10_000_000)
    d["stipend_period"] = choice(form, "stipend_period", {"month": 1, "total": 1}, errors, "stipend period", required=False)
    if d["offer_type"] in ("F", "IF") and d["ctc_lpa"] is None and "ctc_lpa" not in errors:
        errors["ctc_lpa"] = "FTE-bearing roles need an annual CTC to determine the category."
    if d["offer_type"] in ("I", "IF") and d["stipend_amount"] is not None and not d["stipend_period"]:
        errors["stipend_period"] = "Select whether the stipend is monthly or a total amount."
    if d["offer_type"] == "I":
        d["ctc_lpa"] = None
    courses = [c for c in form.getlist("eligible_courses") if c in COURSES]
    if not courses:
        errors["eligible_courses"] = "Select at least one eligible programme."
    d["eligible_courses"] = ",".join(sorted(set(courses)))
    d["min_cgpa"] = number(form, "min_cgpa", errors, "minimum CGPA", 0, 10)
    d["drive_date"] = iso_date(form, "drive_date", errors, "drive date")
    d["response_hours"] = number(form, "response_hours", errors, "company response window", 1, 720,
                                 required=True, integer=True)
    if errors:
        raise ValidationError(errors)
    return d


def offer_fields(form) -> dict:
    errors, d = {}, {}
    d["offer_type"] = choice(form, "offer_type", OFFER_TYPES, errors, "offer type")
    d["ctc_lpa"] = number(form, "ctc_lpa", errors, "CTC", 0.5, 500)
    d["stipend_amount"] = number(form, "stipend_amount", errors, "stipend", 0, 10_000_000)
    d["stipend_period"] = choice(form, "stipend_period", {"month": 1, "total": 1}, errors, "stipend period", required=False)
    d["offer_date"] = iso_date(form, "offer_date", errors, "offer date")
    d["response_hours"] = number(form, "response_hours", errors, "company response window", 1, 720,
                                 required=True, integer=True)
    if d["offer_type"] in ("F", "IF") and d["ctc_lpa"] is None and "ctc_lpa" not in errors:
        errors["ctc_lpa"] = "FTE-bearing offers need an annual CTC."
    if d["offer_type"] == "I":
        d["ctc_lpa"] = None
    remarks = _text(form, "remarks", 500)
    d["remarks"] = remarks[:500] or None
    if errors:
        raise ValidationError(errors)
    return d


def offer_status_fields(form) -> dict:
    errors, d = {}, {}
    d["acceptance"] = choice(form, "acceptance", ACCEPTANCE, errors, "acceptance status")
    d["joining"] = choice(form, "joining", JOINING, errors, "joining status")
    d["ppo_status"] = choice(form, "ppo_status", PPO, errors, "PPO status")
    d["noc_status"] = choice(form, "noc_status", NOC, errors, "NOC status")
    note = _text(form, "note", 300)
    if len(note) < 5:
        errors["note"] = "Record a short reason for this change (at least 5 characters)."
    d["note"] = note[:300]
    if errors:
        raise ValidationError(errors)
    return d


def reason(form, key="reason", min_len=10, label="a reason") -> str:
    value = _text(form, key, 300)
    if len(value) < min_len:
        raise ValidationError({key: f"Enter {label} (at least {min_len} characters)."})
    return value[:300]


def event_choice(form, errors):
    return choice(form, "event", EVENTS, errors, "event")
