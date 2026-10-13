"""Placement policy rule engine (NFSU Student Placement Guidelines 2026-27).

The engine is a pure function: plain data in, an explained decision out. It has
no database or request access, which keeps it deterministic and unit-testable.

Every rule returns a RuleResult (pass / review / block) with a human-readable
reason, so the Placement Cell can see exactly why a student was allowed,
blocked or referred for manual review. Final decisions on exceptions and
discipline remain with the Placement Cell; the engine only enforces and flags.
"""
from dataclasses import asdict, dataclass, field

CATEGORY_RANK = {"C": 0, "B": 1, "A": 2, "A+": 3}
TYPE_LABEL = {"I": "Internship only (I)", "F": "FTE only (F)", "IF": "Internship + PPO/FTE (I+F)"}

DEFAULT_SETTINGS = {
    "a_plus_min_lpa": 16.0,
    "a_min_lpa": 10.0,
    "b_min_lpa": 6.0,
    "b_switch_multiplier": 1.5,
    "absence_debar_drives": 3,
    "acceptance_window_hours": 24,
    "declined_offers_count": True,
    # F -> F upgrade: the offer-type rule forbids another FTE-only role while
    # the category rule permits upward switching. 'review' refers the case to
    # the Placement Cell, 'strict' blocks, 'switching' lets the category rule win.
    "conflict_mode": "review",
    "retention_years": 5,
}

SETTING_SPECS = {
    "a_plus_min_lpa": ("A+ threshold (LPA, inclusive)", float, 1.0, 200.0),
    "a_min_lpa": ("A threshold (LPA, inclusive)", float, 1.0, 200.0),
    "b_min_lpa": ("B threshold (LPA, inclusive)", float, 0.5, 200.0),
    "b_switch_multiplier": ("B-category switch multiplier", float, 1.0, 5.0),
    "absence_debar_drives": ("Drives barred after an unexcused absence", int, 0, 20),
    "acceptance_window_hours": ("Default offer acceptance window (hours)", int, 1, 720),
    "declined_offers_count": ("Declined / expired offers still count as a selection", bool, None, None),
    "conflict_mode": ("Resolution for F→F upgrade conflict", str, ("review", "strict", "switching"), None),
    "retention_years": ("Retention period for archived records (years)", int, 1, 20),
}

PASS, REVIEW, BLOCK = "pass", "review", "block"
SEVERITY = {PASS: 0, REVIEW: 1, BLOCK: 2}


@dataclass
class RuleResult:
    code: str
    title: str
    outcome: str
    message: str


@dataclass
class Decision:
    outcome: str  # 'allow' | 'review' | 'block'
    results: list = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"

    @property
    def headline(self) -> str:
        decisive = [r for r in self.results if r.outcome == (BLOCK if self.outcome == "block" else REVIEW)]
        if self.outcome == "allow":
            return "All policy checks passed."
        return decisive[0].message if decisive else ""

    def to_dict(self) -> dict:
        return {"outcome": self.outcome, "results": [asdict(r) for r in self.results]}


def categorize(ctc_lpa, s: dict = DEFAULT_SETTINGS):
    """Map an annual CTC to a company category. Boundaries are inclusive at
    the lower end: 16.0 is A+, 10.0 is A, 6.0 is B."""
    if ctc_lpa is None:
        return None
    if ctc_lpa >= s["a_plus_min_lpa"]:
        return "A+"
    if ctc_lpa >= s["a_min_lpa"]:
        return "A"
    if ctc_lpa >= s["b_min_lpa"]:
        return "B"
    return "C"


def counted_offers(offers: list, s: dict) -> list:
    """Offers that count as a 'selection' for policy purposes."""
    excluded = set() if s["declined_offers_count"] else {"declined", "expired"}
    return [o for o in offers if o["acceptance"] not in excluded]


def effective_type(offer: dict) -> str:
    """An internship whose PPO has been accepted behaves as I+F."""
    if offer["offer_type"] == "I" and offer.get("ppo_status") == "accepted":
        return "IF"
    return offer["offer_type"]


def best_fte(offers: list):
    fte = [o for o in offers if effective_type(o) in ("F", "IF") and o.get("category")]
    if not fte:
        return None
    return max(fte, key=lambda o: (CATEGORY_RANK[o["category"]], o.get("ctc_lpa") or 0))


def _fmt(v) -> str:
    return f"₹{v:g} LPA"


def evaluate(student: dict, drive: dict, offers: list, debarred_by=None, s: dict | None = None) -> Decision:
    """Decide whether `student` may participate in `drive`.

    student: registration_status, eligibility_status, course, cgpa, archived
    drive:   id, company_id, company_name, offer_type, ctc_lpa, category,
             eligible_courses (list), min_cgpa
    offers:  the student's offer history (offer_type, category, ctc_lpa,
             company_id, company_name, acceptance, ppo_status)
    debarred_by: None, or a dict describing the absence that bars this drive
    """
    s = {**DEFAULT_SETTINGS, **(s or {})}
    results: list[RuleResult] = []
    add = lambda code, title, outcome, msg: results.append(RuleResult(code, title, outcome, msg))

    # R1 Record state
    if student.get("archived"):
        add("R1", "Record status", BLOCK, "Student record is archived.")
    else:
        add("R1", "Record status", PASS, "Active student record.")

    # R2 Placement registration
    reg = student["registration_status"]
    if reg == "registered":
        add("R2", "Placement registration", PASS, "Registered for the 2026–27 placement session.")
    elif reg == "deregistered":
        add("R2", "Placement registration", BLOCK, "Student has deregistered from the placement process.")
    else:
        add("R2", "Placement registration", BLOCK, "Student is not registered for placements.")

    # R3 Academic eligibility verification
    elig = student["eligibility_status"]
    if elig == "eligible":
        add("R3", "Eligibility verification", PASS, "Eligibility verified by the course coordinator.")
    elif elig == "pending":
        add("R3", "Eligibility verification", REVIEW, "Eligibility is pending verification by the course coordinator.")
    else:
        add("R3", "Eligibility verification", BLOCK, "Student has been marked ineligible.")

    # R4 Company-specific criteria
    if student["course"] not in drive["eligible_courses"]:
        add("R4", "Company criteria", BLOCK, "Student's programme is not among the programmes eligible for this drive.")
    elif drive.get("min_cgpa") is not None:
        if student.get("cgpa") is None:
            add("R4", "Company criteria", REVIEW, f"Drive requires CGPA ≥ {drive['min_cgpa']:g}; student CGPA is not on record.")
        elif student["cgpa"] < drive["min_cgpa"]:
            add("R4", "Company criteria", BLOCK, f"CGPA {student['cgpa']:g} is below the drive minimum of {drive['min_cgpa']:g}.")
        else:
            add("R4", "Company criteria", PASS, f"Programme eligible and CGPA {student['cgpa']:g} meets the minimum {drive['min_cgpa']:g}.")
    else:
        add("R4", "Company criteria", PASS, "Programme is eligible for this drive.")

    # R5 Absenteeism debarment
    n = s["absence_debar_drives"]
    if debarred_by:
        add("R5", "Attendance", BLOCK,
            f"Unexcused absence at {debarred_by['company_name']} ({debarred_by['drive_date']}) bars the next {n} drives. "
            "An authorised officer may record an emergency exception.")
    else:
        add("R5", "Attendance", PASS, "No active absenteeism debarment.")

    held = counted_offers(offers, s)
    held_types = {effective_type(o) for o in held}
    new_type = drive["offer_type"]
    top = best_fte(held)
    new_cat = drive.get("category")

    # R7 Category switching (computed first; R6 may depend on it)
    cat_result: RuleResult
    if top is None:
        cat_result = RuleResult("R7", "Category switching", PASS, "No FTE offer held; no switching restriction applies.")
    elif top["category"] == "A+":
        cat_result = RuleResult("R7", "Category switching", BLOCK,
                                f"Selected in an A+ company ({top['company_name']}, {_fmt(top['ctc_lpa'])}). "
                                "A+ selections exit the placement process; no switching.")
    elif new_type == "I":
        cat_result = RuleResult("R7", "Category switching", PASS,
                                "Category switching applies to FTE-bearing roles; this is an internship-only drive.")
    elif new_cat is None:
        cat_result = RuleResult("R7", "Category switching", REVIEW, "Drive has no CTC on record, so its category cannot be determined.")
    elif top["category"] == "A":
        if new_cat == "A+":
            cat_result = RuleResult("R7", "Category switching", PASS, f"Holds an A offer; switching to an A+ drive ({_fmt(drive['ctc_lpa'])}) is permitted.")
        else:
            cat_result = RuleResult("R7", "Category switching", BLOCK,
                                    f"Holds an A offer ({top['company_name']}, {_fmt(top['ctc_lpa'])}); switching is allowed only to A+ companies "
                                    f"(≥ {_fmt(s['a_plus_min_lpa'])}). This drive is {new_cat}.")
    elif top["category"] == "B":
        need = round(top["ctc_lpa"] * s["b_switch_multiplier"], 2)
        if drive["ctc_lpa"] >= need:
            cat_result = RuleResult("R7", "Category switching", PASS,
                                    f"Holds a B offer at {_fmt(top['ctc_lpa'])}; {_fmt(drive['ctc_lpa'])} meets the "
                                    f"{s['b_switch_multiplier']:g}× requirement ({_fmt(need)}).")
        else:
            cat_result = RuleResult("R7", "Category switching", BLOCK,
                                    f"Holds a B offer at {_fmt(top['ctc_lpa'])}; a new offer must be at least "
                                    f"{s['b_switch_multiplier']:g}× ({_fmt(need)}). This drive offers {_fmt(drive['ctc_lpa'])}.")
    else:  # C
        if CATEGORY_RANK[new_cat] > CATEGORY_RANK["C"]:
            cat_result = RuleResult("R7", "Category switching", PASS, f"Holds a C offer; this {new_cat} drive is a higher category.")
        else:
            cat_result = RuleResult("R7", "Category switching", BLOCK,
                                    "Holds a C offer; only higher-category (B, A, A+) opportunities are permitted.")

    # R6 Offer-type restrictions
    if_offers = [o for o in held if effective_type(o) == "IF"]
    if if_offers:
        o = if_offers[0]
        if o["company_id"] == drive.get("company_id"):
            add("R6", "Offer type", REVIEW,
                f"Holds an I+F offer from {o['company_name']}; this drive is from the same organisation and needs manual review.")
        else:
            add("R6", "Offer type", BLOCK,
                f"Selected for I+F at {o['company_name']}; cannot participate in other I, F or I+F roles at another organisation.")
    elif new_type == "I" and "I" in held_types:
        add("R6", "Offer type", BLOCK, "Already selected for an internship; cannot apply for another internship-only role.")
    elif new_type == "F" and "F" in held_types:
        if cat_result.outcome == PASS and s["conflict_mode"] == "switching":
            add("R6", "Offer type", PASS, "FTE-only to FTE-only upgrade permitted because the category switching rule is satisfied (configured precedence).")
        elif cat_result.outcome == PASS and s["conflict_mode"] == "review":
            add("R6", "Offer type", REVIEW,
                "Guideline conflict: the offer-type rule forbids another FTE-only role, but the category switching rule permits this upgrade. "
                "Referred to the Placement Cell.")
        else:
            add("R6", "Offer type", BLOCK, "Already selected for an FTE-only role; cannot apply for another FTE-only role.")
    elif held_types:
        names = ", ".join(sorted(TYPE_LABEL[t] for t in held_types))
        add("R6", "Offer type", PASS, f"Holds {names}; a {TYPE_LABEL[new_type]} role is permitted subject to other rules.")
    else:
        add("R6", "Offer type", PASS, "No prior selection.")

    results.append(cat_result)
    results.sort(key=lambda r: int(r.code[1:]))

    worst = max(SEVERITY[r.outcome] for r in results)
    outcome = {0: "allow", 1: "review", 2: "block"}[worst]
    return Decision(outcome, results)


def switching_window(offers: list, s: dict | None = None) -> dict:
    """Summarise what a student may still apply for (for dashboards)."""
    s = {**DEFAULT_SETTINGS, **(s or {})}
    held = counted_offers(offers, s)
    types = {effective_type(o) for o in held}
    top = best_fte(held)
    if not held:
        return {"code": "open", "label": "Unrestricted"}
    if top and top["category"] == "A+":
        return {"code": "out", "label": "Out of process (A+)"}
    if "IF" in types:
        return {"code": "out", "label": "Out of process (I+F held)"}
    if top is None:  # internship only
        return {"code": "fte", "label": "FTE or I+F roles only"}
    if top["category"] == "A":
        return {"code": "aplus", "label": f"A+ only (≥ {_fmt(s['a_plus_min_lpa'])})"}
    if top["category"] == "B":
        return {"code": "b", "label": f"≥ {_fmt(round(top['ctc_lpa'] * s['b_switch_multiplier'], 2))}"}
    return {"code": "c", "label": f"Higher category (≥ {_fmt(s['b_min_lpa'])})"}
