"""Policy engine: NFSU Student Placement Guidelines 2026-27."""
import pytest

from app.policy import DEFAULT_SETTINGS, categorize, evaluate, switching_window

STUDENT = {"registration_status": "registered", "eligibility_status": "eligible", "course": "MSC_DFIS",
           "cgpa": 8.0, "archived": 0}


def drive(otype="F", ctc=12.0, company_id=99, courses=("MSC_DFIS",), min_cgpa=None):
    return {"id": 1, "company_id": company_id, "company_name": "NewCo", "offer_type": otype, "ctc_lpa": ctc,
            "category": categorize(ctc) if otype != "I" else None, "eligible_courses": list(courses),
            "min_cgpa": min_cgpa, "drive_date": "2026-11-01"}


def offer(otype="F", ctc=8.0, company_id=1, acceptance="accepted", ppo="na"):
    return {"offer_type": otype, "ctc_lpa": ctc, "category": categorize(ctc) if otype != "I" else None,
            "company_id": company_id, "company_name": "HeldCo", "acceptance": acceptance, "ppo_status": ppo}


def rule(decision, code):
    return next(r for r in decision.results if r.code == code)


# --- categorisation -----------------------------------------------------------
@pytest.mark.parametrize("ctc,cat", [(16.0, "A+"), (15.99, "A"), (10.0, "A"), (9.99, "B"), (6.0, "B"), (5.99, "C"), (1, "C")])
def test_category_boundaries_inclusive(ctc, cat):
    assert categorize(ctc) == cat


# --- category switching -------------------------------------------------------
def test_a_plus_selection_exits_process_even_for_internships():
    d = evaluate(STUDENT, drive("I", None), [offer("F", 18.0)])
    assert d.outcome == "block" and rule(d, "R7").outcome == "block"


def test_a_holder_may_switch_only_to_a_plus():
    assert evaluate(STUDENT, drive("IF", 15.0), [offer("F", 12.0)]).outcome == "block"
    assert evaluate(STUDENT, drive("IF", 16.0), [offer("F", 12.0)]).outcome == "allow"


@pytest.mark.parametrize("new,expected", [(11.25, "pass"), (11.24, "block")])
def test_b_holder_needs_one_point_five_times(new, expected):
    d = evaluate(STUDENT, drive("IF", new), [offer("F", 7.5)])
    assert rule(d, "R7").outcome == expected


def test_c_holder_needs_higher_category():
    assert rule(evaluate(STUDENT, drive("IF", 5.5), [offer("F", 5.0)]), "R7").outcome == "block"
    assert rule(evaluate(STUDENT, drive("IF", 6.0), [offer("F", 5.0)]), "R7").outcome == "pass"


def test_switching_uses_best_fte_offer_held():
    d = evaluate(STUDENT, drive("IF", 14.0), [offer("F", 5.0), offer("F", 12.0, company_id=2)])
    assert "A offer" in rule(d, "R7").message and d.outcome == "block"


# --- offer-type restrictions --------------------------------------------------
def test_internship_holder_cannot_take_another_internship():
    assert rule(evaluate(STUDENT, drive("I", None), [offer("I", None)]), "R6").outcome == "block"


def test_internship_holder_may_take_fte_or_if():
    assert evaluate(STUDENT, drive("F", 12.0), [offer("I", None)]).outcome == "allow"
    assert evaluate(STUDENT, drive("IF", 12.0), [offer("I", None)]).outcome == "allow"


def test_fte_holder_may_take_internship():
    assert evaluate(STUDENT, drive("I", None), [offer("F", 8.0)]).outcome == "allow"


def test_if_holder_blocked_at_other_organisation():
    d = evaluate(STUDENT, drive("I", None, company_id=5), [offer("IF", 14.0, company_id=1)])
    assert rule(d, "R6").outcome == "block"


def test_if_holder_same_organisation_referred():
    d = evaluate(STUDENT, drive("F", 18.0, company_id=1), [offer("IF", 14.0, company_id=1)])
    assert rule(d, "R6").outcome == "review"


def test_accepted_ppo_behaves_as_if():
    d = evaluate(STUDENT, drive("F", 20.0, company_id=7), [offer("I", None, ppo="accepted")])
    assert rule(d, "R6").outcome == "block"


@pytest.mark.parametrize("mode,expected", [("review", "review"), ("strict", "block"), ("switching", "allow")])
def test_f_to_f_upgrade_conflict_resolution(mode, expected):
    s = {**DEFAULT_SETTINGS, "conflict_mode": mode}
    assert evaluate(STUDENT, drive("F", 12.0), [offer("F", 7.5)], s=s).outcome == expected


def test_f_to_f_without_valid_switch_is_blocked_in_every_mode():
    for mode in ("review", "strict", "switching"):
        s = {**DEFAULT_SETTINGS, "conflict_mode": mode}
        assert evaluate(STUDENT, drive("F", 9.0), [offer("F", 7.5)], s=s).outcome == "block"


def test_declined_offer_counting_is_configurable():
    held = [offer("F", 18.0, acceptance="declined")]
    assert evaluate(STUDENT, drive("F", 24.0), held).outcome == "block"
    s = {**DEFAULT_SETTINGS, "declined_offers_count": False}
    assert evaluate(STUDENT, drive("F", 24.0), held, s=s).outcome == "allow"


# --- registration, eligibility, criteria, attendance ---------------------------
@pytest.mark.parametrize("field,value,outcome", [
    ("registration_status", "deregistered", "block"), ("registration_status", "not_registered", "block"),
    ("eligibility_status", "ineligible", "block"), ("eligibility_status", "pending", "review"), ("archived", 1, "block")])
def test_student_state_rules(field, value, outcome):
    assert evaluate({**STUDENT, field: value}, drive(), []).outcome == outcome


def test_programme_must_be_eligible():
    assert rule(evaluate(STUDENT, drive(courses=("MTECH_CS",)), []), "R4").outcome == "block"


def test_cgpa_minimum():
    assert evaluate({**STUDENT, "cgpa": 6.9}, drive(min_cgpa=7.0), []).outcome == "block"
    assert evaluate({**STUDENT, "cgpa": None}, drive(min_cgpa=7.0), []).outcome == "review"


def test_absenteeism_debarment_blocks():
    d = evaluate(STUDENT, drive(), [], debarred_by={"company_name": "TCS", "drive_date": "2026-09-05"})
    assert rule(d, "R5").outcome == "block"


def test_every_decision_explains_all_seven_rules():
    d = evaluate(STUDENT, drive(), [])
    assert d.outcome == "allow" and [r.code for r in d.results] == [f"R{i}" for i in range(1, 8)]
    assert all(r.message for r in d.results)


def test_switching_window_summaries():
    assert switching_window([])["code"] == "open"
    assert switching_window([offer("F", 18.0)])["code"] == "out"
    assert switching_window([offer("F", 12.0)])["code"] == "aplus"
    assert "11.25" in switching_window([offer("F", 7.5)])["label"]
    assert switching_window([offer("I", None)])["code"] == "fte"
