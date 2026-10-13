"""Domain vocabularies shared by validation, templates and reports."""
from datetime import datetime, timedelta, timezone

COURSES = {
    "MTECH_CS": "M.Tech. Computer Science",
    "MTECH_AIDS": "M.Tech. AI & Data Science",
    "BTECH_MTECH_CSE": "B.Tech.–M.Tech. CSE",
    "MSC_CS": "M.Sc. Computer Science",
    "MSC_DFIS": "M.Sc. Digital Forensics & InfoSec",
}
COURSE_SHORT = {
    "MTECH_CS": "M.Tech. CS",
    "MTECH_AIDS": "M.Tech. AIDS",
    "BTECH_MTECH_CSE": "B.Tech.–M.Tech. CSE",
    "MSC_CS": "M.Sc. CS",
    "MSC_DFIS": "M.Sc. DFIS",
}
REGISTRATION = {"registered": "Registered", "deregistered": "Deregistered", "not_registered": "Not registered"}
ELIGIBILITY = {"eligible": "Eligible", "ineligible": "Ineligible", "pending": "Pending verification"}
OFFER_TYPES = {"I": "Internship (I)", "F": "Full-time (F)", "IF": "Internship + FTE (I+F)"}
OFFER_TYPE_SHORT = {"I": "I", "F": "F", "IF": "I+F"}
ACCEPTANCE = {"pending": "Pending", "accepted": "Accepted", "declined": "Declined", "expired": "Expired"}
JOINING = {"pending": "Pending", "joined": "Joined", "not_joined": "Not joined"}
PPO = {"na": "Not applicable", "pending": "Pending", "offered": "Offered", "accepted": "Accepted", "declined": "Declined"}
NOC = {"na": "Not applicable", "requested": "Requested", "issued": "Issued", "rejected": "Rejected"}
APPLICATION = {"applied": "Applied", "shortlisted": "Shortlisted", "selected": "Selected",
               "rejected": "Not selected", "withdrawn": "Withdrawn"}
EVENTS = {"ppt": "Pre-placement talk", "test": "Test", "gd": "Group discussion", "interview": "Interview", "other": "Other"}
ATTENDANCE = {"present": "Present", "absent": "Absent", "excused": "Excused (exception)"}
FLAG_KINDS = {"policy_violation": "Suspected violation", "policy_conflict": "Guideline conflict",
              "absenteeism": "Absenteeism", "offer_expired": "Offer expired", "duplicate_suspect": "Duplicate suspect"}
ROLES = {"admin": "Placement Administrator", "officer": "Placement Officer",
         "coordinator": "Course Coordinator", "recruiter": "Company / Recruiter", "student": "Student"}
PLACEMENT_STATUS = {"unplaced": "Unplaced", "internship": "Internship only", "fte": "FTE only",
                    "internship_fte": "Internship + PPO/FTE"}

IST = timezone(timedelta(hours=5, minutes=30))
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def now_iso() -> str:
    return utcnow().strftime(TS_FMT)


def parse_ts(value: str) -> datetime:
    return datetime.strptime(value, TS_FMT).replace(tzinfo=timezone.utc)
