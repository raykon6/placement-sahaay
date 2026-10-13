"""Load demonstration data (fictional students and companies).

    python scripts/seed.py            # creates instance/placement.db
    python scripts/seed.py --reset    # wipes and recreates it

Refuses to run when APP_ENV=production. All names, phone numbers and email
addresses are synthetic.
"""
import json
import os
import random
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app, services  # noqa: E402
from app.audit import record  # noqa: E402
from app.constants import TS_FMT, now_iso, utcnow  # noqa: E402
from app.db import execute, get_db, init_schema, query, transaction  # noqa: E402
from app.policy import DEFAULT_SETTINGS, categorize  # noqa: E402
from app.security import hash_password  # noqa: E402

DEMO_PASSWORD = os.environ.get("PG_DEMO_PASSWORD", "Demo-Placement-2026")

FIRST = ["Aarav", "Diya", "Ishaan", "Ananya", "Kabir", "Meera", "Vihaan", "Saanvi", "Arjun", "Myra", "Reyansh", "Aadhya",
         "Rohan", "Kavya", "Dhruv", "Tara", "Aditya", "Nisha", "Karan", "Riya", "Yash", "Pooja", "Nikhil", "Sneha",
         "Harsh", "Isha", "Manav", "Priya", "Siddharth", "Zoya", "Varun", "Ira", "Kunal", "Anika", "Parth", "Mahi"]
LAST = ["Shah", "Patel", "Mehta", "Iyer", "Desai", "Rao", "Nair", "Joshi", "Trivedi", "Kulkarni", "Bhatt", "Menon",
        "Chauhan", "Pandya", "Reddy", "Gupta", "Verma", "Saxena", "Parikh", "Dave"]
COURSE_CODE = {"MTECH_CS": "CS", "MTECH_AIDS": "AIDS", "BTECH_MTECH_CSE": "CSE", "MSC_CS": "MSCCS", "MSC_DFIS": "DFIS"}
BATCH = {"MTECH_CS": "2025-27", "MTECH_AIDS": "2025-27", "BTECH_MTECH_CSE": "2022-27", "MSC_CS": "2025-27", "MSC_DFIS": "2025-27"}
ALL = ",".join(sorted(COURSE_CODE))

DRIVES = [  # company, title, type, ctc, stipend, courses, date, status
    ("Infosys", "Systems Engineer", "F", 7.5, None, ALL, "2026-08-05", "closed"),
    ("Deloitte", "Cyber Risk Analyst", "F", 12.0, None, ALL, "2026-08-12", "closed"),
    ("CrowdStrike", "Threat Intelligence Engineer", "F", 18.0, None, "MSC_DFIS,MTECH_CS,MSC_CS", "2026-08-20", "closed"),
    ("KPMG", "Forensic Technology Intern", "I", None, 40000, ALL, "2026-08-25", "closed"),
    ("Palo Alto Networks", "Security Engineer (I+F)", "IF", 14.0, 50000, "MTECH_CS,MSC_DFIS,BTECH_MTECH_CSE", "2026-09-02", "closed"),
    ("TCS", "Assistant Systems Engineer", "F", 5.0, None, ALL, "2026-09-05", "closed"),
    ("Mastercard", "Data Analyst", "F", 9.5, None, "MTECH_AIDS,MSC_CS,MTECH_CS", "2026-09-12", "closed"),
    ("Microsoft", "Software Engineer", "F", 24.0, None, ALL, "2026-10-20", "open"),
    ("Accenture", "Security Consultant", "F", 9.0, None, ALL, "2026-10-22", "open"),
    ("Google", "Software Engineer (I+F)", "IF", 20.0, 80000, "MTECH_CS,MTECH_AIDS,BTECH_MTECH_CSE,MSC_CS", "2026-10-25", "open"),
    ("EY", "Cyber Security Intern", "I", None, 35000, ALL, "2026-10-28", "open"),
    ("Quick Heal", "Malware Analyst", "F", 12.5, None, "MSC_DFIS,MTECH_CS", "2026-10-30", "open"),
    ("Cisco", "Network Security Engineer", "F", 13.0, None, ALL, "2026-11-02", "open"),
]


def main(reset: bool):
    if os.environ.get("APP_ENV") == "production":
        sys.exit("Refusing to seed demo data in production.")
    app = create_app()
    db_path = Path(app.config["DATABASE"])
    if reset and db_path.exists():
        db_path.unlink()
        app = create_app()
    with app.app_context():
        if query("SELECT COUNT(*) AS n FROM students", one=True)["n"]:
            sys.exit("Database already contains data. Use --reset to recreate it.")
        rng = random.Random(2026)
        now = utcnow()
        with transaction():
            for k, v in DEFAULT_SETTINGS.items():
                execute("INSERT INTO policy_settings (key, value, updated_at) VALUES (?,?,?)", (k, json.dumps(v), now_iso()))
            record("system.seed", "system", None, {"note": "demonstration data loaded"}, actor={})

        # ---- students
        sid = {}
        used_names = set()
        n = 0
        with transaction():
            for course, code in COURSE_CODE.items():
                count = 10 if course in ("MSC_DFIS", "MTECH_CS") else 8
                for i in range(1, count + 1):
                    while True:
                        name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
                        if name not in used_names:
                            used_names.add(name)
                            break
                    n += 1
                    pid = f"NFSU-25-{code}-{i:03d}"
                    reg, elig = "registered", "eligible"
                    if i == count:
                        reg = "not_registered"
                    elif i == count - 1:
                        elig = "pending"
                    if course == "MSC_CS" and i == 6:
                        reg = "deregistered"
                    if course == "MTECH_AIDS" and i == 5:
                        elig = "ineligible"
                    sid[pid] = services.insert_student({
                        "placement_id": pid, "enrollment_no": f"25{list(COURSE_CODE).index(course) + 1:02d}{i:04d}",
                        "full_name": name, "mobile": f"9{rng.randint(100000000, 999999999)}",
                        "email": f"{name.split()[0].lower()}.{name.split()[1].lower()}{n}@students.nfsu.ac.in",
                        "course": course, "batch": BATCH[course], "registration_status": reg,
                        "eligibility_status": elig, "cgpa": round(rng.uniform(6.4, 9.6), 2), "remarks": None})
            record("student.import", "student", None, {"rows": len(sid), "source": "seed"}, actor={})

        # ---- companies and drives
        drive_id = {}
        with transaction():
            for company, title, otype, ctc, stipend, courses, date, status in DRIVES:
                cid = services.get_or_create_company(company)
                cat = categorize(ctc) if otype != "I" else None
                drive_id[company] = execute(
                    "INSERT INTO drives (company_id, title, offer_type, ctc_lpa, stipend_amount, stipend_period, category,"
                    " eligible_courses, min_cgpa, drive_date, response_hours, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (cid, title, otype, ctc, stipend, "month" if stipend else None, cat, courses,
                     7.0 if company in ("Microsoft", "Google") else None, date, 48 if company == "Microsoft" else 24,
                     status, now_iso())).lastrowid
                record("drive.create", "drive", drive_id[company], {"company": company, "category": cat}, actor={})

        def offer(pid, company, acceptance="accepted", joining="pending", ppo="na", off_campus=False, days_ago=30):
            d = query("SELECT * FROM drives WHERE id = ?", (drive_id[company],), one=True) if company in drive_id else None
            issued = now - timedelta(days=days_ago)
            if d is None:  # off-campus
                cid, otype, ctc, stipend = services.get_or_create_company(company), "F", 11.0, None
            else:
                cid, otype, ctc, stipend = d["company_id"], d["offer_type"], d["ctc_lpa"], d["stipend_amount"]
            deadline = (issued + timedelta(hours=24 if days_ago else 20)).strftime(TS_FMT)
            if days_ago == 0:
                deadline = (now + timedelta(hours=20)).strftime(TS_FMT)
            oid = execute(
                "INSERT INTO offers (student_id, drive_id, company_id, offer_type, category, ctc_lpa, stipend_amount, stipend_period,"
                " offer_date, deadline_at, acceptance, joining, ppo_status, off_campus, noc_status, policy_outcome, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid[pid], d["id"] if d else None, cid, otype, categorize(ctc) if otype != "I" else None, ctc, stipend,
                 "month" if stipend else None, issued.date().isoformat(), deadline, acceptance, joining,
                 ppo if otype == "I" else "na", int(off_campus), "issued" if off_campus else "na", "allow",
                 issued.strftime(TS_FMT), issued.strftime(TS_FMT))).lastrowid
            if d:
                execute("INSERT OR IGNORE INTO applications (drive_id, student_id, status, decision, created_at, updated_at)"
                        " VALUES (?,?,?,?,?,?)", (d["id"], sid[pid], "selected", json.dumps({"outcome": "allow", "results": []}),
                                                  issued.strftime(TS_FMT), issued.strftime(TS_FMT)))
            record("offer.create", "offer", oid, {"student": pid, "company": company}, actor={})

        with transaction():
            # Scenario students used in the demo and in the deck.
            offer("NFSU-25-CS-003", "Infosys", joining="pending", days_ago=60)            # B @ 7.5 -> needs >= 11.25
            offer("NFSU-25-DFIS-002", "CrowdStrike", joining="joined", days_ago=50)        # A+ -> out of process
            offer("NFSU-25-DFIS-004", "Deloitte", days_ago=58)                             # A -> A+ only
            offer("NFSU-25-DFIS-005", "KPMG", ppo="pending", days_ago=45)                  # I -> may apply F / I+F
            offer("NFSU-25-CS-001", "Palo Alto Networks", days_ago=38)                     # I+F -> out
            offer("NFSU-25-CSE-002", "TCS", days_ago=35)                                   # C -> higher category only
            offer("NFSU-25-AIDS-001", "Mastercard", days_ago=28)                           # B @ 9.5
            offer("NFSU-25-AIDS-002", "Mastercard", acceptance="declined", days_ago=28)
            offer("NFSU-25-MSCCS-001", "Mastercard", days_ago=28)
            offer("NFSU-25-CS-004", "KPMG", ppo="accepted", days_ago=45)                   # PPO accepted -> I+F
            offer("NFSU-25-CSE-001", "Deloitte", joining="joined", days_ago=58)
            offer("NFSU-25-DFIS-006", "Infosys", days_ago=60)
            offer("NFSU-25-DFIS-006", "KPMG", days_ago=45)                                 # F + I
            offer("NFSU-25-MSCCS-002", "Zscaler", off_campus=True, days_ago=20)            # off-campus with NOC
            offer("NFSU-25-CS-005", "Cisco", acceptance="pending", days_ago=0)             # pending, live countdown
            # Absenteeism: absent at the TCS test -> barred from the next three drives.
            execute("INSERT INTO applications (drive_id, student_id, status, decision, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                    (drive_id["TCS"], sid["NFSU-25-DFIS-003"], "rejected", json.dumps({"outcome": "allow", "results": []}), now_iso(), now_iso()))
            execute("INSERT INTO attendance (drive_id, student_id, event, status, recorded_at) VALUES (?,?,?,?,?)",
                    (drive_id["TCS"], sid["NFSU-25-DFIS-003"], "test", "absent", now_iso()))
            services.add_flag(sid["NFSU-25-DFIS-003"], "absenteeism",
                              "Absent from test at TCS (2026-09-05); barred from the next 3 drives unless an exception is approved.",
                              drive_id=drive_id["TCS"])
            # A few applications to open drives.
            for pid in ("NFSU-25-CS-002", "NFSU-25-CS-006", "NFSU-25-DFIS-001", "NFSU-25-CSE-003"):
                execute("INSERT INTO applications (drive_id, student_id, status, decision, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                        (drive_id["Microsoft"], sid[pid], "applied", json.dumps({"outcome": "allow", "results": []}), now_iso(), now_iso()))

        # ---- users (one per role)
        users = [
            ("admin", "Dr. Placement Administrator", "admin", None, None, None),
            ("officer", "Placement Officer", "officer", None, None, None),
            ("coord.dfis", "Coordinator — M.Sc. DFIS", "coordinator", "MSC_DFIS", None, None),
            ("recruiter.microsoft", "Microsoft Campus Team", "recruiter", None, "Microsoft", None),
            ("student.cs003", "Student — NFSU-25-CS-003", "student", None, None, "NFSU-25-CS-003"),
        ]
        with transaction():
            for username, display, role, scope, company, pid in users:
                company_id = query("SELECT id FROM companies WHERE name = ?", (company,), one=True)["id"] if company else None
                uid = execute("INSERT INTO users (username, display_name, password_hash, role, course_scope, company_id, student_id, created_at)"
                              " VALUES (?,?,?,?,?,?,?,?)", (username, display, hash_password(DEMO_PASSWORD), role, scope, company_id,
                                                            sid.get(pid), now_iso())).lastrowid
                record("user.create", "user", uid, {"username": username, "role": role}, actor={})
        get_db().execute("PRAGMA optimize")
        print(f"Seeded {len(sid)} students, {len(DRIVES)} drives and {len(users)} demo accounts.")
        print("Demo accounts: admin, officer, coord.dfis, recruiter.microsoft, student.cs003")
        print("Demo password (change for any shared deployment): " + DEMO_PASSWORD)


if __name__ == "__main__":
    main("--reset" in sys.argv)
