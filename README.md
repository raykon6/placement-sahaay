# Placement Sahaay

A secure, policy-driven placement management system for the NFSU Placement Cell (2026–27 session), built for Problem Statement 2.

It keeps course-wise student records, runs every application and offer through an explainable rule engine based on the Student Placement Guidelines, protects contact and compensation data, and writes every sensitive action to a tamper-evident audit trail.

## Quick start

```bash
pip install -r requirements.txt
python scripts/seed.py          # demo data: 44 students, 13 drives, 5 accounts
python run.py --http            # http://127.0.0.1:5000  (local development; add --port 5050 to change)
python run.py                   # https://127.0.0.1:8443 (self-signed dev certificate)
python -m pytest -q tests       # 114 tests
```

Demo accounts (password `Demo-Placement-2026`; change it with `PG_DEMO_PASSWORD` before seeding any shared instance):

| Username | Role | Scope |
|---|---|---|
| `admin` | Placement Administrator | Everything, including policy, users and backups |
| `officer` | Placement Officer | Records, drives, offers, attendance, flags |
| `coord.dfis` | Course Coordinator | M.Sc. DFIS only |
| `recruiter.microsoft` | Company / Recruiter | Microsoft's drives and applicants only |
| `student.cs003` | Student | Own record (NFSU-25-CS-003) |

Suggested demo path: sign in as `admin`, open **Eligibility simulator**, and evaluate `NFSU-25-CS-003` (holds a B offer at ₹7.5 LPA) against a hypothetical F role at 9 LPA and 12 LPA. Then sign in as `student.cs003` and try to apply to Accenture.

## What is in the box

- **Self-registration**: students apply with their enrollment number and official e-mail (unique on the platform), can verify the e-mail with a one-time code, and are approved by their programme coordinator. Approved students sign in with their enrollment number or e-mail. Configure real e-mail with `PG_SMTP_HOST`, `PG_SMTP_PORT`, `PG_SMTP_USER`, `PG_SMTP_PASSWORD` and `PG_MAIL_FROM`; without these, messages go to a development outbox.
- **Student database**: search and filters, create, update, archive, retention-based anonymisation, and validated all-or-nothing CSV import.
- **Policy engine** (`app/policy.py`): seven rules (record, registration, eligibility, company criteria, attendance debarment, offer type, category switching) with a reason for each, and detection of conflicts within the guidelines.
- **Offers**: I, F and I+F offers, PPO, off-campus offers with NOC tracking, acceptance deadlines (24 h or the company's timeline, whichever is earlier) with automatic expiry, joining status, and reneging flags.
- **Reports**: university, course and batch outcomes; company-wise offers; highest, average and median CTC kept separate from monthly stipends; unique placed students counted separately from offers.
- **Security**: see [docs/TECHNICAL.md](docs/TECHNICAL.md).
- **Every feature, explained**: see [docs/FEATURE_GUIDE.md](docs/FEATURE_GUIDE.md), or **How it works** inside the app.

The interface follows the NFSU web style: navy utility bar, white masthead, navy page banners, gold accents, Poppins headings.

## Layout

```
app/
  policy.py        pure rule engine
  services.py      persistence and policy orchestration
  security.py      sessions, CSRF, RBAC, MFA, rate limiting, headers
  audit.py         HMAC hash-chained audit log
  crypto.py        AES-256-GCM fields, blind indexes, backup encryption
  validators.py    server-side input validation
  registration.py  self-registration, e-mail OTP, approval
  mailer.py        SMTP or development outbox
  backup.py        encrypted backup and verified restore
  routes/          auth, main (dashboard and portals), students, drives, offers, policy, reports, admin
  templates/ static/
scripts/           seed, restore_backup, gen_cert
tests/             test_policy, test_security, test_workflow, test_registration
docs/TECHNICAL.md  architecture, schema, controls, testing, limitations
docs/FEATURE_GUIDE.md  every feature and how it works
```
