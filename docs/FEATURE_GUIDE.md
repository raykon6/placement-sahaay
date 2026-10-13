# Placement Sahaay — Feature guide

This guide explains every feature of Placement Sahaay: what it does, who can use it, and how it works behind the scenes. A shorter version is built into the app under **How it works**.

Contents

1. [What Placement Sahaay is](#1-what-placement-sahaay-is)
2. [Roles and what each one sees](#2-roles-and-what-each-one-sees)
3. [Signing in and account security](#3-signing-in-and-account-security)
4. [Layout and navigation](#4-layout-and-navigation)
5. [Dashboard](#5-dashboard)
6. [Students](#6-students)
7. [Recruitment drives](#7-recruitment-drives)
8. [Offers](#8-offers)
9. [The rule engine in depth](#9-the-rule-engine-in-depth)
10. [Review queue](#10-review-queue)
11. [Eligibility simulator](#11-eligibility-simulator)
12. [Placement rules and policy settings](#12-placement-rules-and-policy-settings)
13. [Reports and secure export](#13-reports-and-secure-export)
14. [Audit trail](#14-audit-trail)
15. [Users and roles](#15-users-and-roles)
16. [Backups and recovery](#16-backups-and-recovery)
17. [Student portal](#17-student-portal)
18. [Recruiter portal](#18-recruiter-portal)
19. [Security mechanisms behind the scenes](#19-security-mechanisms-behind-the-scenes)
20. [How data flows through the system](#20-how-data-flows-through-the-system)
21. [Testing](#21-testing)
22. [Five-minute demo script](#22-five-minute-demo-script)

---

## 1. What Placement Sahaay is

Placement Sahaay ("placement helper") is the system of record for the NFSU Training & Placement Cell for the 2026–27 session. It covers five programmes: M.Tech. CS, M.Tech. AIDS, B.Tech.–M.Tech. CSE, M.Sc. CS and M.Sc. DFIS.

It does four jobs:

1. **Keeps records.** Students, drives, applications, attendance and offers. Offer history is never overwritten.
2. **Enforces the guidelines.** Every application, registration and offer passes through a rule engine that encodes the Student Placement Guidelines 2026–27 and explains its decision.
3. **Protects data.** Contact details are encrypted. Each role sees only what it needs. Every sensitive action is logged in a tamper-evident audit trail.
4. **Reports reliably.** Dashboards and reports count unique placed students separately from offers, and keep internship stipends separate from annual CTC.

The system flags suspected violations, but it does not punish anyone. Final decisions on exceptions and discipline stay with the Placement Cell.

---

## 2. Roles and what each one sees

| Role | Typical user | Scope | Can do |
|---|---|---|---|
| **Placement Administrator** | Head of the Placement Cell | Everything | All officer functions, plus policy settings, user accounts, backups, and exports that include contact details |
| **Placement Officer** | Placement Cell staff | All programmes | Manage students, drives, attendance and offers; resolve flags; export without contact details; read the audit trail |
| **Course Coordinator** | Faculty for one programme | One programme | Read students, offers and drives of their programme; verify eligibility and CGPA; use the simulator |
| **Company / Recruiter** | Company HR | One company | See only their company's drives and applicants (name, programme, masked email); shortlist or select |
| **Student** | Each registered student | Own record | View own record and offers; see an explained eligibility decision for each open drive; apply |

The server checks permissions on every request. The interface hides buttons a role cannot use, but that is only a convenience. Hiding a button is not what secures it.

**Demo accounts** (password `Demo-Placement-2026`): `admin`, `officer`, `coord.dfis`, `recruiter.microsoft`, `student.cs003`.

---

## 3. Signing in and account security

### Sign in
- Enter your username and password. If either is wrong, the message is always the same ("Incorrect username or password"), so attackers cannot find out which usernames exist.
- **Lockout:** five failed attempts lock the account for 15 minutes. Each IP address is also limited to 10 sign-in attempts per minute. Every failure is written to the audit trail.
- **Timing:** the password check takes the same time whether or not the user exists, so response time leaks nothing either.

### Two-step verification (MFA)
1. Go to **Account security → Set up MFA**.
2. Add the displayed key to any authenticator app (Google Authenticator, Microsoft Authenticator, Authy).
3. Enter the 6-digit code to confirm.

From then on, sign-in asks for a code after the password. Codes change every 30 seconds. Each code works only once, so a code someone captured cannot be replayed. The secret key is stored encrypted. Administrators and officers who have not enabled MFA see a reminder after every sign-in.

### Passwords
- New passwords must be 12–128 characters, must not contain the username, must not be a common password, and must not be overly repetitive.
- Changing your password signs out all your other sessions.
- Accounts created or reset by an administrator get a one-time temporary password and must set a new one at first sign-in.

### Sessions
- A session ends after **15 minutes of inactivity** or **8 hours** in total, whichever comes first.
- **Sign out** destroys the session on the server, not just in your browser.
- A session is tied to the browser that created it. If its cookie is copied into another browser, the session is revoked.

---

## 4. Layout and navigation

The layout follows the NFSU web style: a navy utility bar, a white masthead and navy page banners.

- **Utility bar (top):** institution name, signed-in user and role, **Account security** and **Sign out**.
- **Masthead:** the Placement Sahaay brand and the main menu. Staff see **Dashboard**, **Records** (Students, Recruitment drives, Offers, Reports), **Policy** (Review queue, Eligibility simulator, Placement rules, Policy settings), **Governance** (Secure export, Audit trail, Users and roles, Backups) and **How it works**. Students and recruiters see a shorter menu.
- **Page banner:** the page title with a gold double rule, breadcrumbs and page actions.
- **Keyboard:** every control has a visible focus ring. **Esc** closes open menus. A "Skip to main content" link appears on the first Tab press.
- **Small screens:** the menu collapses behind a **Menu** button.

---

## 5. Dashboard

**Who:** Admin, Officer, and Coordinator (Coordinators see only their own programme). Admins and officers can filter by programme.

| Widget | What it shows | How it is calculated |
|---|---|---|
| Registered / Eligible / Ineligible | Headcounts | From each student's registration and eligibility status (archived records excluded) |
| Placed (unique) / Unplaced | Students with at least one **accepted** offer | Counted per student, not per offer |
| Offers issued | Total offers and how many students received them | Shows the gap between offers and unique students |
| Placement status bar | I+PPO/F, FTE only, internship only, unplaced | Derived from the types of accepted offers. An internship with an accepted PPO counts as I+F |
| Annual FTE CTC | Highest, average and median LPA | F and I+F offers, declined offers excluded |
| Monthly stipend | Highest, average and median ₹ per month | Internship offers paid monthly. Never mixed with CTC |
| Needs attention | Offers awaiting acceptance (with live countdown), joining pending, open flags | Pending offers are expired automatically when their deadline passes |
| Course- and batch-wise outcomes | Registered, placed, rate, counts by type, offers | One row per programme and batch |
| Company-wise offers | Categories, offer types, highest CTC, number of offers | Grouped by company |
| Eligibility for subsequent drives | How many students fall under each switching window | e.g. "Out of process (A+)", "A+ only", "≥ ₹11.25 LPA" |

---

## 6. Students

### List and search
**Records → Students.** Search by name or Placement ID, and filter by programme, batch, registration, eligibility, placement status, or archived only. Each row shows the student's derived placement status and **next-drive window**, which is what the switching rules still allow them to apply for. Coordinators see only their own programme.

### Adding a student
**Add student** (Admin, Officer). Each field is checked on the server:

| Field | Rule |
|---|---|
| Placement ID | 4–24 characters (A–Z, 0–9, hyphen), unique, **cannot be changed once issued** |
| Full name | Letters, spaces, `.`, `'` and `-` only (markup is rejected) |
| Mobile | Valid 10-digit Indian number. `+91` and spaces are accepted and normalised |
| Email | Valid address, stored in lowercase |
| Programme | One of the five programmes |
| Batch | e.g. `2025-27` or `2025-2027` |
| Registration | Registered, deregistered or not registered |
| Eligibility | Eligible, ineligible or pending verification |
| CGPA | 0–10, optional |

**Duplicate detection:** Placement ID, mobile and email must each be unique. Mobile and email are stored encrypted, so they are compared through a keyed fingerprint (a "blind index") instead of decrypting every record.

### Student record page
- **Placement position:** registration, eligibility, CGPA, and what the student may still apply for.
- **Offer history:** every offer with type, category, package, date, acceptance (with live countdown) and joining. Offers link to their detail page.
- **Eligibility for open drives:** a live decision panel for each open drive the programme qualifies for. Expand a panel to see all seven rule results.
- **Applications and attendance:** past applications and attendance per event, including excused absences and their reasons.
- **Contact:** mobile and email are **masked by default**. **Reveal contact details** shows them once and writes a `student.contact_view` entry to the audit trail.
- **Policy flags** for this student, and **recent audit entries** (for roles that can read the audit trail).

### Editing
- Admins and officers can edit every field except the Placement ID.
- Coordinators can edit **only** eligibility status and CGPA. Any other field sent in the request is ignored, which prevents mass assignment.
- Placement status and packages cannot be edited here at all. They come from the offer records.
- Every change is audited with masked before/after values.

### Archive, restore and anonymise
- **Archive** (Admin, Officer, with a reason): removes the student from active lists and reports. **Restore** reverses it.
- **Anonymise** (Admin only, archived records only, with a reason): permanently replaces the name and contact details and disables the student's login. Offers and statistics are kept, which supports retention policies without corrupting historical figures.

### CSV import
**Records → Students → Import CSV** (Admin, Officer).
- Header must be exactly: `placement_id,full_name,mobile,email,course,batch,registration_status,eligibility_status,cgpa`
- UTF-8, at most 1 MB and 2,000 rows.
- Every row is validated and checked for duplicates, both against the database and within the file.
- **All-or-nothing:** if any row fails, nothing is imported, and a table lists each problem with its row number.
- A successful import is audited with the row count and the SHA-256 fingerprint of the file.

---

## 7. Recruitment drives

### Creating a drive
**Records → Recruitment drives → New drive** (Admin, Officer). Fields: company, role title, offer type (I, F or I+F), annual CTC (required for F and I+F), stipend and period (for I and I+F), eligible programmes, minimum CGPA, drive date, and company response window in hours.

The **category is computed by the server** from the CTC (A+ ≥ 16, A 10–16, B 6–10, C < 6 LPA). It cannot be typed in.

### Drive page
- **Applicants:** each applicant's live policy decision, next to the decision recorded when they applied (including any approved exception).
- **Application status:** applied, shortlisted, selected, not selected or withdrawn.
- **Register a student:** enter a Placement ID. The rule engine decides:
  - **Allowed:** the student is registered.
  - **Blocked:** registration is refused with the reason, and the refusal is audited.
  - **Manual review:** a "Placement Cell approval" box appears. Registration goes through only after a reason of at least 10 characters is recorded. The approval is stored with the application and in the audit trail.
- **Record attendance:** pick the event (pre-placement talk, test, group discussion, interview, other) and mark each applicant present, absent or excused.
  - **Absent** raises an absenteeism flag. The student is then barred from their next three eligible drives (configurable).
  - **Excused** is an emergency exception. Only officers and admins can record it, and it needs a reason of at least 10 characters. It lifts the bar.
  - The whole form is validated before anything is saved. One bad row means nothing is written.
- **Close / reopen** the drive. Students can apply only to open drives.

---

## 8. Offers

### Recording an offer
**Records → Offers → Record offer**, or **Record offer** from a student or drive page.
- **Campus offer:** choose the drive. Offer type, CTC and stipend are **copied from the drive record**. Values sent from the browser are ignored, so nobody can inflate a package by editing the form.
- **Off-campus offer:** leave the drive empty and enter the company, type and package. An **NOC request** is opened automatically.
- **Category** is computed from the CTC.
- **Acceptance deadline** = the offer's issue time plus **24 hours or the company's response window, whichever is earlier**.
- **Policy check:** the rule engine evaluates the offer. Offers are facts, so they are always recorded. If policy would have blocked it, a **suspected violation** flag is raised. If it needs review, a **guideline conflict** flag is raised. The outcome is stored on the offer as "Policy at entry".
- If the offer came from a drive, the student's application is marked **selected**.

### Updating an offer
On the offer page, officers can update:

| Field | Values | Rules |
|---|---|---|
| Acceptance | Pending → Accepted / Declined; Accepted → Declined | Cannot accept after the deadline. Declined and expired are final. Declining an accepted offer (**reneging**) raises a violation flag |
| Joining | Pending, joined, not joined | Only for accepted offers |
| PPO status | Not applicable, pending, offered, accepted, declined | Internship offers only. **An accepted PPO makes the student I+F** for policy purposes |
| NOC status | Not applicable, requested, issued, rejected | Off-campus offers only |

Every update needs a reason. It is written to the audit trail with before and after values, and shown in the offer's **Change history**. If someone else changed the offer at the same moment, the update is rejected and you are asked to reload (optimistic locking).

### Automatic expiry
Each time the dashboard, offers pages or student portal load, pending offers past their deadline are set to **Expired**. The change is audited and flagged.

---

## 9. The rule engine in depth

The engine is a single function, `evaluate(student, drive, offers, debarment, settings)`, in `app/policy.py`. It never reads or writes the database, which makes it predictable and easy to test. The same function runs in five places: the student portal, officer registration, offer entry, the drive applicant list and the simulator.

**Which offers count as a "selection":** all offers by default, including declined and expired ones, so that declining does not reset a student's position. The administrator can change this.

### The seven rules

| # | Rule | Blocks when | Review when |
|---|---|---|---|
| R1 | Record status | Record is archived | — |
| R2 | Registration | Not registered, or deregistered | — |
| R3 | Eligibility | Marked ineligible | Verification pending |
| R4 | Company criteria | Programme not eligible for the drive, or CGPA below the minimum | CGPA not on record but required |
| R5 | Attendance | An unexcused absence bars this drive (one of the next *N* eligible drives after the absence) | — |
| R6 | Offer type | I → another I; F → another F; holding I+F (or an accepted PPO) → any role at another organisation | Holding I+F and the new drive is from the same organisation; or the F→F conflict (below) |
| R7 | Category switching | Best FTE offer is A+ (out of the process, even for internships); A holder → non-A+ drive; B holder → new CTC below 1.5× current; C holder → drive not in a higher category | Drive has no CTC, so its category is unknown |

**Outcome:** the most severe result wins (Blocked > Manual review > Allowed). Every rule still reports, so the explanation is always complete.

### Worked examples (demo data)

| Student | Holds | Drive | Result | Why |
|---|---|---|---|---|
| NFSU-25-CS-003 | F, ₹7.5 LPA (B) | Accenture F ₹9 LPA | Blocked | R6: second FTE-only role. R7: below 1.5× (₹11.25) |
| NFSU-25-CS-003 | F, ₹7.5 LPA (B) | Google I+F ₹20 LPA | Allowed | I+F is not FTE-only; ₹20 ≥ ₹11.25 |
| NFSU-25-CS-003 | F, ₹7.5 LPA (B) | Microsoft F ₹24 LPA | Manual review | Guideline conflict (see below) |
| NFSU-25-DFIS-002 | F, ₹18 LPA (A+) | Any | Blocked | A+ exits the process |
| NFSU-25-DFIS-004 | F, ₹12 LPA (A) | Cisco F ₹13 LPA | Blocked | A holders may switch to A+ only |
| NFSU-25-DFIS-005 | Internship (KPMG) | EY internship | Blocked | No second internship-only role |
| NFSU-25-DFIS-003 | No offers; absent at TCS test | Next 3 eligible drives | Blocked | Absence debarment |

### The guideline conflict
The guidelines say that an FTE holder "cannot apply for another FTE-only role". They also allow A holders to switch to A+, and B holders to switch at 1.5×. When a student with an FTE offer meets the switching condition for another FTE-only role, the two rules disagree. The engine does not guess. Its behaviour follows the **conflict mode** setting:

- **Refer to Placement Cell** (default): outcome is Manual review, with an explanation.
- **Block:** the offer-type rule wins.
- **Allow:** the switching rule wins.

---

## 10. Review queue

**Policy → Review queue** (Admin and Officer resolve; Coordinators can view their programme's flags). It is filtered by Open, Resolved or Dismissed.

| Flag | Raised when |
|---|---|
| Suspected violation | An offer was recorded that policy would block, or a student reneged on an accepted offer |
| Guideline conflict | An offer needs manual review |
| Absenteeism | A student was marked absent at a recruitment event |
| Offer expired | A pending offer passed its deadline without a response |

To **Resolve** or **Dismiss** a flag you must record the Placement Cell's decision (at least 10 characters). The resolver, the time and the decision are stored and audited. Duplicate open flags for the same situation are suppressed.

---

## 11. Eligibility simulator

**Policy → Eligibility simulator** (Admin, Officer, Coordinator for own programme). It answers "can this student sit for this opportunity, and why?" without saving anything.

1. Enter a Placement ID.
2. Choose **Hypothetical** (pick an offer type and CTC) or **Existing drive**.
3. Select **Evaluate**. You get the decision panel with all seven rules, plus a table of the offers the engine considered.

Use it to answer student queries, plan drives ("how many students could sit for a ₹12 LPA FTE role?"), and explain policy in meetings.

---

## 12. Placement rules and policy settings

**Placement rules** (all roles) shows the category table, offer-type restrictions, evaluation order, how conflicts are handled and the operational rules, using the **current** thresholds.

**Policy settings** (Admin only) holds the configurable values:

| Setting | Default |
|---|---|
| A+ / A / B thresholds (LPA, inclusive lower bound) | 16 / 10 / 6 |
| B-category switch multiplier | 1.5 |
| Drives barred after an unexcused absence | 3 |
| Default acceptance window (hours) | 24 |
| Declined / expired offers still count as a selection | Yes |
| F→F conflict resolution | Refer to Placement Cell |
| Retention period for archived records (years) | 5 |

Saving requires a **guideline reference or reason**. The server checks ranges and requires A+ > A > B. Changes take effect immediately and are audited with before and after values.

---

## 13. Reports and secure export

### Reports
**Records → Reports.** One table row per programme, with a university total: registered, eligible, placed, unplaced, I / F / I+PPO/F counts, offers, highest and median CTC, and average monthly stipend. Below the table are summary tiles for average CTC, unique placed vs offers, and pending compliance. The **Print** button produces a clean, print-styled report.

### Secure export
**Governance → Secure export** (Admin, Officer).
- **Datasets:** student register, or offers and compensation.
- **Contact columns** (mobile and email) can be included **only by the Administrator**.
- A **purpose** is mandatory.
- Cells starting with `=`, `+`, `-` or `@` are prefixed so spreadsheets cannot run them as formulas (CSV injection).
- Each export is audited with the dataset, row count, purpose and the **SHA-256 fingerprint** of the file, so a copy found later can be traced to the exact export.

---

## 14. Audit trail

**Governance → Audit trail** (Admin, Officer). You can filter by action prefix (e.g. `student.`, `auth.`, `offer.`) or by actor.

**What is logged:** sign-ins, failures, lockouts and MFA events; access denials; contact reveals; every create, update, archive and anonymise; applications and refusals; attendance; offers and their updates; flags and their resolutions; policy changes; user administration; exports; backups and verifications. Each entry holds the time, actor, role, IP, action, entity and details (before/after values, with personal data masked).

**How tampering is detected:** each entry's hash is an HMAC over the previous entry's hash plus its own content:

```
hash(n) = HMAC-SHA256(audit_key, hash(n-1) || entry(n))
```

- Changing, deleting, inserting or reordering any entry breaks every later link.
- Database triggers reject `UPDATE` and `DELETE` on the audit table.
- The HMAC key lives outside the database, so someone with only the database file cannot rebuild a valid chain.

**Verify integrity** re-computes the whole chain. It reports either "Chain intact (N entries, head hash …)" or the exact entry where tampering was detected.

---

## 15. Users and roles

**Governance → Users and roles** (Admin only).
- **Create account:** username, display name and role. Coordinators must be linked to a programme, recruiters to a company, and students to an existing Placement ID (one account per student). A **temporary password is shown once**, is never stored in readable form, and must be changed at first sign-in.
- **Reset password:** issues a new temporary password and ends the user's sessions.
- **Deactivate / Reactivate:** blocks or restores sign-in and ends sessions. You cannot deactivate yourself.
- **Unlock:** clears a lockout.
- The list shows each user's status, MFA state and last sign-in. All actions are audited.

---

## 16. Backups and recovery

**Governance → Backups** (Admin only).
- **Create backup now:** takes a consistent snapshot of the database and encrypts it with AES-256-GCM under a separate backup key. If the file is altered, decryption fails.
- **Verify restore:** decrypts the backup into a temporary copy, runs SQLite's integrity check, counts the records and verifies the audit chain. This proves the backup is restorable without touching live data.
- **Full restore** runs offline, from the command line: `python scripts/restore_backup.py <file>`. It verifies the backup first, keeps the current database as `*.pre-restore`, then restores.
- Backup file names are validated, so path tricks like `../` are rejected.

---

## 17. Student portal

**My placement** (students only).
- **My record:** registration, eligibility, the student's own contact details, and what they may still apply for.
- **Open drives for your programme:** each drive with a decision panel. Students see exactly which rule allows or blocks them, in the same words staff see.
  - **Allowed** → **Apply** button (asks for confirmation; attendance at all recruitment events becomes mandatory).
  - **Manual review** → "Contact the Placement Cell".
  - **Blocked** → "Not available under the placement policy".
- **My offers:** each offer with acceptance status, a countdown to the deadline, and joining status.

**What students cannot do:** change any record, status or package; view anyone else's record; or apply when the rules forbid it. The student's identity comes from their session, never from the URL. Every Apply request is checked again on the server, and refusals are logged.

---

## 18. Recruiter portal

**My drives** (recruiters only).
- A list of the recruiter's own company's drives, with applicant counts.
- A drive's applicants show name, Placement ID, programme, batch and **masked email** only. Mobile numbers, other companies' packages and placement history are never shown.
- The recruiter can mark candidates **Shortlisted**, **Selected** or **Not selected**. Offers themselves are recorded by the Placement Cell.
- Opening another company's drive is refused and logged.

---

## 19. Security mechanisms behind the scenes

| Threat | Defence in Placement Sahaay |
|---|---|
| Password theft from a database leak | scrypt (memory-hard) hashing with a per-user salt |
| Brute-force sign-in | Lockout after 5 failures, per-IP rate limit, audit |
| Stolen password | Optional TOTP second factor with replay protection |
| Session hijacking | Random 256-bit tokens with only their hash stored; HttpOnly, SameSite=Strict, Secure cookies; browser binding; idle and absolute timeouts; revocation |
| Session fixation | A new session ID is issued at sign-in and on every privilege change |
| Cross-site request forgery | Per-session CSRF token on every form, plus an Origin/Referer check |
| SQL injection | Only parameterised queries; filter values checked against allow-lists |
| Cross-site scripting | Automatic output escaping, a strict Content Security Policy (no inline scripts), and name validation |
| IDOR (viewing others' data) | Object-level checks on every record; identity from the session; scoped roles |
| Privilege escalation / mass assignment | Permission checks per action; field allow-lists per role; server-derived fields |
| Data exposure | AES-256-GCM encryption of contact data, bound to its record and column; masking by default; logged reveals; HTTPS with HSTS; no-store caching |
| Tampering with history | Append-only, hash-chained audit trail; offer history never overwritten |
| Spreadsheet attacks | CSV formula neutralisation on export |
| Clickjacking / embedding | `X-Frame-Options: DENY` and `frame-ancestors 'none'` |
| Open redirects | The post-sign-in `next` parameter accepts only same-site relative paths |
| Data loss | Encrypted backups with automated restore verification |
| Information leaks via errors | Generic error pages; debug mode always off |

Keys (session, field encryption, blind index, audit and backup) are held outside the database. In production they come from environment variables.

---

## 20. How data flows through the system

```
Browser form ─▶ CSRF + session check ─▶ permission + scope check ─▶ server-side validation
      ─▶ domain service ─▶ rule engine (pure) ─▶ database write + audit entry in ONE transaction
      ─▶ flags raised if needed ─▶ dashboards and reports read derived values
```

A change and its audit record are always committed together. If either fails, both are rolled back.

---

## 21. Testing

Run `python -m pytest -q tests`. There are 86 automated tests:

- **Policy engine (34):** every category boundary, including ₹11.25 vs ₹11.24 for the 1.5× rule; all offer-type combinations; PPO as I+F; conflict modes; declined-offer counting; registration, eligibility, CGPA and debarment rules.
- **Security (40):** real attacks against the running app: SQL injection, stored XSS, CSRF, cross-origin posts, IDOR, a student changing their own status, forged applications, mass assignment, privilege escalation, session fixation and replay, idle timeout, browser binding, MFA replay, lockout, rate limiting, encryption at rest, ciphertext swapping, export controls, CSV injection, audit tampering, backup corruption and path traversal.
- **Workflows (12):** registration under policy, recorded approvals, debarment and exceptions, server-derived offer terms, deadline rule, expiry, reneging, statistics, audited policy changes, anonymisation, and guide access for every role.

---

## 22. Five-minute demo script

1. **Sign in as `admin`.** Show the dashboard: unique placed vs offers, separate CTC and stipend figures, the live countdown.
2. **Policy → Eligibility simulator:** `NFSU-25-CS-003`, hypothetical F at ₹9 LPA → Blocked (two reasons). Change to I+F at ₹20 → Allowed.
3. **Records → Students → NFSU-25-CS-003:** expand the Microsoft panel → Manual review (guideline conflict). Select **Reveal contact details** → "Access logged".
4. **Records → Recruitment drives → Quick Heal:** register `NFSU-25-DFIS-006` → review required; enter an approval → registered with the approval stored.
5. **Sign in as `student.cs003`** (another browser or a private window). Try to apply to Accenture → refused and logged. Note there is no way to edit anything.
6. **Back as admin → Governance → Audit trail → Verify integrity** → "Chain intact".
7. **Governance → Backups → Create backup → Verify restore** → integrity OK, chain intact.
