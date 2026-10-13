# Placement Sahaay — Technical documentation

## 1. Architecture

```
Browser ── HTTPS ──> Flask app ──> Domain services ──> SQLite
 (server-rendered,     │ session manager       │            │ AES-256-GCM contact fields
  strict CSP)          │ CSRF / Origin check   │            │ append-only audit_log (triggers)
                       │ RBAC + object scope   └─> Policy engine (pure function)
                       │ validation
                       └─ keys loaded from the environment (or instance/keys.json in development)
```

- **Server-rendered UI.** Jinja2 auto-escapes all output. There is no inline JavaScript, and the CSP is `script-src 'self'`. JavaScript only adds conveniences: countdowns, confirmations, the mobile menu and bar widths. All decisions are made on the server.
- **Policy engine** (`app/policy.py`) is a pure function: `evaluate(student, drive, offers, debarred_by, settings) -> Decision`. It does no I/O, so it is deterministic and unit-tested in isolation. `services.evaluate()` loads data and calls it. The same call runs for the student portal, officer registration, offer entry and the simulator.
- **Derived, not stored.** Placement status, a drive's category and switching eligibility are computed from offer history. Nobody can tamper with them by editing a field, because no such field exists.

## 2. Database schema (`app/schema.sql`)

| Table | Purpose | Notable constraints |
|---|---|---|
| `students` | Profile, registration, eligibility, CGPA | `placement_id` UNIQUE (immutable once issued); `mobile_enc`/`email_enc` ciphertext; `*_index` UNIQUE keyed blind indexes; CHECK constraints on every enumeration |
| `companies` | Recruiters | name UNIQUE (case-insensitive) |
| `drives` | Recruitment drives | offer type I/F/IF; CTC range; category derived by the server; eligible programmes; minimum CGPA; response window |
| `applications` | Student ↔ drive | UNIQUE(drive, student); JSON snapshot of the policy decision, including any approved exception |
| `offers` | Offer events (never overwritten) | lifecycle fields acceptance / joining / PPO / NOC; `deadline_at`; `policy_outcome` at entry |
| `attendance` | Per-event attendance | UNIQUE(drive, student, event); exception reason |
| `flags` | Review queue | kind, detail, resolution, resolver |
| `policy_settings` | Configurable thresholds | JSON values; every change audited |
| `users` | Accounts | role CHECK; course or company or student scope; scrypt hash; encrypted TOTP secret; lockout counters |
| `sessions` | Server-side sessions | SHA-256 of the token only; CSRF token; UA hash; revocation flag |
| `audit_log` | Tamper-evident trail | `prev_hash`, `hash`; triggers reject UPDATE and DELETE |

## 3. Policy rules

| Rule | Outcome |
|---|---|
| R1 Record | Archived → block |
| R2 Registration | Not registered or deregistered → block |
| R3 Eligibility | Ineligible → block; pending → review |
| R4 Company criteria | Programme not eligible or CGPA below minimum → block; CGPA missing → review |
| R5 Attendance | An unexcused absence bars the next *N* (default 3) drives the student is eligible for → block |
| R6 Offer type | I→I block; F→F block (or review/allow when switching permits — see conflict mode); holding I+F (or an accepted PPO) → block at other organisations, review at the same one |
| R7 Category switching | Best FTE offer held: A+ → out of process; A → A+ only; B → ≥ 1.5× current CTC; C → higher category only |

The most severe outcome wins (block > review > allow). Every rule still reports, so the explanation is complete.

**Guideline conflict.** An FTE holder may satisfy R7 while R6 forbids another FTE-only role. `conflict_mode` decides what happens: `review` (default) refers the case to the Placement Cell, `strict` blocks, `switching` allows.

Offers are always recorded, because they are facts. If an offer breaks policy, it raises a `policy_violation` or `policy_conflict` flag. Final decisions stay with the Placement Cell.

## 4. Security controls

| Area | Implementation |
|---|---|
| Authentication | scrypt (Werkzeug) with per-hash salt; always runs the KDF to equalise timing; generic error; lockout after 5 failures for 15 min; 10 attempts/min per IP; RFC 6238 TOTP MFA with ±1-step drift and step-replay rejection; temporary passwords force a change |
| Authorisation | Permission sets per role (`security.PERMISSIONS`) checked by `@require`; object-level `can_access_student`; coordinators scoped to a programme, recruiters to a company, students to their own record (identity taken from the session, never the URL); per-role field allow-lists (mass-assignment defence); denials audited |
| Confidentiality | AES-256-GCM with AAD `students:<placement_id>:<column>`, so ciphertext cannot be moved between rows or columns; keyed HMAC blind indexes for duplicate detection; masked display by default; reveals are audited; recruiters get masked email only; HTTPS with HSTS; `Cache-Control: no-store` |
| Input and query | Allow-list validators for every field; only parameterised SQL (dynamic column names come from fixed lists); LIKE wildcards escaped; Jinja auto-escaping; CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`; 1 MB upload limit; open-redirect-safe `next` |
| CSRF | Synchroniser token per session, double-submit cookie before login, Origin/Referer check, SameSite=Strict cookies |
| Sessions | Random 256-bit token; only its hash is stored; new session ID on login and privilege change (prevents fixation); 15 min idle and 8 h absolute limits; User-Agent binding; logout and password change revoke sessions server-side; HttpOnly, Secure, `__Host-` prefix under HTTPS |
| Audit and integrity | `hash_n = HMAC(audit_key, hash_{n-1} ‖ canonical(entry_n))`; append-only triggers; written in the same transaction as the change; before/after values with masked PII; verifier pinpoints the first broken entry; optimistic concurrency on offer updates |
| Backup and recovery | SQLite online-backup snapshot → AES-256-GCM under a separate backup key; web "Verify restore" decrypts to a temporary file and checks `PRAGMA integrity_check` and the audit chain; `scripts/restore_backup.py` verifies before replacing the database |
| Export | Officer/admin only; contact columns admin-only; mandatory purpose; formula-injection neutralisation; SHA-256 of the file recorded in the audit log and sent as a header |
| Privacy and retention | Only the required fields; configurable retention period; anonymisation of archived records removes identifiers but keeps statistics; `secure_delete` pragma |

Keys: `secret_key`, `field_key`, `index_key`, `audit_key` and `backup_key` (256-bit each). In production they come from `PG_*` environment variables supplied by a secrets manager. In development they are generated once in `instance/keys.json` with owner-only permissions.

## 5. Testing

Run `python -m pytest -q tests`. All 86 tests pass, and the suite takes about 10 seconds.

- `test_policy.py` (34): category boundaries; A+/A/B/C switching, including 11.25 vs 11.24 LPA; I/F/I+F restrictions; PPO acting as I+F; conflict modes; declined-offer counting; registration, eligibility, CGPA and debarment; completeness of explanations.
- `test_security.py` (40): scrypt storage; lockout; uniform errors; rate limiting; SQL injection (login, search, filters); stored XSS; CSRF and cross-origin; IDOR; a student changing their own status or package; a forged apply request; acting for another student; coordinator and recruiter isolation; mass assignment; privilege escalation; MFA and replay; cookie flags; logout revocation; idle timeout; UA binding; session fixation; open redirect; encryption at rest; ciphertext swapping; contact-reveal logging; export controls; CSV injection; append-only audit; tamper detection; security headers; no leaked tracebacks; backup encryption and corruption detection; path traversal.
- `test_workflow.py` (12): officer registration under policy; recorded approval for review cases; three-drive debarment; excused absence; server-derived offer terms; deadline rule; expiry; reneging flag; unique-vs-offer statistics; audited policy change; anonymisation preserving statistics; guide access for every role.

## 6. Limitations

- SQLite and the in-process rate limiter assume a single server. Production should use PostgreSQL and a shared rate-limit store (for example Redis).
- Compensation fields are protected by access control and backup encryption, not field-level encryption (they are needed for aggregate statistics). Use storage-level encryption (TDE or an encrypted volume) in production.
- No outbound notifications (email or SMS) yet. Deadlines are shown in the interface and enforced automatically.
- Google Fonts are loaded from Google's CDN. For a fully offline deployment, self-host the font files and tighten the CSP.
- The demo seed uses a shared demo password and refuses to run when `APP_ENV=production`.
