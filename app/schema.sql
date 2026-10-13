-- PlacementGuard schema. Enumerations are enforced with CHECK constraints as a
-- second line of defence behind server-side validation.

CREATE TABLE IF NOT EXISTS companies (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS students (
    id                   INTEGER PRIMARY KEY,
    placement_id         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name            TEXT NOT NULL,
    -- Contact details: AES-256-GCM ciphertext + keyed blind index for
    -- duplicate detection + a masked form for low-privilege display.
    mobile_enc           TEXT NOT NULL,
    mobile_index         TEXT NOT NULL UNIQUE,
    mobile_masked        TEXT NOT NULL,
    email_enc            TEXT NOT NULL,
    email_index          TEXT NOT NULL UNIQUE,
    email_masked         TEXT NOT NULL,
    course               TEXT NOT NULL CHECK (course IN ('MTECH_CS','MTECH_AIDS','BTECH_MTECH_CSE','MSC_CS','MSC_DFIS')),
    batch                TEXT NOT NULL,
    registration_status  TEXT NOT NULL CHECK (registration_status IN ('registered','deregistered','not_registered')),
    eligibility_status   TEXT NOT NULL CHECK (eligibility_status IN ('eligible','ineligible','pending')),
    cgpa                 REAL CHECK (cgpa IS NULL OR (cgpa >= 0 AND cgpa <= 10)),
    remarks              TEXT,
    archived             INTEGER NOT NULL DEFAULT 0,
    anonymized           INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_students_course ON students(course, batch);

CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY,
    username              TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name          TEXT NOT NULL,
    password_hash         TEXT NOT NULL,
    role                  TEXT NOT NULL CHECK (role IN ('admin','officer','coordinator','recruiter','student')),
    course_scope          TEXT,
    company_id            INTEGER REFERENCES companies(id),
    student_id            INTEGER REFERENCES students(id),
    totp_secret_enc       TEXT,
    mfa_enabled           INTEGER NOT NULL DEFAULT 0,
    last_totp_step        INTEGER NOT NULL DEFAULT 0,
    must_change_password  INTEGER NOT NULL DEFAULT 0,
    failed_attempts       INTEGER NOT NULL DEFAULT 0,
    locked_until          TEXT,
    active                INTEGER NOT NULL DEFAULT 1,
    created_at            TEXT NOT NULL,
    last_login_at         TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY,
    token_hash    TEXT NOT NULL UNIQUE,      -- SHA-256 of the cookie token
    user_id       INTEGER NOT NULL REFERENCES users(id),
    stage         TEXT NOT NULL CHECK (stage IN ('mfa','full')),
    csrf_token    TEXT NOT NULL,
    ua_hash       TEXT NOT NULL,
    ip            TEXT,
    created_at    TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    revoked       INTEGER NOT NULL DEFAULT 0,
    flash         TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS drives (
    id                INTEGER PRIMARY KEY,
    company_id        INTEGER NOT NULL REFERENCES companies(id),
    title             TEXT NOT NULL,
    offer_type        TEXT NOT NULL CHECK (offer_type IN ('I','F','IF')),
    ctc_lpa           REAL CHECK (ctc_lpa IS NULL OR (ctc_lpa > 0 AND ctc_lpa <= 500)),
    stipend_amount    REAL CHECK (stipend_amount IS NULL OR stipend_amount >= 0),
    stipend_period    TEXT CHECK (stipend_period IS NULL OR stipend_period IN ('month','total')),
    category          TEXT CHECK (category IS NULL OR category IN ('A+','A','B','C')),
    eligible_courses  TEXT NOT NULL,
    min_cgpa          REAL,
    drive_date        TEXT NOT NULL,
    response_hours    INTEGER NOT NULL DEFAULT 24 CHECK (response_hours BETWEEN 1 AND 720),
    status            TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
    created_by        INTEGER REFERENCES users(id),
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS applications (
    id          INTEGER PRIMARY KEY,
    drive_id    INTEGER NOT NULL REFERENCES drives(id),
    student_id  INTEGER NOT NULL REFERENCES students(id),
    status      TEXT NOT NULL CHECK (status IN ('applied','shortlisted','selected','rejected','withdrawn')),
    decision    TEXT NOT NULL,               -- policy decision snapshot (JSON)
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (drive_id, student_id)
);

-- Offers are events: they are never overwritten or deleted, only their
-- lifecycle fields move forward, and every move is audited.
CREATE TABLE IF NOT EXISTS offers (
    id              INTEGER PRIMARY KEY,
    student_id      INTEGER NOT NULL REFERENCES students(id),
    drive_id        INTEGER REFERENCES drives(id),
    company_id      INTEGER NOT NULL REFERENCES companies(id),
    offer_type      TEXT NOT NULL CHECK (offer_type IN ('I','F','IF')),
    category        TEXT CHECK (category IS NULL OR category IN ('A+','A','B','C')),
    ctc_lpa         REAL CHECK (ctc_lpa IS NULL OR (ctc_lpa > 0 AND ctc_lpa <= 500)),
    stipend_amount  REAL CHECK (stipend_amount IS NULL OR stipend_amount >= 0),
    stipend_period  TEXT CHECK (stipend_period IS NULL OR stipend_period IN ('month','total')),
    offer_date      TEXT NOT NULL,
    deadline_at     TEXT NOT NULL,
    acceptance      TEXT NOT NULL DEFAULT 'pending' CHECK (acceptance IN ('pending','accepted','declined','expired')),
    joining         TEXT NOT NULL DEFAULT 'pending' CHECK (joining IN ('pending','joined','not_joined')),
    ppo_status      TEXT NOT NULL DEFAULT 'na' CHECK (ppo_status IN ('na','pending','offered','accepted','declined')),
    off_campus      INTEGER NOT NULL DEFAULT 0,
    noc_status      TEXT NOT NULL DEFAULT 'na' CHECK (noc_status IN ('na','requested','issued','rejected')),
    policy_outcome  TEXT NOT NULL,
    remarks         TEXT,
    created_by      INTEGER REFERENCES users(id),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_offers_student ON offers(student_id);

CREATE TABLE IF NOT EXISTS attendance (
    id                INTEGER PRIMARY KEY,
    drive_id          INTEGER NOT NULL REFERENCES drives(id),
    student_id        INTEGER NOT NULL REFERENCES students(id),
    event             TEXT NOT NULL CHECK (event IN ('ppt','test','gd','interview','other')),
    status            TEXT NOT NULL CHECK (status IN ('present','absent','excused')),
    exception_reason  TEXT,
    recorded_by       INTEGER REFERENCES users(id),
    recorded_at       TEXT NOT NULL,
    UNIQUE (drive_id, student_id, event)
);

CREATE TABLE IF NOT EXISTS flags (
    id           INTEGER PRIMARY KEY,
    student_id   INTEGER NOT NULL REFERENCES students(id),
    offer_id     INTEGER REFERENCES offers(id),
    drive_id     INTEGER REFERENCES drives(id),
    kind         TEXT NOT NULL CHECK (kind IN ('policy_violation','policy_conflict','absenteeism','offer_expired','duplicate_suspect')),
    detail       TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved','dismissed')),
    created_at   TEXT NOT NULL,
    resolved_by  INTEGER REFERENCES users(id),
    resolved_at  TEXT,
    resolution   TEXT
);

CREATE TABLE IF NOT EXISTS policy_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    updated_by  INTEGER REFERENCES users(id)
);

-- Tamper-evident, append-only audit trail. Each row carries an HMAC over the
-- previous row's hash plus its own canonical content (a keyed hash chain).
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    actor_id   INTEGER,
    actor      TEXT NOT NULL,
    role       TEXT NOT NULL,
    action     TEXT NOT NULL,
    entity     TEXT,
    entity_id  TEXT,
    detail     TEXT NOT NULL,
    ip         TEXT,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_entity ON audit_log(entity, entity_id);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
