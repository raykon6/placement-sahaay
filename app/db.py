"""SQLite access layer.

Every statement in the application goes through these helpers with bound
parameters; SQL text is never assembled from user input.
"""
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import click
from flask import current_app, g


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)  # explicit transactions
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA secure_delete = ON")  # overwrite freed pages
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def query(sql: str, params=(), one: bool = False):
    cur = get_db().execute(sql, params)
    rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql: str, params=()):
    return get_db().execute(sql, params)


@contextmanager
def transaction():
    """Serialised write transaction (BEGIN IMMEDIATE takes the write lock up
    front, which also keeps the audit hash chain strictly ordered)."""
    conn = get_db()
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def init_schema(conn: sqlite3.Connection):
    schema = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")
    conn.executescript(schema)
    _migrate(conn)


def _migrate(conn: sqlite3.Connection):
    """Additive, idempotent migrations for databases created by earlier versions."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(students)")}
    if "enrollment_no" not in cols:
        conn.execute("ALTER TABLE students ADD COLUMN enrollment_no TEXT COLLATE NOCASE")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_students_enrollment ON students(enrollment_no)"
                 " WHERE enrollment_no IS NOT NULL")


def init_app(app):
    app.teardown_appcontext(close_db)

    @app.cli.command("init-db")
    def init_db_command():
        """Create tables (idempotent)."""
        init_schema(get_db())
        click.echo("Database initialised.")
