"""Application configuration and key management.

Secrets never live in the database. In production they are injected through
environment variables (PG_SECRET_KEY, PG_FIELD_KEY, ...) from a secrets manager;
for local development a key file is generated once under instance/ with
owner-only permissions.
"""
import json
import os
import secrets
import stat
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
KEY_NAMES = ("secret_key", "field_key", "index_key", "audit_key", "backup_key")


class Config:
    APP_ENV = os.environ.get("APP_ENV", "development")
    INSTANCE_DIR = os.environ.get("PG_INSTANCE_DIR", str(BASE_DIR / "instance"))
    DATABASE = os.environ.get("PG_DATABASE", str(Path(INSTANCE_DIR) / "placement.db"))

    # Transport: when served over TLS (default in run.py), cookies are Secure
    # and HSTS is sent. Plain HTTP is only for local development.
    HTTPS = os.environ.get("PG_HTTPS", "1") == "1"

    SESSION_IDLE_MINUTES = int(os.environ.get("PG_SESSION_IDLE_MINUTES", "15"))
    SESSION_ABSOLUTE_HOURS = int(os.environ.get("PG_SESSION_ABSOLUTE_HOURS", "8"))
    LOGIN_MAX_FAILURES = 5
    LOCKOUT_MINUTES = 15
    LOGIN_RATE_PER_MINUTE = 10

    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # upload ceiling (CSV import)
    TESTING = False
    DEBUG = False  # never expose the Werkzeug debugger


def load_keys(instance_dir: str) -> dict:
    """Return the five 32-byte application keys."""
    env = {n: os.environ.get("PG_" + n.upper()) for n in KEY_NAMES}
    if all(env.values()):
        raw = env
    else:
        path = Path(instance_dir) / "keys.json"
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
        else:
            raw = {n: secrets.token_hex(32) for n in KEY_NAMES}
            path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
            try:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
    keys = {}
    for name in KEY_NAMES:
        value = bytes.fromhex(raw[name])
        if len(value) < 32:
            raise RuntimeError(f"Key {name} must be at least 256 bits")
        keys[name] = value
    return keys
