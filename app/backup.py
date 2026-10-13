"""Encrypted backups and verified restoration.

Backups are consistent SQLite snapshots (online backup API), encrypted and
authenticated with AES-256-GCM under a dedicated backup key. Verification
decrypts into a temporary file and checks SQLite integrity plus the audit
hash chain, proving the backup is restorable before anyone relies on it.
"""
import hashlib
import os
import re
import sqlite3
import tempfile
from pathlib import Path

from .audit import verify_chain
from .constants import now_iso
from .crypto import decrypt_backup, encrypt_backup

NAME_RE = re.compile(r"^placement-\d{8}T\d{6}Z\.db\.enc$")


def backup_dir(instance_dir: str) -> Path:
    path = Path(instance_dir) / "backups"
    path.mkdir(exist_ok=True)
    return path


def create_backup(db_path: str, instance_dir: str, key: bytes) -> dict:
    fd, tmp = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        src = sqlite3.connect(db_path)
        dst = sqlite3.connect(tmp)
        with dst:
            src.backup(dst)
        src.close()
        dst.close()
        data = Path(tmp).read_bytes()
    finally:
        os.remove(tmp)
    blob = encrypt_backup(data, key)
    name = "placement-" + now_iso().replace("-", "").replace(":", "") + ".db.enc"
    out = backup_dir(instance_dir) / name
    out.write_bytes(blob)
    return {"name": name, "bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}


def list_backups(instance_dir: str) -> list:
    items = []
    for p in sorted(backup_dir(instance_dir).iterdir(), reverse=True):
        if NAME_RE.match(p.name):
            items.append({"name": p.name, "bytes": p.stat().st_size})
    return items


def resolve(instance_dir: str, name: str) -> Path:
    """Map a user-supplied name to a file, rejecting path traversal."""
    if not NAME_RE.match(name or ""):
        raise ValueError("Invalid backup name")
    path = backup_dir(instance_dir) / name
    if not path.is_file():
        raise ValueError("Backup not found")
    return path


def decrypt_to(path: Path, key: bytes, target: str) -> None:
    Path(target).write_bytes(decrypt_backup(path.read_bytes(), key))


def verify_backup(path: Path, backup_key: bytes, audit_key: bytes) -> dict:
    fd, tmp = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        decrypt_to(path, backup_key, tmp)
        conn = sqlite3.connect(tmp)
        conn.row_factory = sqlite3.Row
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # fixed table names
                  for t in ("students", "offers", "drives", "users", "audit_log")}
        chain = verify_chain(conn, audit_key)
        conn.close()
        return {"ok": integrity == "ok" and chain["ok"], "integrity": integrity, "counts": counts, "chain": chain}
    except ValueError as exc:
        return {"ok": False, "integrity": str(exc), "counts": {}, "chain": {"ok": False}}
    finally:
        os.remove(tmp)
