"""Tamper-evident audit trail (HMAC-SHA256 hash chain).

hash_n = HMAC(audit_key, hash_{n-1} || canonical(entry_n))

Editing, deleting, reordering or inserting a row breaks every later link, and
without the audit key (held outside the database) an attacker who can write
to the database file cannot forge a consistent chain. Database triggers also
reject UPDATE and DELETE on the table.
"""
import hashlib
import hmac
import json

from flask import current_app, g, has_request_context, request

from .constants import now_iso
from .db import get_db

GENESIS = "0" * 64
FIELDS = ("ts", "actor_id", "actor", "role", "action", "entity", "entity_id", "detail", "ip")


def _canonical(entry: dict) -> bytes:
    return json.dumps({k: entry[k] for k in FIELDS}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _digest(key: bytes, prev_hash: str, entry: dict) -> str:
    return hmac.new(key, prev_hash.encode("ascii") + _canonical(entry), hashlib.sha256).hexdigest()


def record(action: str, entity: str | None = None, entity_id=None, detail: dict | None = None,
           actor: dict | None = None, conn=None):
    """Append an audit entry. Call inside the same transaction as the change
    it describes so the change and its record commit (or fail) together."""
    conn = conn or get_db()
    user = actor if actor is not None else (g.get("user") if has_request_context() else None)
    entry = {
        "ts": now_iso(),
        "actor_id": user["id"] if user else None,
        "actor": user["username"] if user else "system",
        "role": user["role"] if user else "system",
        "action": action,
        "entity": entity,
        "entity_id": None if entity_id is None else str(entity_id),
        "detail": json.dumps(detail or {}, sort_keys=True, ensure_ascii=False, default=str),
        "ip": request.remote_addr if has_request_context() else None,
    }
    row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row["hash"] if row else GENESIS
    entry_hash = _digest(current_app.extensions["pg_keys"]["audit_key"], prev_hash, entry)
    conn.execute(
        "INSERT INTO audit_log (ts, actor_id, actor, role, action, entity, entity_id, detail, ip, prev_hash, hash)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (entry["ts"], entry["actor_id"], entry["actor"], entry["role"], entry["action"], entry["entity"],
         entry["entity_id"], entry["detail"], entry["ip"], prev_hash, entry_hash),
    )


def verify_chain(conn=None, key: bytes | None = None) -> dict:
    conn = conn or get_db()
    key = key or current_app.extensions["pg_keys"]["audit_key"]
    prev_hash = GENESIS
    checked = 0
    for row in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        entry = {k: row[k] for k in FIELDS}
        if row["prev_hash"] != prev_hash:
            return {"ok": False, "checked": checked, "bad_id": row["id"], "reason": "Broken link to previous entry"}
        if not hmac.compare_digest(_digest(key, prev_hash, entry), row["hash"]):
            return {"ok": False, "checked": checked, "bad_id": row["id"], "reason": "Entry content does not match its MAC"}
        prev_hash = row["hash"]
        checked += 1
    return {"ok": True, "checked": checked, "bad_id": None, "reason": None, "head": prev_hash}
