"""Field-level encryption, blind indexes and backup encryption.

AES-256-GCM provides confidentiality and integrity. The associated data binds
each ciphertext to its column and record, so a ciphertext copied into another
student's row or another column fails authentication instead of decrypting.
"""
import base64
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

FIELD_PREFIX = "v1:"
BACKUP_MAGIC = b"PGBK1"


def _keys():
    return current_app.extensions["pg_keys"]


def encrypt_field(plaintext: str, aad: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(_keys()["field_key"]).encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))
    return FIELD_PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def decrypt_field(token: str, aad: str) -> str:
    if not token.startswith(FIELD_PREFIX):
        raise ValueError("Unknown ciphertext version")
    blob = base64.b64decode(token[len(FIELD_PREFIX):])
    try:
        pt = AESGCM(_keys()["field_key"]).decrypt(blob[:12], blob[12:], aad.encode("utf-8"))
    except InvalidTag as exc:
        raise ValueError("Ciphertext failed authentication") from exc
    return pt.decode("utf-8")


def blind_index(value: str, purpose: str) -> str:
    """Keyed, deterministic hash used for uniqueness checks without storing
    the plaintext (an unkeyed hash of a phone number is trivially reversible)."""
    msg = (purpose + ":" + value).encode("utf-8")
    return hmac.new(_keys()["index_key"], msg, hashlib.sha256).hexdigest()


def encrypt_backup(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    return BACKUP_MAGIC + nonce + AESGCM(key).encrypt(nonce, data, BACKUP_MAGIC)


def decrypt_backup(blob: bytes, key: bytes) -> bytes:
    if not blob.startswith(BACKUP_MAGIC):
        raise ValueError("Not a Placement Sahaay backup")
    body = blob[len(BACKUP_MAGIC):]
    try:
        return AESGCM(key).decrypt(body[:12], body[12:], BACKUP_MAGIC)
    except InvalidTag as exc:
        raise ValueError("Backup failed authentication (corrupt or wrong key)") from exc


def mask_mobile(mobile: str) -> str:
    return "+91 ••••• •" + mobile[-4:]


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return (local[:1] + "•••@" + domain) if local else "•••"
