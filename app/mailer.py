"""Outbound e-mail.

With PG_SMTP_HOST set, mail is sent over SMTP with STARTTLS (and login when
credentials are given). Without it, the application is in development mode:
each message is written to instance/outbox/ so OTPs can be read locally, and
an administrator can view them under Governance → Development outbox. The
outbox is disabled whenever SMTP is configured or APP_ENV=production.

EmailMessage rejects CR/LF in headers, which blocks header injection through
user-supplied addresses or names.
"""
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from flask import current_app


def smtp_configured() -> bool:
    return bool(current_app.config.get("SMTP_HOST"))


def outbox_enabled() -> bool:
    return not smtp_configured() and current_app.config.get("APP_ENV") != "production"


def outbox_dir() -> Path:
    path = Path(current_app.config["INSTANCE_DIR"]) / "outbox"
    path.mkdir(exist_ok=True)
    return path


def send_mail(to: str, subject: str, body: str) -> str:
    """Send a plain-text message. Returns 'smtp', 'outbox' or 'disabled'."""
    cfg = current_app.config
    msg = EmailMessage()
    msg["From"] = cfg.get("MAIL_FROM", "Placement Sahaay <no-reply@localhost>")
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    if smtp_configured():
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["SMTP_HOST"], int(cfg.get("SMTP_PORT", 587)), timeout=15) as smtp:
            smtp.starttls(context=context)
            if cfg.get("SMTP_USER"):
                smtp.login(cfg["SMTP_USER"], cfg.get("SMTP_PASSWORD", ""))
            smtp.send_message(msg)
        return "smtp"

    if not outbox_enabled():
        return "disabled"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    (outbox_dir() / f"{stamp}.eml").write_bytes(bytes(msg))
    current_app.extensions.setdefault("pg_outbox", []).append({"to": to, "subject": subject, "body": body})
    return "outbox"


def try_send(to: str, subject: str, body: str) -> str:
    """Best-effort send for notifications that must not undo a committed action."""
    try:
        return send_mail(to, subject, body)
    except (OSError, smtplib.SMTPException):
        current_app.logger.warning("Mail delivery failed for a notification")
        return "failed"


def list_outbox(limit: int = 30) -> list:
    if not outbox_enabled():
        return []
    from email import message_from_bytes, policy
    items = []
    for path in sorted(outbox_dir().glob("*.eml"), reverse=True)[:limit]:
        msg = message_from_bytes(path.read_bytes(), policy=policy.default)
        items.append({"name": path.name, "to": msg["To"], "subject": msg["Subject"],
                      "body": msg.get_content()})
    return items
