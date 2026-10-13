"""Restore an encrypted backup (offline, administrator only).

    python scripts/restore_backup.py instance/backups/placement-YYYYMMDDTHHMMSSZ.db.enc

The backup is verified (authenticated decryption, SQLite integrity check and
audit-chain verification) before the live database is replaced. The current
database is kept alongside as *.pre-restore.
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.backup import decrypt_to, verify_backup  # noqa: E402
from app.config import Config, load_keys  # noqa: E402


def main(path: str):
    src = Path(path)
    keys = load_keys(Config.INSTANCE_DIR)
    result = verify_backup(src, keys["backup_key"], keys["audit_key"])
    if not result["ok"]:
        sys.exit(f"Backup failed verification: integrity={result['integrity']} chain={result['chain']}")
    live = Path(Config.DATABASE)
    if live.exists():
        shutil.copy2(live, live.with_suffix(".pre-restore"))
    decrypt_to(src, keys["backup_key"], str(live))
    print(f"Restored {src.name}: {result['counts']}. Previous database saved as {live.with_suffix('.pre-restore').name}.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
