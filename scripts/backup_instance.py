#!/usr/bin/env python3
"""Copy instance/cns_lab.db and instance/keys/ to instance/backups/<timestamp>/ (never deletes anything)."""
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def backup(instance_dir) -> Path:
    inst = Path(instance_dir)
    dest = inst / "backups" / time.strftime("%Y%m%d-%H%M%S")
    dest.mkdir(parents=True, exist_ok=False)
    os.chmod(dest, 0o700)
    db = inst / "cns_lab.db"
    if db.exists():
        shutil.copy2(db, dest / "cns_lab.db")
    keys = inst / "keys"
    if keys.is_dir():
        shutil.copytree(keys, dest / "keys")
    return dest


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    from config import Config
    print("Backup written to", backup(Config.INSTANCE_DIR))
