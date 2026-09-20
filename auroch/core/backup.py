"""Backup and undo.

Nothing this app deletes is gone. Files are moved into a timestamped
quarantine folder with a manifest; registry keys are exported to .reg before
removal. `undo_session` puts everything back.
"""
from __future__ import annotations

import json
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from . import winutil


def data_root() -> Path:
    base = Path(winutil.known_folders()["local"]) / "Auroch"
    base.mkdir(parents=True, exist_ok=True)
    return base


class BackupSession:
    """One repair run. Holds the quarantine folder and the undo manifest."""

    def __init__(self) -> None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.root = data_root() / "backups" / stamp
        self.files_dir = self.root / "files"
        self.registry_dir = self.root / "registry"
        self.manifest_path = self.root / "manifest.json"
        self.entries: List[Dict] = []
        self._counter = 0
        self.root.mkdir(parents=True, exist_ok=True)
        self.files_dir.mkdir(exist_ok=True)
        self.registry_dir.mkdir(exist_ok=True)

    # ---------------------------------------------------------------- files

    def quarantine_file(self, src: Path) -> bool:
        """Move a file into quarantine. Returns True on success."""
        try:
            if not src.exists():
                return False
            self._counter += 1
            dest = self.files_dir / f"{self._counter:06d}_{src.name}"
            shutil.move(str(src), str(dest))
            self.entries.append(
                {
                    "type": "file",
                    "original": str(src),
                    "backup": str(dest),
                    "at": time.time(),
                }
            )
            return True
        except Exception:
            return False

    # ------------------------------------------------------------- registry

    def export_regkey(self, hive_name: str, subkey: str) -> Optional[Path]:
        """Export a key to .reg before it is deleted."""
        if not winutil.IS_WINDOWS:
            return None
        self._counter += 1
        safe = subkey.replace("\\", "_").replace("/", "_")[:80]
        dest = self.registry_dir / f"{self._counter:06d}_{safe}.reg"
        full = f"{hive_name}\\{subkey}"
        rc, _out, _err = winutil.run(
            ["reg.exe", "export", full, str(dest), "/y"], timeout=30
        )
        if rc != 0 or not dest.exists():
            return None
        self.entries.append(
            {
                "type": "registry",
                "original": full,
                "backup": str(dest),
                "at": time.time(),
            }
        )
        return dest

    # ---------------------------------------------------------------- write

    def save(self) -> Path:
        payload = {
            "created": datetime.now().isoformat(timespec="seconds"),
            "entries": self.entries,
        }
        self.manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return self.manifest_path

    @property
    def is_empty(self) -> bool:
        return not self.entries

    def discard_if_empty(self) -> None:
        if self.is_empty:
            try:
                shutil.rmtree(self.root, ignore_errors=True)
            except Exception:
                pass


def list_sessions() -> List[Path]:
    root = data_root() / "backups"
    if not root.exists():
        return []
    return sorted([p for p in root.iterdir() if p.is_dir()], reverse=True)


def session_size(session_dir: Path) -> int:
    """Bytes held by one backup session."""
    total = 0
    for path in session_dir.rglob("*"):
        try:
            if path.is_file():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def total_quarantine_size() -> int:
    """Bytes held across every backup session.

    This is the number that matters: quarantined files sit on the same volume
    they came from, so nothing is actually reclaimed until these are purged.
    """
    return sum(session_size(s) for s in list_sessions())


def purge_sessions(keep_newest: int = 0) -> tuple[int, int]:
    """Permanently delete backup sessions, oldest first.

    This is the only operation in Auroch that destroys data with no way back,
    which is why it is never automatic and never part of a repair run.

    Returns (sessions_removed, bytes_freed).
    """
    sessions = list_sessions()  # newest first
    doomed = sessions[keep_newest:] if keep_newest > 0 else sessions
    removed = 0
    freed = 0
    for session in doomed:
        size = session_size(session)
        try:
            shutil.rmtree(session, ignore_errors=False)
            removed += 1
            freed += size
        except Exception:
            continue
    return removed, freed


def undo_session(session_dir: Path) -> List[str]:
    """Restore everything in a backup session. Returns a log of what happened."""
    log: List[str] = []
    manifest = session_dir / "manifest.json"
    if not manifest.exists():
        return [f"No manifest in {session_dir}"]
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"Unreadable manifest: {exc}"]

    for entry in data.get("entries", []):
        kind = entry.get("type")
        backup = Path(entry.get("backup", ""))
        original = entry.get("original", "")
        if kind == "file":
            try:
                target = Path(original)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(backup), str(target))
                log.append(f"Restored file {original}")
            except Exception as exc:
                log.append(f"FAILED file {original}: {exc}")
        elif kind == "registry":
            rc, _out, err = winutil.run(["reg.exe", "import", str(backup)], timeout=30)
            if rc == 0:
                log.append(f"Restored registry {original}")
            else:
                log.append(f"FAILED registry {original}: {err.strip()}")
    return log


def create_restore_point(description: str = "Auroch repair") -> tuple[bool, str]:
    """Ask Windows for a System Restore point. Requires admin + SR enabled."""
    if not winutil.IS_WINDOWS:
        return False, "Not Windows."
    if not winutil.is_admin():
        return False, "Administrator rights are required to create a restore point."
    rc, _out, err = winutil.powershell(
        "Checkpoint-Computer -Description "
        f"'{description}' -RestorePointType 'MODIFY_SETTINGS'",
        timeout=180,
    )
    if rc == 0:
        return True, "Restore point created."
    msg = (err or "").strip().splitlines()
    detail = msg[0] if msg else "unknown error"
    if "1440" in detail or "once per" in detail.lower():
        return False, "Windows already made a restore point recently; reusing that one."
    return False, f"Could not create a restore point: {detail}"
