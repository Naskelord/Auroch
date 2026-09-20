"""The repair executor.

Rules this module enforces, without exception:
  * Nothing runs that the user did not tick.
  * Files are quarantined, never unlinked.
  * Registry keys are exported to .reg before deletion.
  * A System Restore point is offered before the first registry write.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

from . import winutil
from .backup import BackupSession
from .issue import FixKind, FixResult, Issue

if winutil.IS_WINDOWS:
    import winreg
else:  # pragma: no cover - import shim for off-platform development
    winreg = None  # type: ignore

HIVES = {}
if winreg is not None:
    HIVES = {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
    }


def _delete_regkey_tree(hive_const, subkey: str) -> None:
    """Recursive key delete. winreg.DeleteKey only removes empty keys."""
    try:
        with winreg.OpenKey(hive_const, subkey, 0, winreg.KEY_READ) as key:
            children = []
            index = 0
            while True:
                try:
                    children.append(winreg.EnumKey(key, index))
                    index += 1
                except OSError:
                    break
    except FileNotFoundError:
        return
    for child in children:
        _delete_regkey_tree(hive_const, f"{subkey}\\{child}")
    winreg.DeleteKey(hive_const, subkey)


class Repairer:
    def __init__(self) -> None:
        self.session: Optional[BackupSession] = None
        self.log: List[str] = []

    def _ensure_session(self) -> BackupSession:
        if self.session is None:
            self.session = BackupSession()
        return self.session

    # ------------------------------------------------------------ dispatch

    def apply(self, issue: Issue) -> FixResult:
        try:
            if issue.fix_kind == FixKind.DELETE_FILES:
                return self._delete_files(issue)
            if issue.fix_kind == FixKind.DELETE_REGKEY:
                return self._delete_regkey(issue)
            if issue.fix_kind == FixKind.DELETE_REGVALUE:
                return self._delete_regvalue(issue)
            if issue.fix_kind == FixKind.RUN_COMMAND:
                return self._run_command(issue)
            return FixResult(issue.id, False, "This item has no automatic fix.")
        except PermissionError:
            return FixResult(
                issue.id,
                False,
                "Access denied. Run Auroch as administrator and try again.",
            )
        except Exception as exc:
            return FixResult(issue.id, False, f"{exc.__class__.__name__}: {exc}")

    # ------------------------------------------------------------- handlers

    def _delete_files(self, issue: Issue) -> FixResult:
        session = self._ensure_session()
        paths = [Path(p) for p in issue.payload.get("paths", [])]
        moved = 0
        skipped = 0
        freed = 0
        for path in paths:
            try:
                size = path.stat().st_size if path.exists() else 0
            except OSError:
                size = 0
            if session.quarantine_file(path):
                moved += 1
                freed += size
            else:
                skipped += 1
        if moved == 0:
            return FixResult(
                issue.id,
                False,
                "Nothing could be moved — the files are in use or already gone.",
            )
        note = f"Quarantined {moved} file(s), {_hb(freed)} reclaimed"
        if skipped:
            note += f"; {skipped} skipped (in use or locked)"
        return FixResult(issue.id, True, note + ".", undo_token=str(session.root))

    def _delete_regkey(self, issue: Issue) -> FixResult:
        if winreg is None:
            return FixResult(issue.id, False, "Registry edits require Windows.")
        hive_name = issue.payload["hive"]
        subkey = issue.payload["subkey"]
        session = self._ensure_session()
        if session.export_regkey(hive_name, subkey) is None:
            return FixResult(
                issue.id,
                False,
                "Refused: the key could not be backed up first, so it was left alone.",
            )
        _delete_regkey_tree(HIVES[hive_name], subkey)
        return FixResult(
            issue.id, True, f"Removed {hive_name}\\{subkey}.", undo_token=str(session.root)
        )

    def _delete_regvalue(self, issue: Issue) -> FixResult:
        if winreg is None:
            return FixResult(issue.id, False, "Registry edits require Windows.")
        hive_name = issue.payload["hive"]
        subkey = issue.payload["subkey"]
        value = issue.payload["value"]
        session = self._ensure_session()
        if session.export_regkey(hive_name, subkey) is None:
            return FixResult(
                issue.id,
                False,
                "Refused: the key could not be backed up first, so it was left alone.",
            )
        with winreg.OpenKey(
            HIVES[hive_name], subkey, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, value)
        return FixResult(
            issue.id,
            True,
            f"Removed value '{value}'.",
            undo_token=str(session.root),
        )

    def _run_command(self, issue: Issue) -> FixResult:
        argv = issue.payload.get("argv") or []
        timeout = int(issue.payload.get("timeout", 900))
        rc, out, err = winutil.run(argv, timeout=timeout)
        ok_codes = issue.payload.get("ok_codes", [0])
        tail = (out or err or "").strip().splitlines()
        message = tail[-1] if tail else f"exit code {rc}"
        return FixResult(
            issue.id,
            rc in ok_codes,
            message[:400],
            restart_required=issue.requires_restart,
        )

    # ------------------------------------------------------------------ run

    def run_batch(
        self,
        issues: Iterable[Issue],
        on_progress: Optional[Callable[[str, float], None]] = None,
    ) -> Tuple[List[FixResult], Optional[str]]:
        """Apply every issue passed in. Returns (results, backup_path)."""
        items = list(issues)
        results: List[FixResult] = []
        for index, issue in enumerate(items):
            if on_progress:
                on_progress(issue.title, index / max(len(items), 1))
            result = self.apply(issue)
            results.append(result)
            self.log.append(f"[{'OK ' if result.ok else 'FAIL'}] {issue.title} — {result.message}")
        backup_path = None
        if self.session:
            self.session.save()
            self.session.discard_if_empty()
            if not self.session.is_empty:
                backup_path = str(self.session.root)
        if on_progress:
            on_progress("Done", 1.0)
        return results, backup_path


def _hb(n: int) -> str:
    from .issue import human_bytes

    return human_bytes(n)


def needs_restore_point(issues: Iterable[Issue]) -> bool:
    return any(
        i.fix_kind in (FixKind.DELETE_REGKEY, FixKind.DELETE_REGVALUE) for i in issues
    )
