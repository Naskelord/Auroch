"""Privacy traces: things that record what you did, not what you have."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from ..core import winutil
from ..core.issue import Category, FixKind, Issue, Severity, human_bytes
from ..core.scanner import ScanContext, Scanner, register

if winutil.IS_WINDOWS:
    import winreg
else:  # pragma: no cover
    winreg = None  # type: ignore


@register
class PrivacyScanner(Scanner):
    id = "privacy"
    name = "Privacy traces"
    description = "Recent-file lists, run history, browser history and cookies."
    category = Category.PRIVACY
    weight = 1.5

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return
        folders = winutil.known_folders()

        # Recent documents / jump lists ------------------------------------
        ctx.report("Checking recent-document lists", 0.1)
        recent = Path(folders["recent"])
        if recent.exists():
            paths = [str(p) for p in winutil.iter_files(recent, max_entries=20_000)]
            if paths:
                total = sum(_size(p) for p in paths)
                yield Issue(
                    category=self.category,
                    title=f"Recent documents and jump lists: {len(paths):,} entries",
                    detail=(
                        "Shortcuts recording every file you opened, plus the jump "
                        "lists shown when you right-click a taskbar icon.\n\n"
                        f"Location: {recent}"
                    ),
                    severity=Severity.INFO,
                    fix_kind=FixKind.DELETE_FILES,
                    fix_label="Clear",
                    size_bytes=total,
                    payload={"paths": paths},
                )

        # Run dialog MRU ----------------------------------------------------
        ctx.report("Checking Run dialog history", 0.3)
        if winreg is not None:
            mru = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
            entries = _count_values(winreg.HKEY_CURRENT_USER, mru)
            if entries > 1:
                yield Issue(
                    category=self.category,
                    title=f"Run dialog history: {entries - 1} command(s) remembered",
                    detail=(
                        "Everything you have typed into Win+R, kept in the "
                        f"registry.\n\nKey: HKCU\\{mru}"
                    ),
                    severity=Severity.INFO,
                    fix_kind=FixKind.DELETE_REGKEY,
                    fix_label="Clear history",
                    payload={"hive": "HKCU", "subkey": mru},
                )

            typed = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
            typed_count = _count_values(winreg.HKEY_CURRENT_USER, typed)
            if typed_count:
                yield Issue(
                    category=self.category,
                    title=f"Explorer address bar history: {typed_count} path(s)",
                    detail=f"Paths typed into File Explorer.\n\nKey: HKCU\\{typed}",
                    severity=Severity.INFO,
                    fix_kind=FixKind.DELETE_REGKEY,
                    fix_label="Clear history",
                    payload={"hive": "HKCU", "subkey": typed},
                )

        # Browser history and cookies --------------------------------------
        ctx.report("Checking browser history", 0.6)
        for label, path, kind in self._browser_dbs(folders):
            if ctx.cancelled:
                return
            if not path.exists():
                continue
            size = _size(str(path))
            if size < 4096:
                continue
            severity = Severity.INFO
            note = (
                "Browsing history database."
                if kind == "history"
                else "Cookie store — clearing it signs you out of sites."
            )
            yield Issue(
                category=self.category,
                title=f"{label} {kind}: {human_bytes(size)}",
                detail=f"{note}\n\nLocation: {path}",
                severity=severity,
                fix_kind=FixKind.DELETE_FILES,
                fix_label="Delete (quarantined first)",
                size_bytes=size,
                payload={"paths": [str(path)]},
                remediation_hint="Close the browser first or the file will be locked.",
            )

    # ------------------------------------------------------------------

    @staticmethod
    def _browser_dbs(folders) -> List[tuple]:
        local = Path(folders["local"])
        roaming = Path(folders["roaming"])
        out = []
        chromium = {
            "Chrome": local / "Google" / "Chrome" / "User Data" / "Default",
            "Edge": local / "Microsoft" / "Edge" / "User Data" / "Default",
            "Brave": local / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default",
            "Vivaldi": local / "Vivaldi" / "User Data" / "Default",
        }
        for name, base in chromium.items():
            out.append((name, base / "History", "history"))
            out.append((name, base / "Network" / "Cookies", "cookies"))
        ff = local / "Mozilla" / "Firefox" / "Profiles"
        if ff.exists():
            for profile in ff.iterdir():
                out.append(("Firefox", profile / "places.sqlite", "history"))
                out.append(("Firefox", profile / "cookies.sqlite", "cookies"))
        return out


def _size(path: str) -> int:
    try:
        return Path(path).stat().st_size
    except OSError:
        return 0


def _count_values(hive, subkey: str) -> int:
    if winreg is None:
        return 0
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            return winreg.QueryInfoKey(key)[1]
    except OSError:
        return 0
