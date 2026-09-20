"""Temporary files, caches and installer leftovers."""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterable, List

from ..core.issue import Category, FixKind, Issue, Severity, human_bytes
from ..core.scanner import ScanContext, Scanner, register
from ..core import winutil

#: Files younger than this are left alone — something may still be using them.
MIN_AGE_HOURS = 24


def _collect(root: Path, min_age_hours: int = MIN_AGE_HOURS, limit: int = 60_000):
    """Return (paths, total_bytes) for stale files under root."""
    cutoff = time.time() - min_age_hours * 3600
    paths: List[str] = []
    total = 0
    for path in winutil.iter_files(root, max_entries=limit):
        try:
            stat = path.stat()
            if stat.st_mtime > cutoff:
                continue
            paths.append(str(path))
            total += stat.st_size
        except OSError:
            continue
    return paths, total


@register
class JunkFilesScanner(Scanner):
    id = "junk"
    name = "Junk & temporary files"
    description = "Stale temp files, thumbnail and update caches, crash dumps."
    category = Category.JUNK
    weight = 3.0

    #: (label, folder key, severity, min age hours, note)
    TARGETS = [
        ("User temp folder", "temp_user", 24, "Everything Windows and your apps dumped in %TEMP%."),
        ("Windows temp folder", "temp_win", 48, "System-level temp files. Safe once they are a couple of days old."),
        ("Windows Update cache", "softwaredistribution", 168, "Downloaded update packages already installed. Windows re-downloads if ever needed."),
        ("Application crash dumps", "crashdumps", 72, "Memory dumps written when an app crashed."),
    ]

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return
        folders = winutil.known_folders()

        for label, key, min_age, note in self.TARGETS:
            if ctx.cancelled:
                return
            root = folders.get(key)
            if not root or not Path(root).exists():
                continue
            ctx.report(f"Measuring {label}", -1)
            paths, total = _collect(Path(root), min_age_hours=min_age)
            if not paths or total < 1024 * 1024:
                continue
            yield Issue(
                category=self.category,
                title=f"{label}: {human_bytes(total)} in {len(paths):,} files",
                detail=f"{note}\n\nLocation: {root}",
                severity=Severity.LOW,
                fix_kind=FixKind.DELETE_FILES,
                fix_label="Move to quarantine",
                size_bytes=total,
                payload={"paths": paths},
            )

        # Recycle Bin -------------------------------------------------------
        if ctx.cancelled:
            return
        ctx.report("Checking the Recycle Bin", -1)
        data = winutil.powershell_json(
            "$s=New-Object -ComObject Shell.Application; "
            "$b=$s.Namespace(10).Items(); "
            "$n=0; $sz=0; foreach($i in $b){$n++; $sz += $i.Size}; "
            "[pscustomobject]@{Count=$n; Size=$sz}",
            timeout=60,
        )
        if data and int(data.get("Count", 0)) > 0:
            size = int(data.get("Size", 0) or 0)
            count = int(data["Count"])
            yield Issue(
                category=self.category,
                title=f"Recycle Bin holds {count:,} item(s), {human_bytes(size)}",
                detail=(
                    "Deleted files still occupying disk space. Emptying this is "
                    "permanent — Auroch cannot quarantine items that are already "
                    "in the bin."
                ),
                severity=Severity.LOW,
                fix_kind=FixKind.RUN_COMMAND,
                fix_label="Empty Recycle Bin (permanent)",
                size_bytes=size,
                payload={
                    "argv": [
                        "powershell.exe", "-NoProfile", "-Command",
                        "Clear-RecycleBin -Force -ErrorAction SilentlyContinue",
                    ],
                    "timeout": 300,
                },
            )

        # Browser caches ----------------------------------------------------
        for label, rel in self._browser_cache_dirs(folders):
            if ctx.cancelled:
                return
            if not rel.exists():
                continue
            ctx.report(f"Measuring {label}", -1)
            total, count = winutil.dir_size(rel, max_entries=80_000)
            if total < 20 * 1024 * 1024:
                continue
            paths = [str(p) for p in winutil.iter_files(rel, max_entries=80_000)]
            yield Issue(
                category=self.category,
                title=f"{label} cache: {human_bytes(total)}",
                detail=(
                    f"Cached page assets. Clearing frees space; sites reload a little "
                    f"slower once, then rebuild the cache.\n\nLocation: {rel}"
                ),
                severity=Severity.LOW,
                fix_kind=FixKind.DELETE_FILES,
                fix_label="Move to quarantine",
                size_bytes=total,
                payload={"paths": paths},
                remediation_hint="Close the browser first, or locked files will be skipped.",
            )

        # Old Windows installation -----------------------------------------
        if ctx.cancelled:
            return
        old_windows = Path(winutil.system_drive()) / "Windows.old"
        if old_windows.exists():
            total, _ = winutil.dir_size(old_windows, max_entries=400_000)
            yield Issue(
                category=self.category,
                title=f"Previous Windows installation: {human_bytes(total)}",
                detail=(
                    "C:\\Windows.old is kept after a feature update so you can roll "
                    "back. Once you are sure the current build is fine, it is pure "
                    "dead weight.\n\nAuroch will not touch this folder — removing it "
                    "correctly needs the Disk Cleanup system-files path."
                ),
                severity=Severity.LOW,
                fix_kind=FixKind.MANUAL,
                size_bytes=total,
                remediation_hint=(
                    "Settings > System > Storage > Temporary files, tick "
                    "'Previous Windows installation(s)'."
                ),
            )

    @staticmethod
    def _browser_cache_dirs(folders) -> List[tuple]:
        local = Path(folders["local"])
        roaming = Path(folders["roaming"])
        out = []
        chromium = {
            "Chrome": local / "Google" / "Chrome" / "User Data",
            "Edge": local / "Microsoft" / "Edge" / "User Data",
            "Brave": local / "BraveSoftware" / "Brave-Browser" / "User Data",
            "Vivaldi": local / "Vivaldi" / "User Data",
            "Opera": roaming / "Opera Software" / "Opera Stable",
        }
        for name, base in chromium.items():
            if not base.exists():
                continue
            for profile in ("Default", "Profile 1", "Profile 2", ""):
                cache = (base / profile / "Cache" / "Cache_Data") if profile else (base / "Cache")
                if cache.exists():
                    label = f"{name}{' ' + profile if profile and profile != 'Default' else ''}"
                    out.append((label, cache))
        # Firefox keeps one cache per profile. Label each with its profile name
        # so five rows reading "Firefox cache" are actually tellable apart.
        ff = local / "Mozilla" / "Firefox" / "Profiles"
        if ff.exists():
            for profile in ff.iterdir():
                cache = profile / "cache2"
                if cache.exists():
                    # Profile dirs are named "<salt>.<label>"; the label is the
                    # part a human recognises.
                    label = profile.name.split(".", 1)[-1] or profile.name
                    out.append((f"Firefox [{label}]", cache))
        return out
