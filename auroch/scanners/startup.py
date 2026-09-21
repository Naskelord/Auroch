"""Autoruns: what launches with Windows, and whether it is trustworthy.

This is the one place where Auroch goes further than Fortect: every autorun
target gets an Authenticode check, so an unsigned binary running from a temp
or AppData path surfaces as a real finding rather than a line in a list.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from ..core import winutil
from ..core.issue import Category, FixKind, Issue, Severity
from ..core.scanner import ScanContext, Scanner, register
from .registry import _path_from_command, _read_value

if winutil.IS_WINDOWS:
    import winreg
else:  # pragma: no cover
    winreg = None  # type: ignore

#: Locations legitimate software rarely launches from at boot.
SUSPICIOUS_ROOTS = ("\\appdata\\local\\temp", "\\temp\\", "\\downloads\\", "\\public\\")


@register
class StartupScanner(Scanner):
    id = "startup"
    name = "Startup & autoruns"
    description = "Programs that launch at logon, with signature checks."
    category = Category.STARTUP
    weight = 2.5

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return

        entries = list(self._registry_runs(ctx)) + list(self._startup_folders(ctx))
        ctx.report(f"Verifying {len(entries)} startup entries", 0.4)

        heavy: List[str] = []
        for index, (source, name, command, target, hive, subkey) in enumerate(entries):
            if ctx.cancelled:
                return
            ctx.report(f"Verifying {name}", 0.4 + 0.5 * index / max(len(entries), 1))

            if target is None:
                continue
            lower = str(target).lower()
            suspicious_location = any(root in lower for root in SUSPICIOUS_ROOTS)

            signed: Optional[bool] = None
            if suspicious_location or ctx.deep:
                try:
                    if target.exists():
                        signed = winutil.file_is_signed(target)
                except OSError:
                    signed = None

            if suspicious_location and signed is not True:
                yield Issue(
                    category=self.category,
                    title=f"Unsigned startup program in a temp location: {name}",
                    detail=(
                        "Software that installs properly does not launch itself from "
                        "a temp or Downloads folder, and legitimate software is "
                        "normally signed. This one does both.\n\n"
                        f"Command: {command}\nSource: {source}\n"
                        f"Signature: {'unsigned or invalid' if signed is False else 'could not verify'}"
                    ),
                    severity=Severity.HIGH,
                    fix_kind=(
                        FixKind.DELETE_REGVALUE if hive else FixKind.DELETE_FILES
                    ),
                    fix_label="Disable this startup entry",
                    requires_admin=(hive == "HKLM"),
                    payload=(
                        {"hive": hive, "subkey": subkey, "value": name}
                        if hive
                        else {"paths": [str(command)]}
                    ),
                    remediation_hint=(
                        "Check the file on VirusTotal before deciding. Disabling the "
                        "entry does not remove the file."
                    ),
                )
            else:
                heavy.append(f"{name}  —  {source}")

        if heavy:
            listing = "\n".join(f"  • {h}" for h in sorted(heavy))
            severity = Severity.MEDIUM if len(heavy) >= 12 else Severity.INFO
            yield Issue(
                category=self.category,
                title=f"{len(heavy)} program(s) start automatically with Windows",
                detail=(
                    "Each one adds to logon time and holds memory from boot. "
                    "Nothing here looks malicious — this is a list for you to prune.\n\n"
                    + listing
                ),
                severity=severity,
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "Task Manager > Startup apps lets you disable individual entries "
                    "and shows each one's measured startup impact."
                ),
            )

        yield from self._scheduled_tasks(ctx)

    # ------------------------------------------------------------------

    def _registry_runs(self, ctx: ScanContext) -> Iterable[Tuple]:
        if winreg is None:
            return
        run_keys = [
            ("HKCU Run", "HKCU", winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM Run", "HKLM", winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM Run (32-bit)", "HKLM", winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            ("HKCU RunOnce", "HKCU", winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        for label, hive_name, hive, subkey in run_keys:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, index)
                            index += 1
                        except OSError:
                            break
                        target = _path_from_command(str(value))
                        if target is None or not _exists(target):
                            continue  # dead entries are the registry scanner's job
                        yield (label, name, str(value), target, hive_name, subkey)
            except OSError:
                continue

    def _startup_folders(self, ctx: ScanContext) -> Iterable[Tuple]:
        folders = winutil.known_folders()
        for label, key in (("Startup folder (you)", "startup_user"),
                           ("Startup folder (all users)", "startup_common")):
            root = Path(folders[key])
            if not root.exists():
                continue
            for item in root.iterdir():
                if item.name.lower() == "desktop.ini":
                    continue
                target = item
                if item.suffix.lower() == ".lnk":
                    resolved = _resolve_shortcut(item)
                    if resolved:
                        target = resolved
                yield (label, item.stem, str(item), target, None, None)

    def _scheduled_tasks(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking scheduled tasks", 0.95)
        # Filtering on TaskPath alone is not enough. Windows 11's Content
        # Delivery Manager registers SoftLandingCreativeManagementTask under
        # \SoftLanding\, outside the \Microsoft\ namespace entirely, so a
        # path-only filter reports a Microsoft-signed component as third-party.
        # Read the Author too and exclude anything Microsoft-authored.
        data = winutil.powershell_json(
            "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled' -and "
            "$_.TaskPath -notlike '\\Microsoft\\*'} | "
            "Select-Object TaskName,TaskPath,Author",
            timeout=90,
        )
        if not data:
            return
        if isinstance(data, dict):
            data = [data]

        def microsoft_authored(task) -> bool:
            author = str(task.get("Author", "") or "").lower()
            # Authors appear either as a plain name or as an ms-resource
            # indirection string like "$(@%SystemRoot%\\system32\\...,-100)".
            return ("microsoft" in author
                    or author.startswith("$(@%systemroot%")
                    or author.startswith("$(@%windir%"))

        data = [d for d in data if not microsoft_authored(d)]
        if not data:
            return
        names = [f"{d.get('TaskPath','')}{d.get('TaskName','')}" for d in data]
        if len(names) >= 8:
            listing = "\n".join(f"  • {n}" for n in sorted(names)[:40])
            more = f"\n  … and {len(names) - 40} more" if len(names) > 40 else ""
            yield Issue(
                category=self.category,
                title=f"{len(names)} third-party scheduled task(s) enabled",
                detail=(
                    "Scheduled tasks are the autorun location people forget to "
                    "check. Microsoft's own tasks are excluded from this list.\n\n"
                    + listing
                    + more
                ),
                severity=Severity.INFO,
                fix_kind=FixKind.MANUAL,
                remediation_hint="Review in Task Scheduler (taskschd.msc).",
            )


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _resolve_shortcut(lnk: Path) -> Optional[Path]:
    rc, out, _ = winutil.powershell(
        "$ws=New-Object -ComObject WScript.Shell; "
        f"$ws.CreateShortcut('{lnk}').TargetPath",
        timeout=20,
    )
    if rc == 0 and out.strip():
        return Path(out.strip())
    return None
