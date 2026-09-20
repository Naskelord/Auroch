"""Crashes and stability: BSODs, app crashes, critical event-log entries.

Fortect's "crashed programs" panel, reconstructed from the same sources
Windows already keeps — minidumps, Windows Error Reporting, and the System
event log.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, List

from ..core import winutil
from ..core.issue import Category, FixKind, Issue, Severity, human_bytes
from ..core.scanner import ScanContext, Scanner, register

#: Bugcheck codes worth naming, because the cause is specific.
BUGCHECK_HINTS = {
    "0x00000133": "DPC_WATCHDOG_VIOLATION — usually a storage or chipset driver.",
    "0x0000009f": "DRIVER_POWER_STATE_FAILURE — a driver mishandled sleep/resume.",
    "0x0000003b": "SYSTEM_SERVICE_EXCEPTION — commonly a graphics driver.",
    "0x0000001e": "KMODE_EXCEPTION_NOT_HANDLED — a kernel-mode driver fault.",
    "0x00000050": "PAGE_FAULT_IN_NONPAGED_AREA — often faulty RAM or a driver.",
    "0x0000007e": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED — a driver fault.",
    "0x000000d1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL — a driver accessed bad memory.",
    "0x00000124": "WHEA_UNCORRECTABLE_ERROR — hardware reported an uncorrectable fault.",
    "0x000000ef": "CRITICAL_PROCESS_DIED — a required system process terminated.",
    "0x000000c2": "BAD_POOL_CALLER — a driver corrupted the memory pool.",
}


@register
class StabilityScanner(Scanner):
    id = "stability"
    name = "Crashes & stability"
    description = "Blue screens, application crashes and unexpected shutdowns."
    category = Category.STABILITY
    weight = 2.5

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return

        yield from self._minidumps(ctx)
        yield from self._bugcheck_events(ctx)
        yield from self._app_crashes(ctx)
        yield from self._unexpected_shutdowns(ctx)
        yield from self._disk_errors(ctx)

    # -------------------------------------------------------------------

    def _minidumps(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Looking for crash dumps", 0.1)
        folder = Path(winutil.known_folders()["minidump"])
        if not folder.exists():
            return
        dumps = sorted(
            [p for p in folder.glob("*.dmp")],
            key=lambda p: p.stat().st_mtime if p.exists() else 0,
            reverse=True,
        )
        if not dumps:
            return
        recent = [d for d in dumps if _age_days(d) <= 30]
        total = sum(_size(d) for d in dumps)
        listing = "\n".join(
            f"  • {d.name}  ({_fmt_date(d)})" for d in dumps[:12]
        )
        yield Issue(
            category=self.category,
            title=(
                f"{len(dumps)} blue-screen dump(s) on disk"
                + (f", {len(recent)} in the last 30 days" if recent else "")
            ),
            detail=(
                "Windows writes a minidump every time it bugchecks. Their presence "
                "means the machine has crashed, and the dates tell you whether it is "
                "still happening.\n\n" + listing + f"\n\nFolder: {folder}"
            ),
            severity=Severity.HIGH if len(recent) >= 3 else (
                Severity.MEDIUM if recent else Severity.INFO
            ),
            fix_kind=FixKind.DELETE_FILES if not recent else FixKind.MANUAL,
            fix_label="Clear old dumps" if not recent else "",
            size_bytes=total,
            payload={"paths": [str(d) for d in dumps]} if not recent else {},
            remediation_hint=(
                "Open the newest .dmp in WinDbg (or upload to a dump analyser) to get "
                "the faulting driver by name. Do not delete recent dumps until you have."
                if recent else ""
            ),
        )

    # -------------------------------------------------------------------

    def _bugcheck_events(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Reading bugcheck events from the System log", 0.3)
        data = winutil.powershell_json(
            "Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; "
            "StartTime=(Get-Date).AddDays(-60)} -MaxEvents 40 -ErrorAction SilentlyContinue "
            "| Where-Object {$_.ProviderName -like '*BugCheck*'} "
            "| Select-Object TimeCreated,Message",
            timeout=180,
        )
        if isinstance(data, dict):
            data = [data]
        if not data:
            return
        codes = Counter()
        for event in data:
            match = re.search(r"0x[0-9a-fA-F]{8}", str(event.get("Message", "")))
            if match:
                codes[match.group(0).lower()] += 1

        lines = []
        for code, count in codes.most_common():
            hint = BUGCHECK_HINTS.get(code, "")
            lines.append(f"  • {code} ×{count}" + (f" — {hint}" if hint else ""))

        yield Issue(
            category=self.category,
            title=f"{len(data)} blue screen(s) recorded in the last 60 days",
            detail=(
                "Bugcheck events from the System log, grouped by stop code. A "
                "repeating code points at one specific cause; a scatter of different "
                "codes usually means failing RAM or a failing disk.\n\n"
                + ("\n".join(lines) if lines else "Stop codes could not be parsed.")
            ),
            severity=Severity.CRITICAL if len(data) >= 5 else Severity.HIGH,
            fix_kind=FixKind.MANUAL,
            remediation_hint=(
                "Start with Windows Memory Diagnostic (mdsched.exe) and a driver "
                "update for whatever the stop code implicates."
            ),
        )

    # -------------------------------------------------------------------

    def _app_crashes(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Reading application crash events", 0.55)
        # ProviderName matters: Event ID 1000 in the Application log is NOT
        # unique to crashes. Perflib uses 1000 for "Access to performance data
        # was denied", SideBySide and others reuse it too. Only the
        # 'Application Error' provider means a process actually faulted.
        data = winutil.powershell_json(
            "Get-WinEvent -FilterHashtable @{LogName='Application'; "
            "ProviderName='Application Error'; Id=1000; "
            "StartTime=(Get-Date).AddDays(-30)} -MaxEvents 200 -ErrorAction SilentlyContinue "
            "| Select-Object TimeCreated,Message",
            timeout=180,
        )
        if isinstance(data, dict):
            data = [data]
        if not data:
            return
        apps = Counter()
        for event in data:
            message = str(event.get("Message", ""))
            match = re.search(r"Faulting application name:\s*([^,\r\n]+)", message)
            # No faulting-application field means this is not a crash record.
            # Falling back to the message's first line is how a Perflib warning
            # ended up being reported as a crashing application.
            if not match:
                continue
            name = match.group(1).strip()
            if name:
                apps[name] += 1

        repeat = [(a, c) for a, c in apps.most_common() if c >= 3]
        if not repeat:
            return
        listing = "\n".join(f"  • {a} — crashed {c} times" for a, c in repeat[:15])
        yield Issue(
            category=self.category,
            title=f"{len(repeat)} application(s) crashing repeatedly",
            detail=(
                "Applications that faulted three or more times in the last 30 days. "
                "A single app crashing is that app's problem; several unrelated apps "
                "crashing points at Windows itself, a driver, or memory.\n\n" + listing
            ),
            severity=Severity.MEDIUM if len(repeat) < 4 else Severity.HIGH,
            fix_kind=FixKind.MANUAL,
            remediation_hint=(
                "If several unrelated apps are on this list, run the Windows system "
                "file check first."
            ),
        )

    # -------------------------------------------------------------------

    def _unexpected_shutdowns(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking for unexpected shutdowns", 0.75)
        data = winutil.powershell_json(
            "Get-WinEvent -FilterHashtable @{LogName='System'; Id=41; "
            "StartTime=(Get-Date).AddDays(-60)} -MaxEvents 40 -ErrorAction SilentlyContinue "
            "| Select-Object TimeCreated",
            timeout=180,
        )
        if isinstance(data, dict):
            data = [data]
        if not data or len(data) < 2:
            return
        yield Issue(
            category=self.category,
            title=f"{len(data)} unexpected shutdown(s) in the last 60 days",
            detail=(
                "Kernel-Power event 41: the machine lost power or froze hard enough "
                "that Windows never got to shut down. If these are not matched by "
                "blue screens, suspect the power supply, overheating, or a loose "
                "power connection rather than software."
            ),
            severity=Severity.HIGH if len(data) >= 5 else Severity.MEDIUM,
            fix_kind=FixKind.MANUAL,
            remediation_hint="Check temperatures under load and the PSU before chasing drivers.",
        )

    # -------------------------------------------------------------------

    def _disk_errors(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking the event log for disk errors", 0.9)
        data = winutil.powershell_json(
            "Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; "
            "ProviderName='disk','Ntfs','storahci'; StartTime=(Get-Date).AddDays(-30)} "
            "-MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated,ProviderName",
            timeout=180,
        )
        if isinstance(data, dict):
            data = [data]
        if not data:
            return
        yield Issue(
            category=self.category,
            title=f"{len(data)} disk or filesystem error(s) logged in the last 30 days",
            detail=(
                "Errors from the disk, NTFS or storage controller providers. These "
                "precede drive failure often enough to take seriously even when the "
                "drive still reports healthy."
            ),
            severity=Severity.HIGH,
            fix_kind=FixKind.MANUAL,
            remediation_hint="Back up, then run chkdsk and check the drive's SMART attributes.",
        )


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _age_days(path: Path) -> float:
    try:
        return (datetime.now().timestamp() - path.stat().st_mtime) / 86400.0
    except OSError:
        return 1e9


def _fmt_date(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
    except OSError:
        return "unknown date"
