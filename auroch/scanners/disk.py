"""Disk space, SMART status and filesystem health."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Iterable

from ..core import winutil
from ..core.issue import Category, FixKind, Issue, Severity, human_bytes
from ..core.scanner import ScanContext, Scanner, register


@register
class DiskScanner(Scanner):
    id = "disk"
    name = "Disk health"
    description = "Free space, SMART predictive-failure status, filesystem errors."
    category = Category.DISK
    weight = 1.5

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return

        # Free space --------------------------------------------------------
        ctx.report("Checking free space", 0.1)
        volumes = winutil.powershell_json(
            "Get-Volume | Where-Object {$_.DriveLetter -and $_.DriveType -eq 'Fixed'} "
            "| Select-Object DriveLetter,FileSystemLabel,Size,SizeRemaining,HealthStatus",
            timeout=60,
        )
        if isinstance(volumes, dict):
            volumes = [volumes]
        for vol in volumes or []:
            letter = vol.get("DriveLetter")
            size = int(vol.get("Size") or 0)
            free = int(vol.get("SizeRemaining") or 0)
            if not letter or size <= 0:
                continue
            pct = free / size * 100.0
            label = vol.get("FileSystemLabel") or "Local Disk"
            if pct < 5:
                sev = Severity.CRITICAL
                note = ("Below 5% free. Windows needs headroom for the page file, "
                        "updates and temp data; at this level the system will "
                        "misbehave in ways that look like unrelated faults.")
            elif pct < 10:
                sev = Severity.HIGH
                note = "Below 10% free. Performance degrades and updates start failing."
            elif pct < 15:
                sev = Severity.MEDIUM
                note = "Getting tight. Worth reclaiming space soon."
            else:
                continue
            yield Issue(
                category=self.category,
                title=f"Drive {letter}: only {pct:.0f}% free ({human_bytes(free)} of {human_bytes(size)})",
                detail=f"{note}\n\nVolume: {label} ({letter}:)",
                severity=sev,
                fix_kind=FixKind.MANUAL,
                remediation_hint="Run the Junk & Temporary Files fixes, then review large folders.",
            )

            health = str(vol.get("HealthStatus") or "").lower()
            if health and health != "healthy":
                yield Issue(
                    category=self.category,
                    title=f"Volume {letter}: reports health '{vol.get('HealthStatus')}'",
                    detail="Windows considers this volume unhealthy.",
                    severity=Severity.HIGH,
                    fix_kind=FixKind.MANUAL,
                    remediation_hint=f"Run: chkdsk {letter}: /scan",
                )

        # SMART -------------------------------------------------------------
        ctx.report("Reading SMART status", 0.5)
        disks = winutil.powershell_json(
            "Get-PhysicalDisk | Select-Object FriendlyName,MediaType,HealthStatus,"
            "OperationalStatus,Size",
            timeout=60,
        )
        if isinstance(disks, dict):
            disks = [disks]
        for disk in disks or []:
            name = disk.get("FriendlyName", "Unknown disk")
            health = str(disk.get("HealthStatus", ""))
            # PowerShell may return the enum as an int (0=Healthy, 1=Warning, 2=Unhealthy)
            healthy = health.lower() in ("healthy", "0")
            if not healthy:
                yield Issue(
                    category=self.category,
                    title=f"Disk reporting a problem: {name}",
                    detail=(
                        f"Health status: {health}\n"
                        f"Operational status: {disk.get('OperationalStatus')}\n\n"
                        "A drive that reports anything other than Healthy should be "
                        "backed up now, not after you finish investigating."
                    ),
                    severity=Severity.CRITICAL,
                    fix_kind=FixKind.MANUAL,
                    remediation_hint="Back up immediately, then check the vendor's diagnostic tool.",
                )

        # SMART predictive failure via WMI ----------------------------------
        predict = winutil.powershell_json(
            "Get-CimInstance -Namespace root\\wmi -ClassName MSStorageDriver_FailurePredictStatus "
            "-ErrorAction SilentlyContinue | Select-Object InstanceName,PredictFailure,Reason",
            timeout=60,
        )
        if isinstance(predict, dict):
            predict = [predict]
        for entry in predict or []:
            if entry.get("PredictFailure"):
                yield Issue(
                    category=self.category,
                    title="SMART is predicting imminent drive failure",
                    detail=(
                        f"Device: {entry.get('InstanceName')}\n"
                        f"Reason code: {entry.get('Reason')}\n\n"
                        "This is the drive's own firmware saying it expects to fail. "
                        "Copy your data off it today."
                    ),
                    severity=Severity.CRITICAL,
                    fix_kind=FixKind.MANUAL,
                    remediation_hint="Back up now and replace the drive.",
                )

        # Filesystem dirty bit ----------------------------------------------
        ctx.report("Checking filesystem flags", 0.85)
        drive = winutil.system_drive().rstrip("\\")
        rc, out, _ = winutil.run(["fsutil.exe", "dirty", "query", drive], timeout=30)
        if rc == 0 and "is dirty" in out.lower() and "not dirty" not in out.lower():
            yield Issue(
                category=self.category,
                title=f"Filesystem on {drive} is flagged dirty",
                detail=(
                    "Windows set the dirty bit after an unclean shutdown or a write "
                    "error. It will force a disk check at the next boot."
                ),
                severity=Severity.HIGH,
                fix_kind=FixKind.RUN_COMMAND,
                fix_label=f"Schedule chkdsk on {drive} at next boot",
                requires_admin=True,
                requires_restart=True,
                payload={
                    # chkdsk asks Y/N when the volume is in use; answer it up
                    # front so the call cannot block on stdin.
                    "argv": ["cmd.exe", "/c", f"echo Y| chkdsk.exe {drive} /f /r"],
                    "timeout": 120,
                    "ok_codes": [0, 1, 2, 3],
                },
            )
