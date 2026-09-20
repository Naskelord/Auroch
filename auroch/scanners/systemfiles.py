"""Windows system file integrity.

This is Fortect's headline feature, done with Microsoft's own tools instead of
a proprietary file repository. DISM repairs the component store from Windows
Update; SFC then repairs live system files from the repaired store. That is
the same outcome, from a source you can actually trust.
"""
from __future__ import annotations

import re
from typing import Iterable

from ..core import winutil
from ..core.issue import Category, FixKind, Issue, Severity
from ..core.scanner import ScanContext, Scanner, register


@register
class SystemFileScanner(Scanner):
    id = "systemfiles"
    name = "Windows system files"
    description = "Component store health and protected system file integrity."
    category = Category.SYSTEM_FILES
    weight = 4.0

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return

        if not ctx.is_admin:
            yield Issue(
                category=self.category,
                title="System file integrity was not checked",
                detail=(
                    "Both DISM and SFC require an elevated process. Auroch is "
                    "running as a standard user, so this check was skipped rather "
                    "than reported as a pass."
                ),
                severity=Severity.INFO,
                fix_kind=FixKind.MANUAL,
                remediation_hint="Restart Auroch as administrator to include this check.",
            )
            return

        # DISM CheckHealth is fast; ScanHealth is thorough but slow -----------
        ctx.report("Checking the Windows component store (DISM)", 0.05)
        verb = "/ScanHealth" if ctx.deep else "/CheckHealth"
        rc, out, err = winutil.run(
            ["dism.exe", "/Online", "/Cleanup-Image", verb],
            timeout=1800 if ctx.deep else 300,
        )
        blob = (out + err).lower()

        if "repairable" in blob:
            yield Issue(
                category=self.category,
                title="Windows component store is corrupted but repairable",
                detail=(
                    "DISM found damage in the component store (WinSxS). This is the "
                    "source SFC repairs from, so it has to be fixed first.\n\n"
                    "The repair downloads clean files from Windows Update and can "
                    "take 15–30 minutes."
                ),
                severity=Severity.HIGH,
                fix_kind=FixKind.RUN_COMMAND,
                fix_label="Run DISM /RestoreHealth",
                requires_admin=True,
                payload={
                    "argv": ["dism.exe", "/Online", "/Cleanup-Image", "/RestoreHealth"],
                    "timeout": 3600,
                },
            )
        elif "not repairable" in blob:
            yield Issue(
                category=self.category,
                title="Windows component store corruption is not repairable",
                detail=(
                    "DISM cannot fix this from Windows Update. The usual remaining "
                    "options are an in-place upgrade repair install, or a clean "
                    "install."
                ),
                severity=Severity.CRITICAL,
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "Download the Windows ISO, mount it, run setup.exe and choose "
                    "'Keep personal files and apps'. This repairs Windows without "
                    "losing anything."
                ),
            )
        elif "no component store corruption" in blob:
            yield Issue(
                category=self.category,
                title="Windows component store is healthy",
                detail="DISM reported no corruption in WinSxS.",
                severity=Severity.INFO,
            )
        elif rc != 0:
            yield Issue(
                category=self.category,
                title="DISM could not complete its check",
                detail=f"Exit code {rc}.\n\n{(err or out).strip()[:600]}",
                severity=Severity.MEDIUM,
                fix_kind=FixKind.MANUAL,
            )

        if ctx.cancelled:
            return

        # SFC ---------------------------------------------------------------
        ctx.report("Verifying protected system files (SFC) — this takes a while", 0.4)
        rc, out, err = winutil.run(["sfc.exe", "/verifyonly"], timeout=2400)
        # sfc writes UTF-16 to the pipe; decode leftovers defensively.
        text = (out + err).replace("\x00", "")
        low = text.lower()

        if "did not find any integrity violations" in low:
            yield Issue(
                category=self.category,
                title="Protected system files are intact",
                detail="SFC verified every protected file and found no violations.",
                severity=Severity.INFO,
            )
        elif "found integrity violations" in low:
            yield Issue(
                category=self.category,
                title="Damaged or modified Windows system files detected",
                detail=(
                    "SFC found protected system files that no longer match their "
                    "known-good versions. This is the class of problem that shows up "
                    "as random crashes, features that stop working, or apps that "
                    "fail to start.\n\n"
                    "The fix replaces them from the component store."
                ),
                severity=Severity.HIGH,
                fix_kind=FixKind.RUN_COMMAND,
                fix_label="Run SFC /scannow to repair",
                requires_admin=True,
                payload={"argv": ["sfc.exe", "/scannow"], "timeout": 3600},
                remediation_hint=(
                    "If DISM also reported corruption, fix that first — SFC repairs "
                    "from the component store, so a damaged store means a failed repair."
                ),
            )
        elif "could not perform" in low or rc not in (0,):
            yield Issue(
                category=self.category,
                title="SFC could not complete the verification",
                detail=(
                    f"Exit code {rc}. A pending reboot or another servicing "
                    f"operation in progress is the usual cause.\n\n{text.strip()[:600]}"
                ),
                severity=Severity.MEDIUM,
                fix_kind=FixKind.MANUAL,
                remediation_hint="Restart Windows, then run the scan again.",
            )

        # Pending reboot -----------------------------------------------------
        if self._pending_reboot():
            yield Issue(
                category=self.category,
                title="Windows is waiting for a restart",
                detail=(
                    "A servicing operation has finished but needs a reboot to apply. "
                    "Until then, further repairs and updates may fail for reasons "
                    "that look unrelated."
                ),
                severity=Severity.MEDIUM,
                fix_kind=FixKind.MANUAL,
                requires_restart=True,
                remediation_hint="Restart the machine before running further repairs.",
            )

    @staticmethod
    def _pending_reboot() -> bool:
        script = (
            "$p=$false; "
            "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') {$p=$true}; "
            "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') {$p=$true}; "
            "$p"
        )
        rc, out, _ = winutil.powershell(script, timeout=30)
        return rc == 0 and out.strip().lower() == "true"
