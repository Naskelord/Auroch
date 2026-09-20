"""Performance: boot time, resource pressure, power plan, page file."""
from __future__ import annotations

from typing import Iterable

from ..core import winutil
from ..core.issue import Category, FixKind, Issue, Severity, human_bytes
from ..core.scanner import ScanContext, Scanner, register

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore


@register
class PerformanceScanner(Scanner):
    id = "performance"
    name = "Performance"
    description = "Boot time, memory pressure, power plan, page file."
    category = Category.PERFORMANCE
    weight = 1.5

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return

        # Boot time ---------------------------------------------------------
        ctx.report("Measuring last boot duration", 0.1)
        data = winutil.powershell_json(
            "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-"
            "Performance/Operational'; Id=100} -MaxEvents 5 -ErrorAction SilentlyContinue "
            "| Select-Object TimeCreated,Message",
            timeout=120,
        )
        if isinstance(data, dict):
            data = [data]
        if data:
            import re

            times = []
            for event in data:
                match = re.search(r"Boot Duration\s*:\s*(\d+)", str(event.get("Message", "")))
                if match:
                    times.append(int(match.group(1)) / 1000.0)
            if times:
                avg = sum(times) / len(times)
                if avg > 90:
                    sev = Severity.MEDIUM
                    note = "That is slow even for a mechanical drive."
                elif avg > 45:
                    sev = Severity.LOW
                    note = "Slower than a healthy SSD install, which boots in 15–25 seconds."
                else:
                    sev = Severity.INFO
                    note = "Within normal range."
                yield Issue(
                    category=self.category,
                    title=f"Average boot time: {avg:.0f} seconds",
                    detail=f"{note}\n\nMeasured over the last {len(times)} boot(s).",
                    severity=sev,
                    fix_kind=FixKind.MANUAL,
                    remediation_hint=(
                        "Trim startup programs in Task Manager > Startup apps."
                        if sev > Severity.INFO else ""
                    ),
                )

        # Memory and CPU ----------------------------------------------------
        if psutil is not None:
            ctx.report("Sampling memory and CPU", 0.5)
            mem = psutil.virtual_memory()
            if mem.percent > 85:
                top = self._top_processes("memory")
                yield Issue(
                    category=self.category,
                    title=f"Memory is {mem.percent:.0f}% used ({human_bytes(mem.used)} of {human_bytes(mem.total)})",
                    detail=(
                        "At this level Windows is paging to disk constantly, which "
                        "feels like a slow machine no matter how fast the CPU is.\n\n"
                        "Largest consumers right now:\n" + top
                    ),
                    severity=Severity.HIGH if mem.percent > 92 else Severity.MEDIUM,
                    fix_kind=FixKind.MANUAL,
                    remediation_hint="Close what you are not using, or add RAM.",
                )

            total_gb = mem.total / (1024 ** 3)
            if total_gb < 7.5:
                yield Issue(
                    category=self.category,
                    title=f"Installed RAM: {total_gb:.0f} GB",
                    detail=(
                        "8 GB is the practical floor for Windows 11 with a browser "
                        "and an IDE open. Below that, paging dominates."
                    ),
                    severity=Severity.LOW,
                    fix_kind=FixKind.MANUAL,
                )

        # Power plan --------------------------------------------------------
        ctx.report("Checking the power plan", 0.75)
        rc, out, _ = winutil.run(["powercfg.exe", "/getactivescheme"], timeout=30)
        if rc == 0 and "power saver" in out.lower():
            yield Issue(
                category=self.category,
                title="Active power plan is Power Saver",
                detail=(
                    "Power Saver caps CPU frequency. On a desktop this is pure lost "
                    "performance; on a laptop it is a deliberate trade."
                ),
                severity=Severity.LOW,
                fix_kind=FixKind.RUN_COMMAND,
                fix_label="Switch to Balanced",
                payload={
                    "argv": ["powercfg.exe", "/setactive",
                             "381b4222-f694-41f0-9685-ff5bb260df2e"],
                    "timeout": 60,
                },
            )

        # Fast startup + page file ------------------------------------------
        ctx.report("Checking the page file", 0.9)
        pagefile = winutil.powershell_json(
            "Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | "
            "Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage",
            timeout=60,
        )
        if isinstance(pagefile, dict):
            pagefile = [pagefile]
        for pf in pagefile or []:
            allocated = int(pf.get("AllocatedBaseSize") or 0)
            peak = int(pf.get("PeakUsage") or 0)
            if allocated and peak >= allocated * 0.9:
                yield Issue(
                    category=self.category,
                    title="Page file has been running at its size limit",
                    detail=(
                        f"Peak usage {peak} MB of {allocated} MB allocated. When the "
                        "page file fills, applications start failing with "
                        "out-of-memory errors that look like bugs in the app.\n\n"
                        f"File: {pf.get('Name')}"
                    ),
                    severity=Severity.MEDIUM,
                    fix_kind=FixKind.MANUAL,
                    remediation_hint=(
                        "Let Windows manage the page file size, or add physical RAM."
                    ),
                )

    @staticmethod
    def _top_processes(by: str = "memory", limit: int = 5) -> str:
        if psutil is None:
            return "  (psutil not installed)"
        rows = []
        for proc in psutil.process_iter(["name", "memory_info"]):
            try:
                info = proc.info
                rss = info["memory_info"].rss if info.get("memory_info") else 0
                rows.append((info.get("name") or "?", rss))
            except Exception:
                continue
        rows.sort(key=lambda r: -r[1])
        merged = {}
        for name, rss in rows:
            merged[name] = merged.get(name, 0) + rss
        top = sorted(merged.items(), key=lambda r: -r[1])[:limit]
        return "\n".join(f"  • {name} — {human_bytes(rss)}" for name, rss in top)
