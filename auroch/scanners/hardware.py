"""Hardware inventory. Informational — nothing here is ever a 'problem'."""
from __future__ import annotations

import platform
from typing import Iterable

from ..core import winutil
from ..core.issue import Category, Issue, Severity, human_bytes
from ..core.scanner import ScanContext, Scanner, register

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore


@register
class HardwareScanner(Scanner):
    id = "hardware"
    name = "Hardware inventory"
    description = "CPU, memory, GPU, storage and Windows build."
    category = Category.HARDWARE
    weight = 1.0

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return

        ctx.report("Reading system information", 0.2)
        os_info = winutil.powershell_json(
            "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,"
            "BuildNumber,OSArchitecture,InstallDate,LastBootUpTime",
            timeout=60,
        ) or {}
        cs = winutil.powershell_json(
            "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,"
            "TotalPhysicalMemory",
            timeout=60,
        ) or {}
        cpu = winutil.powershell_json(
            "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,"
            "NumberOfLogicalProcessors,MaxClockSpeed",
            timeout=60,
        ) or {}
        if isinstance(cpu, list):
            cpu = cpu[0] if cpu else {}

        lines = [
            f"Windows:      {os_info.get('Caption', platform.system())}",
            f"Build:        {os_info.get('BuildNumber', '?')}  ({os_info.get('OSArchitecture', '?')})",
            f"Machine:      {cs.get('Manufacturer', '?')} {cs.get('Model', '')}".rstrip(),
            f"CPU:          {cpu.get('Name', platform.processor())}",
            f"Cores:        {cpu.get('NumberOfCores', '?')} physical / "
            f"{cpu.get('NumberOfLogicalProcessors', '?')} logical",
        ]
        total_mem = cs.get("TotalPhysicalMemory")
        if total_mem:
            lines.append(f"Memory:       {human_bytes(int(total_mem))}")

        yield Issue(
            category=self.category,
            title="System summary",
            detail="\n".join(lines),
            severity=Severity.INFO,
        )

        # Memory modules ----------------------------------------------------
        ctx.report("Reading memory modules", 0.45)
        modules = winutil.powershell_json(
            "Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel,"
            "DeviceLocator,Capacity,Speed,Manufacturer",
            timeout=60,
        )
        if isinstance(modules, dict):
            modules = [modules]
        if modules:
            rows = [
                f"  • {m.get('DeviceLocator', '?')}: "
                f"{human_bytes(int(m.get('Capacity') or 0))} @ {m.get('Speed', '?')} MHz "
                f"({str(m.get('Manufacturer', '')).strip()})"
                for m in modules
            ]
            yield Issue(
                category=self.category,
                title=f"Memory: {len(modules)} module(s) installed",
                detail="\n".join(rows),
                severity=Severity.INFO,
            )

        # GPUs ---------------------------------------------------------------
        ctx.report("Reading graphics adapters", 0.65)
        gpus = winutil.powershell_json(
            "Get-CimInstance Win32_VideoController | Select-Object Name,"
            "DriverVersion,DriverDate,AdapterRAM",
            timeout=60,
        )
        if isinstance(gpus, dict):
            gpus = [gpus]
        for gpu in gpus or []:
            yield Issue(
                category=self.category,
                title=f"Graphics: {gpu.get('Name', '?')}",
                detail=(
                    f"Driver version: {gpu.get('DriverVersion', '?')}\n"
                    f"Driver date:    {_ps_date(gpu.get('DriverDate'))}"
                ),
                severity=Severity.INFO,
            )

        # Storage --------------------------------------------------------------
        ctx.report("Reading storage devices", 0.85)
        disks = winutil.powershell_json(
            "Get-PhysicalDisk | Select-Object FriendlyName,MediaType,Size,"
            "HealthStatus,BusType",
            timeout=60,
        )
        if isinstance(disks, dict):
            disks = [disks]
        if disks:
            rows = [
                f"  • {d.get('FriendlyName', '?')} — "
                f"{human_bytes(int(d.get('Size') or 0))}, "
                f"{d.get('MediaType', '?')}, health {d.get('HealthStatus', '?')}"
                for d in disks
            ]
            yield Issue(
                category=self.category,
                title=f"Storage: {len(disks)} physical disk(s)",
                detail="\n".join(rows),
                severity=Severity.INFO,
            )


def _ps_date(value) -> str:
    if not value:
        return "?"
    text = str(value)
    if text.startswith("/Date("):
        from datetime import datetime

        try:
            ms = int(text[6:].split(")")[0].split("+")[0])
            return datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d")
        except Exception:
            return text
    return text[:10]
