"""Security posture: antivirus, firewall, UAC, updates, encryption.

Replaces Fortect's bundled Avira engine with the AV that is already on the
machine and already has kernel-level hooks — Microsoft Defender. Auroch reads
its state and can drive an on-demand scan; it does not try to be an AV itself.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from ..core import winutil
from ..core.issue import Category, FixKind, Issue, Severity
from ..core.scanner import ScanContext, Scanner, register


def _parse_ps_date(value) -> Optional[datetime]:
    """PowerShell JSON dates arrive as '/Date(1690000000000)/' or ISO text."""
    if not value:
        return None
    text = str(value)
    if text.startswith("/Date("):
        try:
            ms = int(text[6:].split(")")[0].split("+")[0].split("-")[0])
            return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        except Exception:
            return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        return None


@register
class SecurityScanner(Scanner):
    id = "security"
    name = "Security posture"
    description = "Antivirus state, firewall, UAC, updates and disk encryption."
    category = Category.SECURITY
    weight = 2.0

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return

        # --- Registered AV products ---------------------------------------
        ctx.report("Checking registered antivirus products", 0.1)
        products = winutil.powershell_json(
            "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct "
            "-ErrorAction SilentlyContinue | Select-Object displayName,productState",
            timeout=60,
        )
        if isinstance(products, dict):
            products = [products]
        names = [p.get("displayName", "?") for p in (products or [])]
        if len(names) > 1:
            yield Issue(
                category=self.category,
                title=f"{len(names)} antivirus products are registered",
                detail=(
                    "Multiple real-time scanners hooking the same file operations "
                    "fight each other, slow the machine down, and each can quarantine "
                    "the other's files.\n\nRegistered: " + ", ".join(names)
                ),
                severity=Severity.MEDIUM,
                fix_kind=FixKind.MANUAL,
                remediation_hint="Keep one. Uninstall the rest through Apps & features.",
            )
        elif not names:
            yield Issue(
                category=self.category,
                title="No antivirus product is registered with Windows",
                detail="Windows Security Center reports no registered AV product.",
                severity=Severity.HIGH,
                fix_kind=FixKind.MANUAL,
                remediation_hint="Enable Microsoft Defender in Windows Security.",
            )

        # --- Defender state -------------------------------------------------
        ctx.report("Reading Microsoft Defender status", 0.3)
        status = winutil.powershell_json(
            "Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object "
            "RealTimeProtectionEnabled,AntivirusSignatureAge,AntivirusSignatureLastUpdated,"
            "QuickScanAge,AMServiceEnabled,BehaviorMonitorEnabled,TamperProtectionSource",
            timeout=90,
        )
        if status:
            if status.get("RealTimeProtectionEnabled") is False:
                yield Issue(
                    category=self.category,
                    title="Defender real-time protection is switched off",
                    detail=(
                        "Nothing is inspecting files as they are written or executed. "
                        "If you turned this off deliberately for a tool, fine — "
                        "otherwise turn it back on."
                    ),
                    severity=Severity.CRITICAL,
                    fix_kind=FixKind.RUN_COMMAND,
                    fix_label="Re-enable real-time protection",
                    requires_admin=True,
                    payload={
                        "argv": ["powershell.exe", "-NoProfile", "-Command",
                                 "Set-MpPreference -DisableRealtimeMonitoring $false"],
                        "timeout": 120,
                    },
                )

            age = status.get("AntivirusSignatureAge")
            if isinstance(age, int) and age > 3:
                yield Issue(
                    category=self.category,
                    title=f"Antivirus definitions are {age} days old",
                    detail=(
                        "Definitions normally update several times a day. Being days "
                        "behind usually means the update service is broken, not idle."
                    ),
                    severity=Severity.HIGH if age > 7 else Severity.MEDIUM,
                    fix_kind=FixKind.RUN_COMMAND,
                    fix_label="Update definitions now",
                    payload={
                        "argv": ["powershell.exe", "-NoProfile", "-Command",
                                 "Update-MpSignature"],
                        "timeout": 600,
                    },
                )

            quick = status.get("QuickScanAge")
            if isinstance(quick, int) and quick > 14:
                yield Issue(
                    category=self.category,
                    title=f"Last malware scan was {quick} days ago",
                    detail="Real-time protection catches most things, but a periodic full sweep still finds dormant files.",
                    severity=Severity.LOW,
                    fix_kind=FixKind.RUN_COMMAND,
                    fix_label="Run a Defender quick scan",
                    payload={
                        "argv": ["powershell.exe", "-NoProfile", "-Command",
                                 "Start-MpScan -ScanType QuickScan"],
                        "timeout": 1800,
                    },
                )

            if status.get("BehaviorMonitorEnabled") is False:
                yield Issue(
                    category=self.category,
                    title="Defender behaviour monitoring is disabled",
                    detail="The component that catches malicious behaviour from files that are not yet in the signature set.",
                    severity=Severity.HIGH,
                    fix_kind=FixKind.RUN_COMMAND,
                    fix_label="Re-enable behaviour monitoring",
                    requires_admin=True,
                    payload={
                        "argv": ["powershell.exe", "-NoProfile", "-Command",
                                 "Set-MpPreference -DisableBehaviorMonitoring $false"],
                        "timeout": 120,
                    },
                )

        # --- Active threats --------------------------------------------------
        ctx.report("Checking for detected threats", 0.5)
        threats = winutil.powershell_json(
            "Get-MpThreatDetection -ErrorAction SilentlyContinue | "
            "Where-Object {$_.ThreatStatusID -in 1,102,103} | "
            "Select-Object ThreatID,Resources,InitialDetectionTime",
            timeout=90,
        )
        if isinstance(threats, dict):
            threats = [threats]
        if threats:
            yield Issue(
                category=self.category,
                title=f"Defender has {len(threats)} unresolved threat detection(s)",
                detail=(
                    "These were detected but not successfully removed or quarantined.\n\n"
                    + "\n".join(f"  • {t.get('Resources')}" for t in threats[:15])
                ),
                severity=Severity.CRITICAL,
                fix_kind=FixKind.RUN_COMMAND,
                fix_label="Tell Defender to remove all active threats",
                requires_admin=True,
                payload={
                    "argv": ["powershell.exe", "-NoProfile", "-Command",
                             "Remove-MpThreat"],
                    "timeout": 1800,
                },
            )

        # --- Firewall ---------------------------------------------------------
        ctx.report("Checking the firewall", 0.65)
        profiles = winutil.powershell_json(
            "Get-NetFirewallProfile | Select-Object Name,Enabled", timeout=60
        )
        if isinstance(profiles, dict):
            profiles = [profiles]
        off = [p.get("Name") for p in (profiles or []) if not p.get("Enabled")]
        if off:
            yield Issue(
                category=self.category,
                title=f"Firewall is off for: {', '.join(str(o) for o in off)}",
                detail="Inbound connections are unfiltered on those network profiles.",
                severity=Severity.HIGH,
                fix_kind=FixKind.RUN_COMMAND,
                fix_label="Turn the firewall back on",
                requires_admin=True,
                payload={
                    "argv": ["powershell.exe", "-NoProfile", "-Command",
                             "Set-NetFirewallProfile -All -Enabled True"],
                    "timeout": 120,
                },
            )

        # --- UAC ---------------------------------------------------------------
        ctx.report("Checking User Account Control", 0.75)
        rc, out, _ = winutil.powershell(
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
            "\\Policies\\System').EnableLUA",
            timeout=30,
        )
        if rc == 0 and out.strip() == "0":
            yield Issue(
                category=self.category,
                title="User Account Control is disabled",
                detail=(
                    "With UAC off, any program you launch runs with full administrator "
                    "rights and never asks. It is the single largest self-inflicted "
                    "hole in a Windows install."
                ),
                severity=Severity.CRITICAL,
                fix_kind=FixKind.RUN_COMMAND,
                fix_label="Re-enable UAC (requires restart)",
                requires_admin=True,
                requires_restart=True,
                payload={
                    "argv": ["reg.exe", "add",
                             r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                             "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "1", "/f"],
                    "timeout": 60,
                },
            )

        # --- Hosts file tampering ------------------------------------------------
        ctx.report("Checking the hosts file", 0.85)
        yield from self._hosts_file()

        # --- Pending Windows updates ---------------------------------------------
        ctx.report("Checking for pending security updates", 0.95)
        if ctx.deep:
            yield from self._pending_updates()

    # -----------------------------------------------------------------------

    #: Hostname suffixes that developer tooling writes into hosts by design.
    #: Docker Desktop, Rancher, Lima and OrbStack all point these at the host's
    #: LAN address, which is exactly the shape a naive check calls hijacking.
    TOOL_SUFFIXES = (
        ".docker.internal",
        ".lima.internal",
        ".orb.local",
        ".rancher.internal",
        ".wsl.internal",
    )

    def _hosts_file(self) -> Iterable[Issue]:
        import ipaddress
        from pathlib import Path

        hosts = Path(winutil.known_folders()["windir"]) / "System32" / "drivers" / "etc" / "hosts"
        try:
            # utf-8-sig, not utf-8: Windows ships this file with a BOM, and a
            # BOM glued to the first character defeats a startswith("#") comment
            # test — str.strip() does not remove U+FEFF.
            raw = hosts.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            return

        entries = []  # (ip, hostname)
        for line in raw.splitlines():
            line = line.strip().lstrip("﻿").strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                # Anything whose first token is not an IP is not a hosts entry,
                # so it cannot be a redirection either.
                addr = ipaddress.ip_address(parts[0])
            except ValueError:
                continue
            for name in parts[1:]:
                if name.startswith("#"):
                    break
                entries.append((addr, name))

        blocked = [e for e in entries if e[0].is_loopback or e[0].is_unspecified]
        redirected = [e for e in entries if e not in blocked]

        # Split by where the traffic actually goes. A name pointed at a public
        # internet address is the hijack case. A name pointed at a machine on
        # your own LAN is almost always Docker, WSL, a VPN or a local test rig.
        public = [e for e in redirected
                  if e[0].is_global and not e[0].is_private]
        lan = [e for e in redirected if e not in public]
        lan_tool = [e for e in lan
                    if e[1].lower().endswith(self.TOOL_SUFFIXES)]
        lan_other = [e for e in lan if e not in lan_tool]

        if public:
            yield Issue(
                category=self.category,
                title=f"Hosts file sends {len(public)} name(s) to public internet addresses",
                detail=(
                    "The hosts file overrides DNS. These entries point real "
                    "hostnames at machines on the public internet, which is how "
                    "traffic gets silently redirected to a server you did not "
                    "choose.\n\n"
                    + "\n".join(f"  {ip}  {name}" for ip, name in public[:20])
                    + f"\n\nFile: {hosts}"
                ),
                severity=Severity.HIGH,
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "Open the file in an elevated editor and remove anything you "
                    "did not add yourself."
                ),
            )

        if lan_other:
            yield Issue(
                category=self.category,
                title=f"Hosts file maps {len(lan_other)} name(s) to private addresses",
                detail=(
                    "These point at private or non-routable addresses, not the "
                    "public internet. That is normal for a VPN, a NAS, a home lab "
                    "or a local test server — listed so you can confirm you "
                    "recognise them, not because anything looks wrong.\n\n"
                    + "\n".join(f"  {ip}  {name}" for ip, name in lan_other[:20])
                    + f"\n\nFile: {hosts}"
                ),
                severity=Severity.INFO,
                fix_kind=FixKind.MANUAL,
            )

        # lan_tool is deliberately silent. Docker writes host.docker.internal
        # every time it starts; reporting it on every scan would be noise, and
        # noise is how a scanner teaches you to ignore it.

        if len(blocked) > 200:
            yield Issue(
                category=self.category,
                title=f"Hosts file blocks {len(blocked)} name(s)",
                detail=(
                    "Entries pointed at 127.0.0.1 or 0.0.0.0 — almost certainly an "
                    "ad-blocking list. Harmless, though a very large hosts file "
                    "slows name resolution on some systems."
                ),
                severity=Severity.INFO,
            )

    def _pending_updates(self) -> Iterable[Issue]:
        data = winutil.powershell_json(
            "$s=New-Object -ComObject Microsoft.Update.Session; "
            "$r=$s.CreateUpdateSearcher().Search('IsInstalled=0 and Type=''Software'''); "
            "$r.Updates | Select-Object Title,MsrcSeverity",
            timeout=300,
        )
        if isinstance(data, dict):
            data = [data]
        if not data:
            return
        critical = [u for u in data if str(u.get("MsrcSeverity", "")).lower() in ("critical", "important")]
        yield Issue(
            category=self.category,
            title=f"{len(data)} Windows update(s) pending"
                  + (f", {len(critical)} rated Critical/Important" if critical else ""),
            detail="\n".join(f"  • {u.get('Title')}" for u in data[:20]),
            severity=Severity.HIGH if critical else Severity.LOW,
            fix_kind=FixKind.MANUAL,
            remediation_hint="Settings > Windows Update > Check for updates.",
        )
