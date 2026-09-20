"""Attack surface: what this machine exposes to the network.

Every finding here answers one question — if someone were on your network
right now, what could they reach? Ports are judged by which interface they
bind to, because 127.0.0.1 is a developer's business and 0.0.0.0 is everyone's.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from ..core import winutil
from ..core.issue import Category, FixKind, Issue, Severity
from ..core.scanner import ScanContext, Scanner, register

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore

#: Ports that are a problem specifically because they are reachable.
NOTABLE_PORTS: Dict[int, tuple] = {
    445: ("SMB file sharing", Severity.HIGH,
          "SMB exposed to a network is how ransomware spreads laterally and how "
          "EternalBlue-class exploits land."),
    139: ("NetBIOS session", Severity.HIGH,
          "Legacy SMB transport. Nothing modern needs it."),
    3389: ("Remote Desktop", Severity.CRITICAL,
           "RDP reachable from a network is among the most attacked services in "
           "existence; exposed RDP is a leading ransomware entry point."),
    5900: ("VNC", Severity.CRITICAL,
           "VNC often ships with weak or no authentication."),
    23: ("Telnet", Severity.CRITICAL, "Telnet is unencrypted, including its password."),
    21: ("FTP", Severity.HIGH, "FTP credentials cross the network in clear text."),
    135: ("RPC endpoint mapper", Severity.MEDIUM,
          "Windows RPC. Needed locally; should not face an untrusted network."),
    5985: ("WinRM (HTTP)", Severity.HIGH,
           "Remote PowerShell over unencrypted HTTP."),
    1433: ("MSSQL", Severity.HIGH, "Database engine reachable from the network."),
    3306: ("MySQL", Severity.HIGH, "Database engine reachable from the network."),
    5432: ("PostgreSQL", Severity.HIGH, "Database engine reachable from the network."),
    6379: ("Redis", Severity.CRITICAL,
           "Redis has no authentication by default and is trivially abused for "
           "remote code execution when exposed."),
    27017: ("MongoDB", Severity.HIGH, "Historically exposed without authentication."),
    9200: ("Elasticsearch", Severity.HIGH, "Frequently exposed without authentication."),
}


def _is_wildcard(addr: str) -> bool:
    """True when the socket is bound to every interface, not just loopback."""
    if not addr:
        return False
    if addr in ("0.0.0.0", "::", "*"):
        return True
    try:
        return not ipaddress.ip_address(addr.strip("[]")).is_loopback
    except ValueError:
        return False


@register
class AttackSurfaceScanner(Scanner):
    id = "network"
    name = "Network & attack surface"
    description = "Listening ports, shares, RDP and SMB exposure, network profile."
    category = Category.NETWORK
    weight = 2.0

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return

        yield from self._network_profile(ctx)
        yield from self._listening_ports(ctx)
        yield from self._shares(ctx)
        yield from self._rdp(ctx)
        yield from self._smb(ctx)

    # ------------------------------------------------------------------

    def _network_profile(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking network profiles", 0.05)
        data = winutil.powershell_json(
            "Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,"
            "NetworkCategory",
            timeout=60,
        )
        if isinstance(data, dict):
            data = [data]
        for profile in data or []:
            category = str(profile.get("NetworkCategory", ""))
            # PowerShell may hand back the enum name or its integer value.
            is_private = category.lower() in ("private", "1", "domainauthenticated", "2")
            if is_private and category.lower() != "private":
                continue
            if category.lower() in ("private", "1"):
                yield Issue(
                    category=self.category,
                    title=f"Network '{profile.get('Name')}' is set to Private",
                    detail=(
                        "On a Private network Windows relaxes the firewall and enables "
                        "discovery and file sharing. Correct for your own home network; "
                        "wrong for a cafe, hotel or office guest network.\n\n"
                        f"Adapter: {profile.get('InterfaceAlias')}"
                    ),
                    severity=Severity.INFO,
                    fix_kind=FixKind.MANUAL,
                    remediation_hint=(
                        "If this is not a network you control, switch it to Public in "
                        "Settings > Network & Internet."
                    ),
                )

    # ------------------------------------------------------------------

    def _listening_ports(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Enumerating listening ports", 0.25)
        if psutil is None:
            return

        exposed: List[tuple] = []
        loopback_only = 0
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return

        for conn in connections:
            if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                continue
            addr = conn.laddr.ip
            port = conn.laddr.port
            if not _is_wildcard(addr):
                loopback_only += 1
                continue
            name, exe = self._process_of(conn.pid)
            exposed.append((port, addr, name, exe, conn.pid))

        # Named, known-risky services first — one finding each, because the
        # remediation differs per service.
        seen_ports = set()
        for port, addr, name, exe, pid in sorted(exposed):
            if port in NOTABLE_PORTS and port not in seen_ports:
                seen_ports.add(port)
                label, severity, why = NOTABLE_PORTS[port]
                yield Issue(
                    category=self.category,
                    title=f"{label} is listening on all interfaces (port {port})",
                    detail=(
                        f"{why}\n\n"
                        f"Bound to: {addr}:{port}\n"
                        f"Process:  {name} (PID {pid})\n"
                        f"Path:     {exe or 'unknown'}\n\n"
                        "Bound to all interfaces means anything that can route to this "
                        "machine can attempt to connect. Your firewall may still be "
                        "blocking it — check the Firewall section alongside this."
                    ),
                    severity=severity,
                    fix_kind=FixKind.MANUAL,
                    remediation_hint=(
                        "If you do not need it, stop the service. If you do, restrict "
                        "it with a firewall rule scoped to specific addresses."
                    ),
                )

        others = [e for e in exposed if e[0] not in NOTABLE_PORTS]
        if others:
            rows = "\n".join(
                f"  • {port:<6} {name or '?'}  (PID {pid})  {exe or ''}".rstrip()
                for port, addr, name, exe, pid in sorted(others)[:40]
            )
            more = f"\n  … and {len(others) - 40} more" if len(others) > 40 else ""
            yield Issue(
                category=self.category,
                title=f"{len(others)} other port(s) listening on all interfaces",
                detail=(
                    "Not known-dangerous services, but each is a door. Anything you "
                    "do not recognise is worth identifying.\n\n" + rows + more
                ),
                severity=Severity.LOW if len(others) < 10 else Severity.MEDIUM,
                fix_kind=FixKind.MANUAL,
            )

        if loopback_only:
            yield Issue(
                category=self.category,
                title=f"{loopback_only} service(s) listening on loopback only",
                detail=(
                    "Bound to 127.0.0.1, so they are reachable only from this machine. "
                    "This is the correct way to run local development servers and "
                    "databases — listed for completeness, not as a problem."
                ),
                severity=Severity.INFO,
            )

    @staticmethod
    def _process_of(pid: Optional[int]) -> tuple:
        if not pid or psutil is None:
            return (None, None)
        try:
            proc = psutil.Process(pid)
            return (proc.name(), proc.exe())
        except Exception:
            try:
                return (psutil.Process(pid).name(), None)
            except Exception:
                return (None, None)

    # ------------------------------------------------------------------

    def _shares(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking file shares", 0.65)
        data = winutil.powershell_json(
            "Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name,Path,"
            "Description,ShareType",
            timeout=60,
        )
        if isinstance(data, dict):
            data = [data]
        # Admin shares (C$, ADMIN$, IPC$) exist on every Windows box by default.
        default_names = {"ADMIN$", "IPC$", "print$"}
        custom = [
            s for s in (data or [])
            if str(s.get("Name", "")) not in default_names
            and not (str(s.get("Name", "")).endswith("$") and len(str(s.get("Name", ""))) == 2)
        ]
        if not custom:
            return
        for share in custom:
            name = share.get("Name")
            path = share.get("Path")
            access = winutil.powershell_json(
                f"Get-SmbShareAccess -Name '{name}' -ErrorAction SilentlyContinue | "
                "Select-Object AccountName,AccessRight,AccessControlType",
                timeout=45,
            )
            if isinstance(access, dict):
                access = [access]
            everyone = [
                a for a in (access or [])
                if str(a.get("AccountName", "")).lower() in ("everyone", "заходи", "\\everyone")
                and str(a.get("AccessControlType", "")).lower() in ("allow", "0")
            ]
            rows = "\n".join(
                f"  • {a.get('AccountName')}: {a.get('AccessRight')} ({a.get('AccessControlType')})"
                for a in (access or [])
            )
            yield Issue(
                category=self.category,
                title=(
                    f"File share '{name}' is open to Everyone"
                    if everyone else f"File share '{name}' is published"
                ),
                detail=(
                    f"Path: {path}\n\nPermissions:\n{rows or '  (could not read)'}\n\n"
                    + (
                        "'Everyone' means any account that can reach this machine over "
                        "SMB, including anonymous access in some configurations."
                        if everyone else
                        "Anyone with the listed permissions can reach these files over "
                        "the network."
                    )
                ),
                severity=Severity.HIGH if everyone else Severity.MEDIUM,
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "Remove the share if it is not in use, or replace Everyone with "
                    "specific accounts."
                ),
            )

    # ------------------------------------------------------------------

    def _rdp(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking Remote Desktop", 0.8)
        rc, out, _ = winutil.powershell(
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
            "Terminal Server').fDenyTSConnections",
            timeout=30,
        )
        if rc != 0 or out.strip() != "0":
            return  # RDP disabled, nothing to say

        nla = winutil.powershell_json(
            "Get-CimInstance -Namespace root\\CIMV2\\TerminalServices "
            "-ClassName Win32_TSGeneralSetting -ErrorAction SilentlyContinue | "
            "Select-Object UserAuthenticationRequired",
            timeout=60,
        )
        nla_on = bool(nla and nla.get("UserAuthenticationRequired"))
        yield Issue(
            category=self.category,
            title=(
                "Remote Desktop is enabled"
                + ("" if nla_on else " without Network Level Authentication")
            ),
            detail=(
                "RDP accepts incoming connections on this machine.\n\n"
                + (
                    "Network Level Authentication is on, which means credentials are "
                    "required before a session is established — that is the correct "
                    "setting."
                    if nla_on else
                    "Network Level Authentication is OFF. Without it, an unauthenticated "
                    "attacker can reach the full login surface, and the machine is "
                    "exposed to pre-auth vulnerability classes."
                )
            ),
            severity=Severity.MEDIUM if nla_on else Severity.CRITICAL,
            fix_kind=FixKind.NONE if nla_on else FixKind.RUN_COMMAND,
            fix_label="" if nla_on else "Require Network Level Authentication",
            requires_admin=not nla_on,
            payload={} if nla_on else {
                "argv": ["reg.exe", "add",
                         r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                         "/v", "UserAuthentication", "/t", "REG_DWORD", "/d", "1", "/f"],
                "timeout": 60,
            },
            remediation_hint=(
                "If you never use Remote Desktop, turn it off entirely in "
                "Settings > System > Remote Desktop."
            ),
        )

    # ------------------------------------------------------------------

    def _smb(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking SMB configuration", 0.92)
        cfg = winutil.powershell_json(
            "Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object "
            "EnableSMB1Protocol,RequireSecuritySignature,EnableSecuritySignature",
            timeout=60,
        )
        if not cfg:
            return
        if cfg.get("EnableSMB1Protocol"):
            yield Issue(
                category=self.category,
                title="SMBv1 is enabled",
                detail=(
                    "SMBv1 is a 1980s protocol with no meaningful security. It is the "
                    "vector WannaCry and NotPetya used, Microsoft deprecated it, and "
                    "modern Windows does not install it by default — so something "
                    "turned it on here."
                ),
                severity=Severity.CRITICAL,
                fix_kind=FixKind.RUN_COMMAND,
                fix_label="Disable SMBv1",
                requires_admin=True,
                payload={
                    "argv": ["powershell.exe", "-NoProfile", "-Command",
                             "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"],
                    "timeout": 120,
                },
            )
        if cfg.get("RequireSecuritySignature") is False:
            yield Issue(
                category=self.category,
                title="SMB signing is not required",
                detail=(
                    "Without required signing, SMB sessions can be relayed and "
                    "tampered with by anyone positioned on the network path — the "
                    "basis of NTLM relay attacks."
                ),
                severity=Severity.MEDIUM,
                fix_kind=FixKind.RUN_COMMAND,
                fix_label="Require SMB signing",
                requires_admin=True,
                payload={
                    "argv": ["powershell.exe", "-NoProfile", "-Command",
                             "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"],
                    "timeout": 120,
                },
                remediation_hint=(
                    "Harmless on modern networks; can break very old NAS devices."
                ),
            )
