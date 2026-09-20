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


#: Adapter descriptions that mean "this is a virtual switch, not your LAN".
VIRTUAL_ADAPTER_MARKERS = (
    "hyper-v", "vethernet", "wsl", "docker", "virtualbox", "vmware",
    "tap-", "tunnel", "loopback", "npcap", "bluetooth",
)

#: Get-SmbShareAccess returns enums; over JSON they arrive as integers.
SMB_ACCESS_RIGHT = {0: "Full Control", 1: "Change", 2: "Read", 3: "Custom"}
SMB_ACL_TYPE = {0: "Allow", 1: "Deny"}


def _smb_right(value) -> str:
    try:
        return SMB_ACCESS_RIGHT.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)


def _smb_type(value) -> str:
    try:
        return SMB_ACL_TYPE.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)


WILDCARD = "wildcard"   # 0.0.0.0 or :: — every interface, present and future
LOOPBACK = "loopback"   # 127.0.0.1 / ::1 — this machine only
VIRTUAL = "virtual"     # one virtual adapter (Docker, WSL, Hyper-V)
REAL = "real"           # one genuine network interface

#: How much of the world each bind kind exposes you to.
_EXPOSURE_ORDER = {LOOPBACK: -1, VIRTUAL: 0, REAL: 1, WILDCARD: 2}


def _bind_kind(addr: str, adapters: Dict[str, tuple]) -> str:
    """Classify what a listening socket is actually reachable from.

    The earlier version answered a yes/no question — "is this loopback?" — and
    so titled a socket bound to one Docker adapter as "listening on all
    interfaces". Binding to 172.19.176.1 exposes you to containers on that
    switch; binding to 0.0.0.0 exposes you to the network. Those are not the
    same finding and must not carry the same severity.
    """
    if not addr:
        return LOOPBACK
    if addr in ("0.0.0.0", "::", "*"):
        return WILDCARD
    clean = addr.strip("[]").split("%")[0]
    try:
        if ipaddress.ip_address(clean).is_loopback:
            return LOOPBACK
    except ValueError:
        return LOOPBACK
    alias, description = adapters.get(clean, ("", ""))
    haystack = f"{alias} {description}".lower()
    if any(m in haystack for m in VIRTUAL_ADAPTER_MARKERS):
        return VIRTUAL
    return REAL


def _adapter_map() -> Dict[str, tuple]:
    """{ip address: (interface alias, adapter description)}."""
    out: Dict[str, tuple] = {}
    addrs = winutil.powershell_json(
        "Get-NetIPAddress -ErrorAction SilentlyContinue | "
        "Select-Object IPAddress,InterfaceAlias", timeout=60)
    if isinstance(addrs, dict):
        addrs = [addrs]
    descriptions: Dict[str, str] = {}
    nics = winutil.powershell_json(
        "Get-NetAdapter -ErrorAction SilentlyContinue | "
        "Select-Object Name,InterfaceDescription", timeout=60)
    if isinstance(nics, dict):
        nics = [nics]
    for nic in nics or []:
        descriptions[str(nic.get("Name", ""))] = str(nic.get("InterfaceDescription", ""))
    for entry in addrs or []:
        ip = str(entry.get("IPAddress", "")).split("%")[0]
        alias = str(entry.get("InterfaceAlias", ""))
        if ip:
            out[ip] = (alias, descriptions.get(alias, ""))
    return out


def _soften(severity: Severity, steps: int = 2) -> Severity:
    """Lower a severity without dropping below Info."""
    return Severity(max(int(Severity.INFO), int(severity) - steps))


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

        adapters = _adapter_map()
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return

        # A service bound to both 0.0.0.0 and :: is one service with two
        # sockets. Keying by (port, pid) collapses the IPv4/IPv6 pair; without
        # this the reported count is roughly double the truth.
        seen: Dict[tuple, dict] = {}
        loopback_only: set = set()

        for conn in connections:
            if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                continue
            addr = conn.laddr.ip
            port = conn.laddr.port
            kind = _bind_kind(addr, adapters)
            if kind == LOOPBACK:
                loopback_only.add((port, conn.pid))
                continue

            key = (port, conn.pid)
            name, exe = self._process_of(conn.pid)
            existing = seen.get(key)
            if existing is None:
                seen[key] = {"port": port, "pid": conn.pid, "name": name,
                             "exe": exe, "kind": kind, "addrs": {addr},
                             "widest_addr": addr}
            else:
                existing["addrs"].add(addr)
                # Widest exposure wins: a service on both a virtual adapter and
                # a real one is reportable at the real one's level — and must be
                # described by THAT adapter, not by whichever address happens to
                # sort first.
                if _EXPOSURE_ORDER[kind] > _EXPOSURE_ORDER[existing["kind"]]:
                    existing["kind"] = kind
                    existing["widest_addr"] = addr

        entries = list(seen.values())
        named: set = set()

        for entry in sorted(entries, key=lambda e: e["port"]):
            port = entry["port"]
            if port not in NOTABLE_PORTS or port in named:
                continue
            named.add(port)
            label, severity, why = NOTABLE_PORTS[port]
            kind = entry["kind"]
            bound = ", ".join(sorted(entry["addrs"]))

            if kind == WILDCARD:
                where = "on all interfaces"
                reach = ("Bound to all interfaces means anything that can route to "
                         "this machine can attempt to connect. Your firewall may "
                         "still be blocking it — check the Firewall section too.")
            elif kind == VIRTUAL:
                alias = adapters.get(entry["widest_addr"], ("", ""))[0]
                where = f"on a virtual adapter ({alias or 'virtual switch'})"
                severity = _soften(severity)
                reach = ("This is the host side of an internal virtual switch — "
                         "Docker, WSL or Hyper-V. Reachable by containers and VMs "
                         "on that switch, not by your physical network. Lowered in "
                         "severity for that reason.")
            else:
                alias = adapters.get(entry["widest_addr"], ("", ""))[0]
                where = f"on {alias or 'a network interface'}"
                reach = ("Bound to a real network interface, so other machines on "
                         "that network can attempt to connect.")

            yield Issue(
                category=self.category,
                title=f"{label} is listening {where} (port {port})",
                detail=(
                    f"{why}\n\n"
                    f"Bound to: {bound}:{port}\n"
                    f"Rated on: {entry['widest_addr']} ({kind})\n"
                    f"Process:  {entry['name'] or '?'} (PID {entry['pid']})\n"
                    f"Path:     {entry['exe'] or 'unknown'}\n\n{reach}"
                ),
                severity=severity,
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "If you do not need it, stop the service. If you do, restrict "
                    "it with a firewall rule scoped to specific addresses."
                ),
            )

        others = [e for e in entries if e["port"] not in NOTABLE_PORTS]
        wildcard_others = [e for e in others if e["kind"] == WILDCARD]
        real_others = [e for e in others if e["kind"] == REAL]
        virtual_others = [e for e in others if e["kind"] == VIRTUAL]

        def rows(items):
            return "\n".join(
                f"  • {e['port']:<6} {e['name'] or '?'}  (PID {e['pid']})"
                + (f"\n      {e['exe']}" if e["exe"] else "")
                for e in sorted(items, key=lambda x: x["port"])[:40]
            )

        exposed = wildcard_others + real_others
        if exposed:
            yield Issue(
                category=self.category,
                title=f"{len(exposed)} other port(s) reachable from the network",
                detail=(
                    "Not known-dangerous services, but each is a door. Anything you "
                    "do not recognise is worth identifying. Sockets bound to both "
                    "IPv4 and IPv6 are counted once.\n\n" + rows(exposed)
                    + (f"\n  … and {len(exposed) - 40} more" if len(exposed) > 40 else "")
                ),
                severity=Severity.LOW if len(exposed) < 10 else Severity.MEDIUM,
                fix_kind=FixKind.MANUAL,
            )

        if virtual_others:
            yield Issue(
                category=self.category,
                title=f"{len(virtual_others)} port(s) listening on virtual adapters only",
                detail=(
                    "Bound to Docker, WSL or Hyper-V virtual switches rather than "
                    "your physical network. Reachable by containers and VMs on those "
                    "switches, not from the LAN.\n\n" + rows(virtual_others)
                ),
                severity=Severity.INFO,
            )

        if loopback_only:
            yield Issue(
                category=self.category,
                title=f"{len(loopback_only)} service(s) listening on loopback only",
                detail=(
                    "Bound to 127.0.0.1 or ::1, so they are reachable only from this "
                    "machine. This is the correct way to run local development "
                    "servers and databases — listed for completeness, not as a "
                    "problem."
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
                f"  • {a.get('AccountName')}: {_smb_right(a.get('AccessRight'))}"
                f" ({_smb_type(a.get('AccessControlType'))})"
                for a in (access or [])
            )
            full_control = any(
                str(a.get("AccountName", "")).lower().endswith("everyone")
                and _smb_right(a.get("AccessRight")) == "Full Control"
                and _smb_type(a.get("AccessControlType")) == "Allow"
                for a in (access or [])
            )
            yield Issue(
                category=self.category,
                title=(
                    f"File share '{name}' gives Everyone full control"
                    if full_control else
                    f"File share '{name}' is open to Everyone"
                    if everyone else f"File share '{name}' is published"
                ),
                detail=(
                    f"Path: {path}\n\nPermissions:\n{rows or '  (could not read)'}\n\n"
                    + (
                        "Full Control for Everyone means any account that can reach "
                        "this machine over SMB can read, modify and DELETE these "
                        "files — not merely read them."
                        if full_control else
                        "'Everyone' means any account that can reach this machine over "
                        "SMB, including anonymous access in some configurations."
                        if everyone else
                        "Anyone with the listed permissions can reach these files over "
                        "the network."
                    )
                ),
                severity=(Severity.CRITICAL if full_control
                          else Severity.HIGH if everyone else Severity.MEDIUM),
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "Remove the share if it is not in use, or replace Everyone with "
                    "specific accounts:\n"
                    f"  Revoke-SmbShareAccess -Name '{name}' -AccountName Everyone -Force\n"
                    f"  Remove-SmbShare -Name '{name}'"
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
