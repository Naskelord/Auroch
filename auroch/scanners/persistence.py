"""Persistence and tamper hunting.

Malware's hardest problem is surviving a reboot, so it has to write itself into
one of a finite set of places. This module walks those places. It is not an
antivirus — it does not know what is malicious — but it surfaces the shapes
that matter: code running from user-writable folders, Defender exclusions
covering broad paths, WMI event subscriptions, and hooks in Winlogon and LSA
that legitimate desktop software almost never touches.

Findings here are evidence, not verdicts. Each one says what is unusual and
what to check, because a false accusation is worse than a quiet list.
"""
from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath
from typing import Iterable, List, Optional

from ..core import winutil
from ..core.issue import Category, FixKind, Issue, Severity
from ..core.scanner import ScanContext, Scanner, register
from .registry import ABSENT, PRESENT, _path_from_command, _path_state

if winutil.IS_WINDOWS:
    import winreg
else:  # pragma: no cover
    winreg = None  # type: ignore

#: Candidate locations worth an ACL check. These are NOT conclusions — the
#: earlier version treated any path under ProgramData as user-writable, which
#: flagged Microsoft Defender's own platform binaries as a privilege-escalation
#: risk. ProgramData is a legitimate machine-wide data location whose
#: subfolders carry whatever ACL their creator set.
CANDIDATE_MARKERS = (
    "\\appdata\\local\\temp",
    "\\appdata\\roaming",
    "\\appdata\\local",
    "\\downloads",
    "\\users\\public",
    "\\programdata\\",
    "\\windows\\temp",
    "\\temp\\",
)

#: Identities that mean "any ordinary user", in the locales we can anticipate.
#: A write grant to one of these is what makes a path a privilege-escalation
#: risk; a grant to a single named user is not.
NONADMIN_IDENTITIES = (
    "everyone",
    "builtin\\users",
    "nt authority\\authenticated users",
    "authenticated users",
    "users",
)

_ACL_CACHE: dict = {}


def _nonadmin_writable(path: Optional[Path]) -> Optional[bool]:
    """True if ordinary users can write to this path's directory.

    Returns None when it cannot be determined — which, as everywhere else in
    Auroch, must not be treated as a finding.
    """
    if path is None or not winutil.IS_WINDOWS:
        return None
    directory = str(path.parent if path.suffix else path)
    if directory in _ACL_CACHE:
        return _ACL_CACHE[directory]

    safe = directory.replace("'", "''")
    acl = winutil.powershell_json(
        f"(Get-Acl -LiteralPath '{safe}' -ErrorAction SilentlyContinue).Access | "
        "Select-Object IdentityReference,FileSystemRights,AccessControlType",
        timeout=45,
    )
    if acl is None:
        _ACL_CACHE[directory] = None
        return None
    if isinstance(acl, dict):
        acl = [acl]

    writable = False
    for ace in acl:
        if str(ace.get("AccessControlType", "")).lower() not in ("allow", "0"):
            continue
        identity = str(ace.get("IdentityReference", "")).lower()
        if not any(identity.endswith(i) or identity == i for i in NONADMIN_IDENTITIES):
            continue
        rights = str(ace.get("FileSystemRights", "")).lower()
        if any(r in rights for r in ("fullcontrol", "modify", "write")):
            writable = True
            break
    _ACL_CACHE[directory] = writable
    return writable

#: Autorun locations beyond the Run keys everyone checks.
EXTRA_AUTORUN_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", "RunServices"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce", "RunServicesOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", "RunServices"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "Windows load/run"),
    ("HKCU", r"Environment", "UserInitMprLogonScript"),
]


def _hive(name: str):
    return {"HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER}[name]


def _values(hive_name: str, subkey: str) -> List[tuple]:
    if winreg is None:
        return []
    out = []
    try:
        with winreg.OpenKey(_hive(hive_name), subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    i += 1
                    out.append((name, value))
                except OSError:
                    break
    except OSError:
        pass
    return out


def _read(hive_name: str, subkey: str, value: str) -> Optional[str]:
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(_hive(hive_name), subkey, 0, winreg.KEY_READ) as key:
            v, _ = winreg.QueryValueEx(key, value)
            return str(v)
    except OSError:
        return None


def _is_candidate(path: Optional[Path]) -> bool:
    """Cheap pre-filter so the ACL query runs on a handful of paths, not all."""
    if path is None:
        return False
    low = str(path).lower()
    return any(m in low for m in CANDIDATE_MARKERS)


def _user_writable(path: Optional[Path]) -> bool:
    """Marker-only test, for autoruns where the *location itself* is the signal.

    Malware auto-starting from Downloads is notable regardless of the ACL.
    Privilege escalation via a service binary is not — that needs the real
    permission check above.
    """
    return _is_candidate(path)


@register
class PersistenceScanner(Scanner):
    id = "persistence"
    name = "Persistence & tampering"
    description = "Autorun locations, WMI subscriptions, Defender exclusions, hooks."
    category = Category.PERSISTENCE
    weight = 3.0

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return

        yield from self._defender_exclusions(ctx)
        yield from self._defender_tamper(ctx)
        yield from self._extra_autoruns(ctx)
        yield from self._winlogon(ctx)
        yield from self._image_hijacks(ctx)
        yield from self._wmi_subscriptions(ctx)
        yield from self._suspicious_services(ctx)

    # ------------------------------------------------- Defender exclusions

    def _defender_exclusions(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Auditing Defender exclusions", 0.05)
        prefs = winutil.powershell_json(
            "Get-MpPreference -ErrorAction SilentlyContinue | Select-Object "
            "ExclusionPath,ExclusionProcess,ExclusionExtension",
            timeout=90,
        )
        if not prefs:
            return

        def as_list(v):
            if v is None:
                return []
            return list(v) if isinstance(v, list) else [v]

        paths = as_list(prefs.get("ExclusionPath"))
        procs = as_list(prefs.get("ExclusionProcess"))
        exts = as_list(prefs.get("ExclusionExtension"))

        # Windows substitutes an explanatory sentence for the real list when the
        # caller is not elevated. Detect it and report a skipped check.
        def _is_denied(values) -> bool:
            return any(str(v).strip().lower().startswith(("n/a:", "n/a "))
                       for v in values)

        if _is_denied(paths) or _is_denied(procs) or _is_denied(exts):
            yield Issue(
                category=self.category,
                title="Defender exclusions were not checked",
                detail=(
                    "Reading the exclusion list requires an elevated process, and "
                    "Auroch is running as a standard user. Windows returned an "
                    "explanatory message instead of the list.\n\n"
                    "This check is skipped rather than passed — an unread list is "
                    "not an empty one."
                ),
                severity=Severity.INFO,
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "Restart Auroch as administrator to audit exclusions. This is "
                    "the single most valuable check in this section."
                ),
            )
            return

        # A broad exclusion is the dangerous kind: it blinds Defender across a
        # whole tree rather than one known-noisy file.
        broad: List[str] = []
        for raw in paths:
            p = str(raw).rstrip("\\/").lower()
            if not p:
                continue
            depth = p.replace("/", "\\").strip("\\").count("\\")
            drive_root = len(p) <= 3 and p.endswith(":")
            if (drive_root or depth <= 1
                    or p.endswith("\\users") or p.endswith("\\windows")
                    or p.endswith("\\programdata") or p.endswith("\\temp")):
                broad.append(str(raw))

        risky_exts = [e for e in exts
                      if str(e).lower().lstrip(".") in
                      ("exe", "dll", "scr", "ps1", "bat", "cmd", "vbs", "js", "jar")]

        if broad or risky_exts:
            lines = []
            if broad:
                lines.append("Broad path exclusions:")
                lines += [f"  • {b}" for b in broad]
            if risky_exts:
                lines.append("Executable file types excluded:")
                lines += [f"  • {e}" for e in risky_exts]
            yield Issue(
                category=self.category,
                title="Microsoft Defender has dangerously broad exclusions",
                detail=(
                    "Defender skips these entirely. Adding an exclusion for its own "
                    "folder is one of the first things malware does after gaining "
                    "admin rights, and excluding an executable file type disables "
                    "scanning for that type everywhere.\n\n"
                    + "\n".join(lines)
                    + "\n\nIf you added these yourself for a build folder or a game, "
                    "they are fine. If you did not add them, find out who did."
                ),
                severity=Severity.CRITICAL,
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "Review in Windows Security > Virus & threat protection > Manage "
                    "settings > Exclusions. Remove one with:\n"
                    "  Remove-MpPreference -ExclusionPath '<path>'"
                ),
            )
        elif paths or procs or exts:
            rows = ([f"  path:    {p}" for p in paths]
                    + [f"  process: {p}" for p in procs]
                    + [f"  type:    {e}" for e in exts])
            yield Issue(
                category=self.category,
                title=f"Defender has {len(rows)} exclusion(s) configured",
                detail=(
                    "None look over-broad. Listed so you can confirm you recognise "
                    "them — almost nobody ever checks this list, which is exactly why "
                    "it gets abused.\n\n" + "\n".join(rows[:30])
                ),
                severity=Severity.INFO,
            )

    # ----------------------------------------------------- tamper protection

    def _defender_tamper(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking Defender tamper protection", 0.15)
        status = winutil.powershell_json(
            "Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object "
            "IsTamperProtected,AntispywareEnabled,IoavProtectionEnabled",
            timeout=90,
        )
        if not status:
            return
        if status.get("IsTamperProtected") is False:
            yield Issue(
                category=self.category,
                title="Defender Tamper Protection is off",
                detail=(
                    "Tamper Protection is what stops other software — including "
                    "malware running as administrator — from silently disabling "
                    "Defender or adding exclusions. With it off, every other "
                    "protective setting can be switched off without asking you."
                ),
                severity=Severity.HIGH,
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "Turn it on in Windows Security > Virus & threat protection > "
                    "Manage settings. It cannot be enabled from a script by design — "
                    "that is the point of it."
                ),
            )

    # ------------------------------------------------------ extra autoruns

    def _extra_autoruns(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Walking less-known autorun locations", 0.3)
        findings: List[str] = []
        suspicious: List[tuple] = []

        for hive_name, subkey, label in EXTRA_AUTORUN_KEYS:
            for name, value in _values(hive_name, subkey):
                text = str(value).strip()
                if not text:
                    continue
                if label == "Windows load/run" and name.lower() not in ("load", "run"):
                    continue
                if label == "UserInitMprLogonScript" and name.lower() != "userinitmprlogonscript":
                    continue
                target = _path_from_command(text)
                entry = f"{hive_name}\\{label} :: {name} = {text}"
                if _user_writable(target):
                    suspicious.append((entry, target))
                else:
                    findings.append(entry)

        for entry, target in suspicious:
            yield Issue(
                category=self.category,
                title=f"Autorun from a user-writable folder: {entry.split('::')[1].split('=')[0].strip()}",
                detail=(
                    "This starts automatically and lives somewhere any program can "
                    "write. Installed software runs from Program Files; things that "
                    "run from AppData, Temp, Downloads or ProgramData are either "
                    "sloppy or deliberate.\n\n"
                    f"{entry}\nResolved path: {target}\n"
                    f"File present: {_path_state(target)}"
                ),
                severity=Severity.HIGH,
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "Identify the file before removing it — check its signature and "
                    "upload the hash to VirusTotal."
                ),
            )

        if findings:
            yield Issue(
                category=self.category,
                title=f"{len(findings)} entry(s) in secondary autorun locations",
                detail=(
                    "Autorun keys beyond the usual Run keys. All resolve to normal "
                    "install locations; listed for completeness.\n\n"
                    + "\n".join(f"  • {f}" for f in findings[:25])
                ),
                severity=Severity.INFO,
            )

    # ---------------------------------------------------------- winlogon

    def _winlogon(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking Winlogon and LSA hooks", 0.5)
        wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        # Windows stores these as a comma-separated list, and the stock value
        # carries a trailing comma — "C:\\WINDOWS\\system32\\userinit.exe,".
        # Parse it as a list instead of string-matching the whole field.
        for value_name, expected_exe in (("Shell", "explorer.exe"),
                                         ("Userinit", "userinit.exe")):
            actual = _read("HKLM", wl, value_name)
            if actual is None:
                continue

            components = [c.strip().strip('"') for c in str(actual).split(",")]
            components = [c for c in components if c]
            extras = [
                c for c in components
                if PureWindowsPath(c).name.lower() != expected_exe
            ]

            if not components:
                continue
            if not extras:
                continue  # exactly the stock value, however it is spelled

            if all(PureWindowsPath(c).name.lower() != expected_exe
                   for c in components):
                yield Issue(
                    category=self.category,
                    title=f"Winlogon {value_name} has been replaced",
                    detail=(
                        f"Windows runs this at every logon and it should be "
                        f"'{expected_exe}', which is absent entirely.\n\n"
                        f"Value: {actual}\nKey: HKLM\\{wl}\n\n"
                        "Replacing this is a classic persistence technique — it runs "
                        "before anything the user sees."
                    ),
                    severity=Severity.CRITICAL,
                    fix_kind=FixKind.MANUAL,
                    remediation_hint=(
                        "Do not edit this blindly; a wrong value here prevents logon "
                        "entirely. Identify the program first."
                    ),
                )
            else:
                yield Issue(
                    category=self.category,
                    title=f"Winlogon {value_name} has {len(extras)} extra entry(s)",
                    detail=(
                        f"'{expected_exe}' is present as expected, but these are "
                        f"chained onto it and will also run at every logon:\n\n"
                        + "\n".join(f"  • {e}" for e in extras)
                        + f"\n\nFull value: {actual}\nKey: HKLM\\{wl}"
                    ),
                    severity=Severity.HIGH,
                    fix_kind=FixKind.MANUAL,
                )

    # ------------------------------------------------------ image hijacks

    def _image_hijacks(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking for debugger hijacks", 0.62)
        base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        if winreg is None:
            return
        hijacks = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        child = winreg.EnumKey(key, i)
                        i += 1
                    except OSError:
                        break
                    dbg = _read("HKLM", f"{base}\\{child}", "Debugger")
                    if dbg:
                        hijacks.append((child, dbg))
        except OSError:
            return

        for target, debugger in hijacks:
            # Legitimate use exists (developers attaching debuggers), but on a
            # normal desktop this is overwhelmingly a hijack or a "kill this
            # program" trick used against security tools.
            yield Issue(
                category=self.category,
                title=f"Image File Execution Options debugger set for {target}",
                detail=(
                    f"Whenever Windows launches '{target}', it runs this instead:\n\n"
                    f"  {debugger}\n\n"
                    f"Key: HKLM\\{base}\\{target}\n\n"
                    "This mechanism exists for debugging, but is widely used both to "
                    "hijack a program and to prevent security tools from starting. "
                    "Unless you set this up yourself, treat it as hostile."
                ),
                severity=Severity.CRITICAL,
                fix_kind=FixKind.DELETE_REGVALUE,
                fix_label="Remove the debugger hijack",
                requires_admin=True,
                payload={"hive": "HKLM", "subkey": f"{base}\\{target}", "value": "Debugger"},
            )

    # --------------------------------------------------- WMI subscriptions

    def _wmi_subscriptions(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking WMI event subscriptions", 0.75)
        consumers = winutil.powershell_json(
            "Get-CimInstance -Namespace root\\subscription -ClassName "
            "__EventConsumer -ErrorAction SilentlyContinue | "
            "Select-Object Name,__CLASS",
            timeout=120,
        )
        if isinstance(consumers, dict):
            consumers = [consumers]
        # Windows ships a couple of these (SCM Event Log Consumer); more than
        # that on a desktop is unusual and is a known fileless-persistence spot.
        custom = [c for c in (consumers or [])
                  if "SCM Event" not in str(c.get("Name", ""))]
        if not custom:
            return
        yield Issue(
            category=self.category,
            title=f"{len(custom)} WMI event consumer(s) registered",
            detail=(
                "WMI event subscriptions run code in response to system events and "
                "survive reboots without any file on disk or entry in the usual "
                "autorun lists. They are a well-known fileless persistence mechanism, "
                "and a normal desktop has almost none.\n\n"
                + "\n".join(f"  • {c.get('Name')}  ({c.get('__CLASS')})" for c in custom[:20])
                + "\n\nSome management and monitoring software uses these legitimately."
            ),
            severity=Severity.HIGH,
            fix_kind=FixKind.MANUAL,
            remediation_hint=(
                "Inspect with:\n"
                "  Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding"
            ),
        )

    # ----------------------------------------------------------- services

    def _suspicious_services(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking service binaries", 0.9)
        data = winutil.powershell_json(
            "Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | "
            "Where-Object {$_.PathName} | Select-Object Name,DisplayName,PathName,StartMode",
            timeout=120,
        )
        if isinstance(data, dict):
            data = [data]
        flagged = []
        for svc in data or []:
            path = _path_from_command(str(svc.get("PathName", "")))
            # Two gates: a cheap location filter, then a real ACL check. Only a
            # confirmed write grant to ordinary users counts. "Could not read
            # the ACL" is not evidence of anything.
            if not _is_candidate(path):
                continue
            if _nonadmin_writable(path) is not True:
                continue
            flagged.append((svc, path))
        if not flagged:
            return
        rows = "\n".join(
            f"  • {s.get('DisplayName') or s.get('Name')}\n"
            f"      {s.get('PathName')}\n"
            f"      start: {s.get('StartMode')}"
            for s, _ in flagged[:15]
        )
        yield Issue(
            category=self.category,
            title=f"{len(flagged)} service(s) run from user-writable locations",
            detail=(
                "Services run as SYSTEM. Each folder below was checked with Get-Acl and "
                "grants write access to ordinary users, so any user could replace the "
                "binary and gain SYSTEM privileges at the next restart.\n\n" + rows
            ),
            severity=Severity.HIGH,
            fix_kind=FixKind.MANUAL,
            remediation_hint=(
                "Check who owns the folder. Legitimate software sometimes does this "
                "badly; it is still a privilege-escalation path either way."
            ),
        )
