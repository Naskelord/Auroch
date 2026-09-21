"""Registry hygiene.

Deliberately narrow. Commercial cleaners inflate their numbers by counting
every orphaned COM reference in the hive; almost none of those cost you
anything. This scanner only reports entries that point at a file that is
definitively gone, and it marks all of them Minor, because that is what they
are.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from ..core import winutil
from ..core.issue import Category, FixKind, Issue, Severity
from ..core.scanner import ScanContext, Scanner, register

if winutil.IS_WINDOWS:
    import winreg
else:  # pragma: no cover
    winreg = None  # type: ignore

_ENV_RE = re.compile(r"%([^%]+)%")


def _expand(value: str) -> str:
    """Expand %VARS% and trim whitespace.

    Quotes are deliberately NOT stripped here. In a command line the quoting is
    structural — it is what marks where the executable path ends — so removing
    it up front destroys the only reliable parse of `"C:\\a b\\x.exe" --flag`.
    Callers that want a bare path strip the quotes themselves.
    """
    return os.path.expandvars(value).strip()


def _as_path(value: str) -> Optional[Path]:
    """A registry value that is meant to be a plain path, not a command line."""
    cleaned = _expand(value).strip('"').strip()
    return Path(cleaned) if cleaned else None


#: Matches the shortest prefix ending in an executable extension at a token
#: boundary, so "C:\Program Files\X\app.exe -flag" yields the full exe path.
_EXE_BOUNDARY_RE = re.compile(
    r"^(.*?\.(?:exe|com|bat|cmd|scr|msi))(?=[\"\s]|$)", re.IGNORECASE
)


def _path_from_command(command: str) -> Optional[Path]:
    """Pull the executable out of a command line.

    The unquoted case is the dangerous one. Splitting on spaces and taking the
    first token turns "C:\\Program Files\\Riot Vanguard\\vgtray.exe" into
    "C:\\Program", which does not exist — so the entry gets condemned for a
    path it never referenced. Cutting at the first executable extension parses
    it correctly without touching the filesystem at all.
    """
    command = _expand(command)
    if not command:
        return None

    if command.startswith('"'):
        end = command.find('"', 1)
        candidate = command[1:end] if end > 0 else command.strip('"')
        return Path(candidate) if candidate.strip() else None

    match = _EXE_BOUNDARY_RE.match(command)
    if match:
        return Path(match.group(1))

    # No recognisable executable extension. Try progressively longer prefixes.
    parts = command.split(" ")
    accumulated = ""
    for part in parts:
        accumulated = f"{accumulated} {part}".strip()
        if _path_state(Path(accumulated)) == PRESENT:
            return Path(accumulated)

    # Refuse to guess. A truncated first token is not a path, and reporting it
    # as a missing file is worse than reporting nothing.
    if len(parts) == 1 and parts[0]:
        return Path(parts[0])
    return None


def _enum_subkeys(hive, subkey: str) -> List[str]:
    out: List[str] = []
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            index = 0
            while True:
                try:
                    out.append(winreg.EnumKey(key, index))
                    index += 1
                except OSError:
                    break
    except OSError:
        pass
    return out


def _read_value(hive, subkey: str, name: str) -> Optional[str]:
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value) if value is not None else None
    except OSError:
        return None


def _read_dword(hive, subkey: str, name: str) -> int:
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return int(value)
    except (OSError, TypeError, ValueError):
        return 0


#: Result of asking the filesystem about a path.
PRESENT = "present"
ABSENT = "absent"
UNKNOWN = "unknown"


def _path_state(path: Optional[Path]) -> str:
    """PRESENT / ABSENT / UNKNOWN for a path.

    The distinction matters more than it looks. `Path.exists()` swallows every
    OSError and answers False, so a path inside a folder the current user may
    not list — `C:\\ProgramData\\Package Cache`, where every Burn-bundle
    installer lives — reads as "missing" when it is merely unreadable. That is
    how a dozen installed Visual C++ redistributables got reported as leftovers.

    Only FileNotFoundError is real evidence of absence. Everything else is
    ignorance, and ignorance must not condemn an entry.
    """
    if path is None or str(path).strip() in ("", "."):
        return UNKNOWN

    # A bare name with no directory component is resolved by the shell through
    # PATH, not as a literal file. "cmd.exe" exists; it simply is not a path.
    text = str(path)
    if "\\" not in text and "/" not in text:
        import shutil
        if shutil.which(text):
            return PRESENT
        # PATH at logon may differ from PATH now, so absence here proves
        # nothing.
        return UNKNOWN

    try:
        path.stat()
        return PRESENT
    except FileNotFoundError:
        # The leaf is gone — but if its parent is also unreadable rather than
        # absent, we still cannot be sure. Check the parent to be certain.
        try:
            parent = path.parent
            if parent != path:
                parent.stat()
            return ABSENT
        except FileNotFoundError:
            return ABSENT
        except OSError:
            return UNKNOWN
    except NotADirectoryError:
        return ABSENT
    except (PermissionError, OSError):
        return UNKNOWN


@register
class RegistryScanner(Scanner):
    id = "registry"
    name = "Registry hygiene"
    description = "Entries pointing at files that no longer exist."
    category = Category.REGISTRY
    weight = 2.0

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if winreg is None:
            return

        yield from self._orphan_uninstall_entries(ctx)
        yield from self._orphan_app_paths(ctx)
        yield from self._broken_startup_entries(ctx)

    # ----------------------------------------------------------------------

    def _orphan_uninstall_entries(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking uninstall entries", 0.1)
        roots: List[Tuple[str, object, str]] = [
            ("HKLM", winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            ("HKCU", winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for hive_name, hive, base in roots:
            for child in _enum_subkeys(hive, base):
                if ctx.cancelled:
                    return
                full = f"{base}\\{child}"
                display = _read_value(hive, full, "DisplayName") or child

                # Windows Installer owns its own state. The InstallLocation it
                # records is routinely stale or absent for products that are
                # installed and working — VC++ redistributables, .NET and
                # Windows SDKs above all — so judging those on a path check
                # produces confident nonsense. Leave them to msiexec.
                if _read_dword(hive, full, "WindowsInstaller"):
                    continue
                # SystemComponent entries are hidden from Programs and Features
                # by design; they are not clutter the user can see or act on.
                if _read_dword(hive, full, "SystemComponent"):
                    continue

                uninstall = _read_value(hive, full, "UninstallString") or ""
                quiet = _read_value(hive, full, "QuietUninstallString") or ""
                if "msiexec" in (uninstall + quiet).lower():
                    continue

                install_loc = _read_value(hive, full, "InstallLocation") or ""
                install_target = _as_path(install_loc) if install_loc.strip() else None
                uninstall_target = (
                    _path_from_command(uninstall or quiet)
                    if (uninstall or quiet) else None
                )

                # An entry is only orphaned when EVERY route it offers is
                # *provably* dead. A stale InstallLocation alone does not
                # condemn it while a working uninstaller sits next to it, and
                # neither does a path we merely failed to read.
                states = [
                    _path_state(install_target),
                    _path_state(uninstall_target),
                ]
                if PRESENT in states or UNKNOWN in states:
                    continue
                if ABSENT not in states:
                    continue

                missing = " and ".join(
                    str(p) for p in (install_target, uninstall_target) if p is not None
                )
                yield Issue(
                    category=self.category,
                    title=f"Leftover uninstall entry: {display}",
                    detail=(
                        "The Programs and Features list still shows this, but both "
                        "its install folder and its uninstaller are gone, so the "
                        "entry can no longer do anything.\n\n"
                        f"Missing: {missing}\n"
                        f"Key: {hive_name}\\{full}"
                    ),
                    severity=Severity.LOW,
                    fix_kind=FixKind.DELETE_REGKEY,
                    fix_label="Remove entry",
                    requires_admin=(hive_name == "HKLM"),
                    payload={"hive": hive_name, "subkey": full},
                )

    # ----------------------------------------------------------------------

    def _orphan_app_paths(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking App Paths", 0.5)
        base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
        for hive_name, hive in (("HKLM", winreg.HKEY_LOCAL_MACHINE),
                                ("HKCU", winreg.HKEY_CURRENT_USER)):
            for child in _enum_subkeys(hive, base):
                if ctx.cancelled:
                    return
                full = f"{base}\\{child}"
                default = _read_value(hive, full, "")
                if not default:
                    continue
                target = _path_from_command(default)
                if _path_state(target) != ABSENT:
                    continue
                yield Issue(
                    category=self.category,
                    title=f"Dead App Paths entry: {child}",
                    detail=(
                        "Windows would try to launch a missing file if anything "
                        f"asked for '{child}'.\n\nMissing path: {target}\n"
                        f"Key: {hive_name}\\{full}"
                    ),
                    severity=Severity.LOW,
                    fix_kind=FixKind.DELETE_REGKEY,
                    fix_label="Remove entry",
                    requires_admin=(hive_name == "HKLM"),
                    payload={"hive": hive_name, "subkey": full},
                )

    # ----------------------------------------------------------------------

    def _broken_startup_entries(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking Run keys for dead targets", 0.8)
        run_keys = [
            ("HKCU", winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for hive_name, hive, subkey in run_keys:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, index)
                            index += 1
                        except OSError:
                            break
                        if ctx.cancelled:
                            return
                        target = _path_from_command(str(value))
                        if _path_state(target) != ABSENT:
                            continue
                        yield Issue(
                            category=self.category,
                            title=f"Startup entry points at a missing file: {name}",
                            detail=(
                                "Windows tries to run this at every logon and fails "
                                f"silently.\n\nCommand: {value}\nMissing: {target}\n"
                                f"Key: {hive_name}\\{subkey}"
                            ),
                            severity=Severity.MEDIUM,
                            fix_kind=FixKind.DELETE_REGVALUE,
                            fix_label="Remove startup entry",
                            requires_admin=(hive_name == "HKLM"),
                            payload={
                                "hive": hive_name,
                                "subkey": subkey,
                                "value": name,
                            },
                        )
            except OSError:
                continue
