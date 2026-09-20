"""Ground truth for the Registry Hygiene scanner.

Run this on Windows and send me the output. It dumps, for every uninstall
entry Auroch would flag, the raw registry values and exactly what the
filesystem said about each path — including whether a check failed because the
path is genuinely gone or because we were not allowed to look.

    python tools/diagnose_uninstall.py

It reads only. It changes nothing.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import winreg
except ImportError:
    print("This diagnostic only runs on Windows.")
    raise SystemExit(1)

from auroch.core import winutil
from auroch.scanners.registry import (
    ABSENT,
    PRESENT,
    UNKNOWN,
    _enum_subkeys,
    _path_from_command,
    _path_state,
    _read_dword,
    _read_value,
)

ROOTS = [
    ("HKLM", winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKCU", winreg.HKEY_CURRENT_USER,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def raw_probe(path: Path | None) -> str:
    """What the OS actually says, with the exception type preserved."""
    if path is None:
        return "(no path)"
    try:
        os.stat(path)
        return "stat OK"
    except FileNotFoundError:
        return "FileNotFoundError"
    except PermissionError:
        return "PermissionError  <-- unreadable, NOT missing"
    except OSError as exc:
        return f"{exc.__class__.__name__}: {exc}"


def main() -> int:
    print(f"Elevated: {winutil.is_admin()}")
    print(f"Python:   {sys.version.split()[0]} ({'64' if sys.maxsize > 2**32 else '32'}-bit)")
    print("=" * 78)

    flagged = 0
    skipped = 0
    for hive_name, hive, base in ROOTS:
        for child in _enum_subkeys(hive, base):
            full = f"{base}\\{child}"
            display = _read_value(hive, full, "DisplayName") or child

            wi = _read_dword(hive, full, "WindowsInstaller")
            sc = _read_dword(hive, full, "SystemComponent")
            uninstall = _read_value(hive, full, "UninstallString") or ""
            quiet = _read_value(hive, full, "QuietUninstallString") or ""
            install_loc = _read_value(hive, full, "InstallLocation") or ""

            reason = None
            if wi:
                reason = "WindowsInstaller=1"
            elif sc:
                reason = "SystemComponent=1"
            elif "msiexec" in (uninstall + quiet).lower():
                reason = "msiexec uninstaller"
            if reason:
                skipped += 1
                continue

            install_target = (
                Path(os.path.expandvars(install_loc.strip().strip('"')))
                if install_loc.strip() else None
            )
            uninstall_target = (
                _path_from_command(uninstall or quiet) if (uninstall or quiet) else None
            )
            states = [_path_state(install_target), _path_state(uninstall_target)]

            would_flag = (PRESENT not in states
                          and UNKNOWN not in states
                          and ABSENT in states)
            if not would_flag:
                skipped += 1
                continue

            flagged += 1
            print(f"\nFLAGGED: {display}")
            print(f"  key              : {hive_name}\\{full}")
            print(f"  WindowsInstaller : {wi}    SystemComponent: {sc}")
            print(f"  InstallLocation  : {install_loc!r}")
            print(f"     -> {install_target}")
            print(f"     -> state={states[0]}   probe={raw_probe(install_target)}")
            print(f"  UninstallString  : {uninstall!r}")
            if quiet:
                print(f"  QuietUninstall   : {quiet!r}")
            print(f"     -> {uninstall_target}")
            print(f"     -> state={states[1]}   probe={raw_probe(uninstall_target)}")

    print("\n" + "=" * 78)
    print(f"Uninstall entries — would flag: {flagged}   skipped as fine: {skipped}")

    # ---- Run keys -------------------------------------------------------
    print("\n" + "=" * 78)
    print("STARTUP (Run key) ENTRIES — every value, flagged or not")
    print("=" * 78)

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
                    target = _path_from_command(str(value))
                    state = _path_state(target)
                    verdict = "WOULD FLAG" if state == ABSENT else f"ok ({state})"
                    print(f"\n  [{hive_name}] {name}   -> {verdict}")
                    print(f"     raw value : {value!r}")
                    print(f"     parsed    : {target}")
                    print(f"     probe     : {raw_probe(target)}")
        except OSError as exc:
            print(f"\n  [{hive_name}] {subkey} unreadable: {exc}")

    print("\n" + "=" * 78)
    print("Send me any block whose program you still have installed.")
    print("The 'probe' line says exactly what Windows reported.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
