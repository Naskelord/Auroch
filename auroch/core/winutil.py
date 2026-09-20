"""Thin Windows helpers. Every function here is safe to import on non-Windows;
they degrade to no-ops so the codebase stays testable off-platform.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

IS_WINDOWS = sys.platform == "win32"

# Suppress console windows spawned by subprocess on Windows.
_CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def is_admin() -> bool:
    """True if the current process holds an elevated token."""
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Re-launch this script elevated via ShellExecute 'runas'.

    Returns True if the elevated process was started (caller should exit).
    """
    if not IS_WINDOWS or is_admin():
        return False
    try:
        params = " ".join(f'"{a}"' for a in sys.argv)
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        return int(rc) > 32
    except Exception:
        return False


def run(
    argv: Sequence[str],
    timeout: int = 120,
    shell: bool = False,
) -> Tuple[int, str, str]:
    """Run a command, never raising. Returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            list(argv) if not shell else argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
            creationflags=_CREATE_NO_WINDOW,
            errors="replace",
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"
    except FileNotFoundError as exc:
        return -1, "", str(exc)
    except Exception as exc:  # pragma: no cover - defensive
        return -1, "", str(exc)


def powershell(script: str, timeout: int = 120) -> Tuple[int, str, str]:
    """Run a PowerShell snippet with output as text."""
    if not IS_WINDOWS:
        return -1, "", "not windows"
    return run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=timeout,
    )


def powershell_json(script: str, timeout: int = 120):
    """Run PowerShell and parse ConvertTo-Json output. Returns None on failure."""
    import json

    wrapped = f"$ProgressPreference='SilentlyContinue'; {script} | ConvertTo-Json -Depth 4 -Compress"
    rc, out, _err = powershell(wrapped, timeout=timeout)
    if rc != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def dir_size(path: Path, max_entries: int = 200_000) -> Tuple[int, int]:
    """(total_bytes, file_count) for a directory tree. Never raises."""
    total = 0
    count = 0
    try:
        stack = [path]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        if count >= max_entries:
                            return total, count
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(Path(entry.path))
                            elif entry.is_file(follow_symlinks=False):
                                total += entry.stat(follow_symlinks=False).st_size
                                count += 1
                        except OSError:
                            continue
            except (OSError, PermissionError):
                continue
    except Exception:
        pass
    return total, count


def iter_files(path: Path, max_entries: int = 200_000) -> Iterable[Path]:
    """Yield every file under path. Never raises."""
    count = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if count >= max_entries:
                        return
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            count += 1
                            yield Path(entry.path)
                    except OSError:
                        continue
        except (OSError, PermissionError):
            continue


def file_is_signed(path: Path) -> Optional[bool]:
    """Authenticode status. None when it can't be determined."""
    if not IS_WINDOWS:
        return None
    rc, out, _ = powershell(
        f"(Get-AuthenticodeSignature -LiteralPath '{path}').Status", timeout=20
    )
    if rc != 0 or not out.strip():
        return None
    return out.strip().lower() == "valid"


def known_folders() -> dict:
    """Common Windows locations, resolved from the environment."""
    home = Path.home()
    local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
    roaming = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    windir = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return {
        "home": home,
        "local": local,
        "roaming": roaming,
        "windir": windir,
        "temp_user": Path(os.environ.get("TEMP", local / "Temp")),
        "temp_win": windir / "Temp",
        "prefetch": windir / "Prefetch",
        "minidump": windir / "Minidump",
        "softwaredistribution": windir / "SoftwareDistribution" / "Download",
        "crashdumps": local / "CrashDumps",
        "wer_local": local / "Microsoft" / "Windows" / "WER",
        "wer_program": Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        / "Microsoft"
        / "Windows"
        / "WER",
        "recent": roaming / "Microsoft" / "Windows" / "Recent",
        "startup_user": roaming
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup",
        "startup_common": Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup",
    }


def system_drive() -> str:
    return os.environ.get("SystemDrive", "C:") + "\\"
