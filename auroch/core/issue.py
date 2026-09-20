"""Core data types shared by every scanner and fixer."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict


class Severity(IntEnum):
    """How much the finding actually matters.

    Deliberately conservative. Most of what commercial "PC cleaners" count as
    CRITICAL is INFO or LOW here.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "Info",
            Severity.LOW: "Minor",
            Severity.MEDIUM: "Moderate",
            Severity.HIGH: "Important",
            Severity.CRITICAL: "Critical",
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "#6b7684",
            Severity.LOW: "#3f8fd0",
            Severity.MEDIUM: "#d0a03f",
            Severity.HIGH: "#d97539",
            Severity.CRITICAL: "#d0453f",
        }[self]


class Category:
    JUNK = "Junk & Temporary Files"
    REGISTRY = "Registry Hygiene"
    PRIVACY = "Privacy Traces"
    STARTUP = "Startup & Autoruns"
    DISK = "Disk Health"
    SYSTEM_FILES = "Windows System Files"
    SECURITY = "Security Posture"
    STABILITY = "Crashes & Stability"
    PERFORMANCE = "Performance"
    HARDWARE = "Hardware Inventory"

    ORDER = [
        SYSTEM_FILES,
        SECURITY,
        STABILITY,
        DISK,
        STARTUP,
        PERFORMANCE,
        JUNK,
        PRIVACY,
        REGISTRY,
        HARDWARE,
    ]


class FixKind:
    """How the fixer will carry out a repair. Drives the backup strategy."""

    NONE = "none"                 # informational only
    DELETE_FILES = "delete_files"  # payload["paths"] -> quarantine
    DELETE_REGKEY = "delete_regkey"  # payload["hive"], payload["subkey"]
    DELETE_REGVALUE = "delete_regvalue"  # + payload["value"]
    RUN_COMMAND = "run_command"    # payload["argv"]
    MANUAL = "manual"              # user must act; we only explain how


@dataclass
class Issue:
    """One finding. Immutable-ish; `selected` is the only UI-mutated field."""

    category: str
    title: str
    detail: str
    severity: Severity
    fix_kind: str = FixKind.NONE
    fix_label: str = ""
    size_bytes: int = 0
    requires_admin: bool = False
    requires_restart: bool = False
    payload: Dict[str, Any] = field(default_factory=dict)
    remediation_hint: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    selected: bool = True

    @property
    def fixable(self) -> bool:
        return self.fix_kind not in (FixKind.NONE, FixKind.MANUAL)

    @property
    def counts_as_problem(self) -> bool:
        """Hardware inventory and other INFO rows are not 'problems'.

        This is the honesty valve: the headline number on the dashboard only
        counts things that are actually worth acting on.
        """
        return self.severity >= Severity.LOW


@dataclass
class FixResult:
    issue_id: str
    ok: bool
    message: str
    undo_token: str = ""
    restart_required: bool = False


def human_bytes(n: int) -> str:
    if n <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024.0 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.0f} {units[i]}" if i == 0 else f"{f:.1f} {units[i]}"
