"""Windows Firewall audit.

Windows ships a capable firewall behind a genuinely hostile UI, so almost
nobody ever reviews their rules. Over years, installers accumulate inbound
allow rules that outlive the software that created them. This module reads the
whole rule set in one pass and reports the ones that actually widen your
exposure, rather than listing all four hundred of them.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Iterable, List

from ..core import winutil
from ..core.issue import Category, FixKind, Issue, Severity
from ..core.scanner import ScanContext, Scanner, register
from .registry import ABSENT, _path_state

#: One PowerShell pass. Querying the filters per rule turns a 3-second job into
#: a 3-minute one, because each Get-NetFirewall*Filter call re-reads the store.
_RULE_QUERY = r"""
$ErrorActionPreference='SilentlyContinue'
$appMap=@{}; Get-NetFirewallApplicationFilter  | ForEach-Object { $appMap[$_.InstanceID]  = $_.Program }
$addrMap=@{}; Get-NetFirewallAddressFilter     | ForEach-Object { $addrMap[$_.InstanceID] = ($_.RemoteAddress -join ',') }
$portMap=@{}; Get-NetFirewallPortFilter        | ForEach-Object { $portMap[$_.InstanceID] = ($_.LocalPort -join ',') }
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | ForEach-Object {
  [pscustomobject]@{
    Name    = $_.Name
    Display = $_.DisplayName
    Profile = [string]$_.Profile
    Group   = $_.DisplayGroup
    Program = $appMap[$_.Name]
    Remote  = $addrMap[$_.Name]
    Port    = $portMap[$_.Name]
  }
}
"""


def _disable_rule(name: str) -> dict:
    """Payload that turns one rule off. Reversal is a single documented command."""
    return {
        "argv": ["powershell.exe", "-NoProfile", "-Command",
                 f"Disable-NetFirewallRule -Name '{name}'"],
        "timeout": 60,
    }


@register
class FirewallScanner(Scanner):
    id = "firewall"
    name = "Firewall"
    description = "Inbound rule audit, default actions, logging, stale rules."
    category = Category.FIREWALL
    weight = 2.5

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:
        if not winutil.IS_WINDOWS:
            return

        yield from self._profiles(ctx)
        yield from self._inbound_rules(ctx)

    # ------------------------------------------------------------------

    def _profiles(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Checking firewall profiles", 0.05)
        data = winutil.powershell_json(
            "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,"
            "DefaultOutboundAction,LogBlocked,LogFileName",
            timeout=60,
        )
        if isinstance(data, dict):
            data = [data]
        for profile in data or []:
            name = profile.get("Name")
            # The profile-disabled case is reported by the Security scanner;
            # duplicating it here would inflate the count for one real problem.
            if not profile.get("Enabled"):
                continue

            inbound = str(profile.get("DefaultInboundAction", ""))
            # 0 = NotConfigured, 1 = Allow, 2 = Block in the CIM enum.
            if inbound.lower() in ("allow", "1"):
                yield Issue(
                    category=self.category,
                    title=f"{name} profile allows inbound connections by default",
                    detail=(
                        "The firewall's default answer for unsolicited inbound traffic "
                        "should be Block — rules then carve out the exceptions. Set to "
                        "Allow, every service on this machine is reachable unless a "
                        "rule specifically forbids it, which inverts the entire model."
                    ),
                    severity=Severity.CRITICAL,
                    fix_kind=FixKind.RUN_COMMAND,
                    fix_label=f"Block inbound by default on {name}",
                    requires_admin=True,
                    payload={
                        "argv": ["powershell.exe", "-NoProfile", "-Command",
                                 f"Set-NetFirewallProfile -Name {name} "
                                 "-DefaultInboundAction Block"],
                        "timeout": 60,
                    },
                )

            if not profile.get("LogBlocked"):
                yield Issue(
                    category=self.category,
                    title=f"{name} profile does not log blocked connections",
                    detail=(
                        "Dropped-connection logging costs nothing and is the only "
                        "record you have if you ever need to work out what was probing "
                        "this machine.\n\n"
                        f"Log file: {profile.get('LogFileName') or 'not set'}"
                    ),
                    severity=Severity.INFO,
                    fix_kind=FixKind.RUN_COMMAND,
                    fix_label=f"Enable blocked-connection logging on {name}",
                    requires_admin=True,
                    payload={
                        "argv": ["powershell.exe", "-NoProfile", "-Command",
                                 f"Set-NetFirewallProfile -Name {name} -LogBlocked True"],
                        "timeout": 60,
                    },
                )

    # ------------------------------------------------------------------

    def _inbound_rules(self, ctx: ScanContext) -> Iterable[Issue]:
        ctx.report("Reading firewall rules (one pass, please wait)", 0.2)
        data = winutil.powershell_json(_RULE_QUERY, timeout=180)
        if isinstance(data, dict):
            data = [data]
        if not data:
            return

        ctx.report(f"Auditing {len(data)} inbound allow rules", 0.6)

        public_any: List[dict] = []
        stale: List[dict] = []

        for rule in data:
            profile = str(rule.get("Profile", "")).lower()
            remote = str(rule.get("Remote", "")).strip()
            program = (rule.get("Program") or "").strip()

            # "Any" remote address means the whole internet, not just the LAN.
            wide_open = remote.lower() in ("any", "*", "")
            on_public = "public" in profile or profile in ("0", "any")

            if wide_open and on_public:
                public_any.append(rule)

            # A rule whose program is gone is dead weight and a small risk: if
            # anything ever lands at that exact path, the hole is pre-approved.
            if program and program.lower() not in ("any", "system"):
                expanded = Path(os.path.expandvars(program))
                if _path_state(expanded) == ABSENT:
                    stale.append(rule)

        if public_any:
            shown = sorted(public_any, key=lambda r: str(r.get("Display", "")))[:25]
            rows = "\n".join(
                f"  • {r.get('Display')}"
                + (f"\n      program: {r.get('Program')}" if r.get("Program") else "")
                + (f"\n      ports:   {r.get('Port')}" if r.get("Port") else "")
                for r in shown
            )
            more = (f"\n  … and {len(public_any) - 25} more"
                    if len(public_any) > 25 else "")
            yield Issue(
                category=self.category,
                title=(
                    f"{len(public_any)} inbound rule(s) accept connections from any "
                    "address on the Public profile"
                ),
                detail=(
                    "These allow unsolicited inbound traffic from anywhere, including "
                    "on untrusted networks. Many are legitimate — games, media servers "
                    "and sync clients need them — but each one is a permanently open "
                    "door, and installers rarely scope them properly.\n\n"
                    + rows + more
                    + "\n\nAuroch will not bulk-disable these; review them and disable "
                    "individually what you do not use."
                ),
                severity=Severity.MEDIUM if len(public_any) < 15 else Severity.HIGH,
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "Disable one with:  Disable-NetFirewallRule -DisplayName '<name>'\n"
                    "Re-enable it with: Enable-NetFirewallRule  -DisplayName '<name>'"
                ),
            )

        if stale:
            shown = sorted(stale, key=lambda r: str(r.get("Display", "")))[:25]
            rows = "\n".join(
                f"  • {r.get('Display')}\n      missing: {r.get('Program')}"
                for r in shown
            )
            more = f"\n  … and {len(stale) - 25} more" if len(stale) > 25 else ""
            yield Issue(
                category=self.category,
                title=f"{len(stale)} firewall rule(s) point at programs that no longer exist",
                detail=(
                    "Left behind by uninstalled software. Mostly clutter, with one real "
                    "edge: the permission is granted to a path, so anything later placed "
                    "at that exact path inherits an inbound allow rule it never asked "
                    "for.\n\n" + rows + more
                ),
                severity=Severity.LOW,
                fix_kind=FixKind.MANUAL,
                remediation_hint=(
                    "Remove one with: Remove-NetFirewallRule -DisplayName '<name>'\n"
                    "Auroch does not delete firewall rules automatically — unlike a "
                    "registry key, a deleted rule cannot be exported and restored."
                ),
            )

        total = len(data)
        if total and not public_any and not stale:
            yield Issue(
                category=self.category,
                title=f"{total} inbound allow rules, none over-permissive",
                detail=(
                    "Every enabled inbound rule is either scoped to specific addresses "
                    "or confined to Private/Domain profiles, and all of them point at "
                    "programs that still exist."
                ),
                severity=Severity.INFO,
            )
