# Auroch

A PC health, repair and security auditing tool for Windows. Built in Python as
a personal-use alternative to commercial "PC optimizer" suites.

## What it does

Thirteen scanners, run in order of how much they matter.

### Security

| Scanner | Checks |
|---|---|
| Windows system files | `SFC /verifyonly` and `DISM /CheckHealth`, plus pending-reboot state |
| Security posture | Defender real-time protection, definition age, unresolved threats, firewall profiles, UAC, hosts-file tampering, multiple AV products |
| Persistence & tampering | Defender exclusion auditing, Tamper Protection, secondary autorun keys, Winlogon `Shell`/`Userinit`, Image File Execution Options debugger hijacks, WMI event consumers, services in user-writable folders |
| Accounts & access | *(planned)* local admins, guest account, password policy, RDP config, BitLocker |
| Network & attack surface | Listening sockets classified by bind address, named risky services with their owning process, SMB shares, SMBv1 and signing, RDP with NLA state, network profile |
| Firewall | Inbound rules accepting any remote address on Public, rules pointing at missing programs, default inbound action, drop logging |
| VPN & DNS | *(planned)* DNS leak detection, kill-switch audit, adapter state |
| Windows hardening | *(planned)* ASR rules, Controlled Folder Access, macro policy, PowerShell logging, SmartScreen |

### Health

| Scanner | Checks |
|---|---|
| Crashes & stability | BSOD minidumps, bugcheck events grouped by stop code, repeatedly-crashing apps, Kernel-Power 41 events, disk/NTFS errors |
| Disk health | Free space per volume, `Get-PhysicalDisk` health, SMART predictive-failure, NTFS dirty bit |
| Startup & autoruns | Run keys, startup folders, scheduled tasks — with Authenticode checks on anything launching from a temp or Downloads path |
| Performance | Boot duration from the diagnostics log, memory pressure with top consumers, page-file saturation, power plan |
| Junk & temp files | `%TEMP%`, Windows temp, Windows Update cache, crash dumps, browser caches, Recycle Bin, `Windows.old` |
| Privacy traces | Recent documents, jump lists, Run-dialog MRU, Explorer typed paths, browser history and cookie stores |
| Registry hygiene | Uninstall entries, App Paths and Run values that point at files which no longer exist |
| Hardware inventory | CPU, RAM modules, GPU and driver dates, storage — informational only |

## Design decisions worth knowing about

### Unknown is not a finding

This is the rule the whole tool is built on, and nearly every bug found during
development was a violation of it. `Path.exists()` returns `False` for "access
denied" as readily as for "not there". `Get-MpPreference` returns an
explanatory sentence instead of the exclusion list when unelevated. An
unreadable ACL is not a permissive one.

So paths resolve to **present / absent / unknown**, and only a genuine
`FileNotFoundError` counts as proof of absence. A check that could not run is
reported as *skipped*, never as passed. A permission a scanner could not read
produces no finding at all.

### Three fix tiers, two of them reversible — and it says which

| Tier | Mechanism | Reversible |
|---|---|---|
| File deletion | Moved to `%LOCALAPPDATA%\Auroch\backups\<timestamp>\` with a JSON manifest | Yes — `Tools > Undo` |
| Registry deletion | Key exported to `.reg` first; the delete is **refused** if the export fails | Yes — `Tools > Undo` |
| Command | Runs a Windows tool (SFC, DISM, chkdsk, Defender, `reg add`) | **No** |

The confirmation dialog splits your selection into these groups by name and
switches to a warning icon whenever anything irreversible is ticked.

Firewall rules are the exception that proves the rule: Auroch will not delete
one automatically, because unlike a registry key a firewall rule cannot be
exported and restored, so it could not honour the undo guarantee.

### Quarantine does not free disk space, and the UI does not pretend otherwise

Quarantined files sit on the same volume they came from. Ticking 3 GB of temp
files reclaims nothing until you run `Tools > Empty quarantine`. The footer
reads `3.1 GB → quarantine`, never "frees 3.1 GB", and bytes headed for
permanent deletion are counted separately from bytes headed for quarantine.

### The health score cannot be gamed by junk

Minor findings accumulate with diminishing returns and are **capped at 22
points total**, so no quantity of temp files can push a healthy machine below
78. Important and Critical findings accumulate linearly and hit hard — one
drive predicting its own failure drops you to 40.

Inflating an issue count with harmless registry orphans is the central
dishonesty of the tools this replaces.

### Findings state what is unusual, not what is malicious

A WMI event consumer or a service in ProgramData is described with what makes
it notable and what to check. Never "this is malware". For a tool you are meant
to trust, a false accusation is worse than a quiet list.

### It wraps Microsoft's tools rather than replacing them

Malware scanning drives Defender via PowerShell; system-file repair drives SFC
and DISM against Microsoft's own sources. There is no bundled AV engine and no
kernel driver.

## Running it

```
pip install -r requirements.txt
python main.py
```

Several checks need elevation — Defender exclusion auditing above all. Use
`run_as_admin.bat`, or click *Restart as administrator* on the home screen.
Without it those checks are **skipped and reported as skipped**, never
silently passed.

Command line, for a scheduled task:

```
python main.py --cli          # standard scan, writes an HTML report to the Desktop
python main.py --cli --deep   # adds DISM /ScanHealth and a Windows Update query
```

## Layout

```
main.py                  entry point (GUI / --cli / --elevate)
auroch/
  core/
    issue.py             Issue, Severity, FixKind, Category ordering
    scanner.py           Scanner base class + registry
    engine.py            orchestration, ScanReport, health scoring
    actions.py           the repair executor
    backup.py            quarantine, .reg export, restore points, undo, purge
    report.py            self-contained HTML export
    winutil.py           elevation, PowerShell/subprocess, filesystem walking
  scanners/              one module per scanner; @register adds it to the run
  ui/
    theme.py             palette + stylesheet
    widgets.py           ScoreRing, PulseRing
    workers.py           QThread wrappers (the GUI thread never blocks)
    main_window.py       the four pages
tools/
  diagnose_uninstall.py  read-only ground-truth dump for the registry scanner
```

## Adding a scanner

```python
from ..core.issue import Category, Issue, Severity
from ..core.scanner import ScanContext, Scanner, register

@register
class MyScanner(Scanner):
    id = "mine"
    name = "My check"
    category = Category.PERFORMANCE
    weight = 1.0

    def scan(self, ctx: ScanContext):
        ctx.report("Looking at something", 0.5)
        if definitely_wrong:          # not "could not verify"
            yield Issue(self.category, "Title", "Detail", Severity.MEDIUM)
```

Then import it in `auroch/scanners/__init__.py`. Import order is run order.

## Deliberate non-goals

Real-time file protection, network/web filtering, and a bundled antivirus
engine. All three require signed kernel-mode drivers; Python cannot run in
kernel mode, and a userspace imitation would give the appearance of protection
without the substance. Defender already does this properly at the kernel level
— Auroch audits its configuration instead, which is the part nobody checks.

## License

MIT — see [LICENSE](LICENSE). You may use, modify and redistribute this
freely, keeping the copyright notice.

Auroch moves files, deletes registry keys, empties the Recycle Bin and can
schedule chkdsk. It is provided **as is, with no warranty of any kind**, and
the author is not liable for data loss or damage arising from its use. Read
what a fix will do before you tick it; that is why every finding states its
mechanism.
