# Auroch

A PC health, repair and maintenance tool for Windows. Built in Python as a
personal-use alternative to commercial "PC optimizer" suites.

## What it does

Ten scanners, run in order of how much they matter:

| Scanner | Checks |
|---|---|
| Windows system files | `SFC /verifyonly` and `DISM /CheckHealth`, plus pending-reboot state |
| Security posture | Defender real-time protection, definition age, unresolved threats, firewall profiles, UAC, hosts-file tampering, multiple AV products |
| Crashes & stability | BSOD minidumps, bugcheck events grouped by stop code, repeatedly-crashing apps, Kernel-Power 41 events, disk/NTFS errors |
| Disk health | Free space per volume, `Get-PhysicalDisk` health, SMART predictive-failure, NTFS dirty bit |
| Startup & autoruns | Run keys, startup folders, scheduled tasks — with Authenticode checks on anything launching from a temp or Downloads path |
| Performance | Boot duration from the diagnostics log, memory pressure with top consumers, page-file saturation, power plan |
| Junk & temp files | `%TEMP%`, Windows temp, Windows Update cache, crash dumps, browser caches, Recycle Bin, `Windows.old` |
| Privacy traces | Recent documents, jump lists, Run-dialog MRU, Explorer typed paths, browser history and cookie stores |
| Registry hygiene | Uninstall entries, App Paths and Run values that point at files which no longer exist |
| Hardware inventory | CPU, RAM modules, GPU and driver dates, storage — informational only |

## Design decisions worth knowing about

**Two of the three fix tiers are reversible; the third is not, and says so.**

| Tier | Mechanism | Reversible |
|---|---|---|
| File deletion | Moved to `%LOCALAPPDATA%\Auroch\backups\<timestamp>\` with a JSON manifest | Yes — `Tools > Undo` |
| Registry deletion | Key exported to `.reg` first; the delete is **refused** if the export fails | Yes — `Tools > Undo` |
| Command | Runs a Windows tool (SFC, DISM, chkdsk, Defender, powercfg, `reg add`) | **No** |

The confirmation dialog splits the selection into these groups by name and
switches to a warning icon whenever anything irreversible is ticked. Tier 3
covers emptying the Recycle Bin, `Remove-MpThreat`, and scheduling chkdsk.

**Quarantine does not free disk space, and the UI does not pretend otherwise.**
Quarantined files sit on the same volume they came from, so ticking 3 GB of
temp files reclaims nothing until you run `Tools > Empty quarantine`. The
footer reads `3.1 GB → quarantine`, never "frees 3.1 GB", and bytes headed for
permanent deletion are counted separately from bytes headed for quarantine.
Emptying the quarantine offers *delete all but the newest* as the default, so
one undo always survives.

**Nothing runs unless you tick it.** The scan is read-only. The Fix button is
disabled until you select something, and it shows a confirmation listing every
item before it acts.

**The health score cannot be gamed by junk.** Minor findings accumulate with
diminishing returns and are capped at 22 points total, so no quantity of temp
files can make a healthy machine score below 78. Important and Critical
findings accumulate linearly and hit hard. This is deliberate: inflating the
issue count with harmless registry orphans is the central dishonesty of the
commercial tools this replaces.

**It wraps Microsoft's tools rather than replacing them.** Malware scanning
drives Defender via PowerShell; system-file repair drives SFC and DISM against
Microsoft's own sources. There is no bundled AV engine and no kernel driver,
because doing either properly needs a licensed signature feed, an EV
code-signing certificate and Microsoft attestation signing — and doing either
badly is worse than not doing it.

## Running it

```
pip install -r requirements.txt
python main.py
```

Several checks need elevation. Either use `run_as_admin.bat`, or click
*Restart as administrator* on the home screen. Without it, the system-file and
component-store checks are **skipped and reported as skipped** — never silently
passed.

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
    issue.py             Issue, Severity, FixKind, formatting
    scanner.py           Scanner base class + registry
    engine.py            orchestration, ScanReport, health scoring
    actions.py           the repair executor
    backup.py            quarantine, .reg export, restore points, undo
    report.py            self-contained HTML export
    winutil.py           elevation, PowerShell/subprocess, filesystem walking
  scanners/              one module per scanner; @register adds it to the run
  ui/
    theme.py             palette + stylesheet
    widgets.py           ScoreRing, PulseRing
    workers.py           QThread wrappers (the GUI thread never blocks)
    main_window.py       the four pages
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
        if something_is_wrong:
            yield Issue(self.category, "Title", "Detail", Severity.MEDIUM)
```

Then import it in `auroch/scanners/__init__.py`. Import order is run order.

## Deliberate non-goals

Real-time file protection, network/web filtering, and a bundled antivirus
engine. All three require signed kernel-mode drivers. Python cannot run in
kernel mode, and a userspace imitation would give the appearance of protection
without the substance.
