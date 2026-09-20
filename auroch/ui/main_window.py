"""The application window."""
from __future__ import annotations

import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QColor, QFont, QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import __app_name__, __version__
from ..core import backup as backup_mod
from ..core import winutil
from ..core.actions import needs_restore_point
from ..core.engine import ScanReport
from ..core.issue import Category, FixKind, Issue, Severity, human_bytes
from ..core.report import save_html
from . import theme
from .widgets import PulseRing, ScoreRing
from .workers import RepairWorker, ScanWorker

ISSUE_ROLE = Qt.ItemDataRole.UserRole + 1


def panel() -> QFrame:
    frame = QFrame()
    frame.setObjectName("Panel")
    return frame


def label(text: str, kind: str = "") -> QLabel:
    lbl = QLabel(text)
    if kind:
        lbl.setObjectName(kind)
    lbl.setWordWrap(True)
    return lbl


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{__app_name__} — PC Health & Repair")
        self.resize(1180, 780)
        self.setMinimumSize(980, 640)

        self.is_admin = winutil.is_admin()
        self.report: Optional[ScanReport] = None
        self.scan_worker: Optional[ScanWorker] = None
        self.repair_worker: Optional[RepairWorker] = None
        self._live_count = 0

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self.stack.addWidget(self._build_home())       # 0
        self.stack.addWidget(self._build_scanning())   # 1
        self.stack.addWidget(self._build_results())    # 2
        self.stack.addWidget(self._build_repair())     # 3

        self._build_menu()
        self.statusBar().showMessage(
            f"{__app_name__} {__version__}   ·   "
            + ("running as administrator" if self.is_admin
               else "running as standard user — some checks are unavailable")
        )

    # ================================================================ HOME

    def _build_home(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(46, 40, 46, 34)
        outer.setSpacing(0)

        title = label(__app_name__, "H1")
        outer.addWidget(title)
        outer.addWidget(
            label(
                "Finds what is actually wrong with this PC, and fixes only what you "
                "tick. Nothing is deleted — everything it removes is backed up first.",
                "Dim",
            )
        )
        outer.addSpacing(26)

        if not self.is_admin:
            warn = panel()
            warn_layout = QHBoxLayout(warn)
            warn_layout.setContentsMargins(18, 14, 18, 14)
            warn_layout.addWidget(
                label(
                    "Running as a standard user. System file integrity, the component "
                    "store check and machine-wide repairs will be skipped.",
                    "Dim",
                ),
                1,
            )
            elevate = QPushButton("Restart as administrator")
            elevate.clicked.connect(self._elevate)
            warn_layout.addWidget(elevate)
            outer.addWidget(warn)
            outer.addSpacing(18)

        # Scan cards -------------------------------------------------------
        cards = QHBoxLayout()
        cards.setSpacing(16)
        cards.addWidget(
            self._scan_card(
                "Standard scan",
                "Every check except the slow ones. Takes a couple of minutes.",
                "Run standard scan",
                lambda: self._start_scan(deep=False),
                primary=True,
            )
        )
        cards.addWidget(
            self._scan_card(
                "Deep scan",
                "Adds DISM /ScanHealth, a signature check on every autorun, and a "
                "Windows Update query. Can take 20–40 minutes.",
                "Run deep scan",
                lambda: self._start_scan(deep=True),
            )
        )
        outer.addLayout(cards)
        outer.addSpacing(18)

        # What it checks ---------------------------------------------------
        checks = panel()
        checks_layout = QVBoxLayout(checks)
        checks_layout.setContentsMargins(22, 18, 22, 18)
        checks_layout.addWidget(label("What gets checked", "H2"))
        checks_layout.addSpacing(6)
        grid = QHBoxLayout()
        grid.setSpacing(34)
        left = QVBoxLayout()
        right = QVBoxLayout()
        items = [
            ("Windows system files", "SFC + DISM against Microsoft's own sources"),
            ("Security posture", "Defender, firewall, UAC, hosts file, threats"),
            ("Crashes & stability", "Blue screens, app crashes, power events"),
            ("Disk health", "Free space, SMART, filesystem flags"),
            ("Startup & autoruns", "Signature checks on what launches at boot"),
            ("Performance", "Boot time, memory pressure, page file, power plan"),
            ("Junk & temp files", "Caches, update leftovers, dumps"),
            ("Privacy traces", "Recent files, run history, browser data"),
            ("Registry hygiene", "Entries pointing at files that are gone"),
            ("Hardware inventory", "CPU, RAM, GPU, storage"),
        ]
        for index, (name, detail) in enumerate(items):
            row = QVBoxLayout()
            row.setSpacing(1)
            row.addWidget(label(f"● {name}"))
            sub = label(f"     {detail}", "Dim")
            sub_font = sub.font()
            sub_font.setPointSize(9)
            sub.setFont(sub_font)
            row.addWidget(sub)
            (left if index < 5 else right).addLayout(row)
        grid.addLayout(left, 1)
        grid.addLayout(right, 1)
        checks_layout.addLayout(grid)
        outer.addWidget(checks)

        outer.addStretch(1)
        return page

    def _scan_card(self, title: str, body: str, button: str, slot, primary=False) -> QFrame:
        card = panel()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(8)
        layout.addWidget(label(title, "H2"))
        body_label = label(body, "Dim")
        body_label.setMinimumHeight(48)
        body_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(body_label)
        layout.addSpacing(4)
        btn = QPushButton(button)
        if primary:
            btn.setObjectName("Primary")
        btn.clicked.connect(slot)
        layout.addWidget(btn)
        return card

    # ============================================================ SCANNING

    def _build_scanning(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(46, 40, 46, 34)
        outer.addStretch(1)

        self.pulse = PulseRing(diameter=210)
        holder = QHBoxLayout()
        holder.addStretch(1)
        holder.addWidget(self.pulse)
        holder.addStretch(1)
        outer.addLayout(holder)

        outer.addSpacing(22)
        self.scan_status = label("Preparing…", "H2")
        self.scan_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(self.scan_status)

        self.scan_substatus = label("", "Dim")
        self.scan_substatus.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(self.scan_substatus)

        outer.addSpacing(20)
        self.scan_log = QPlainTextEdit()
        self.scan_log.setReadOnly(True)
        self.scan_log.setMaximumHeight(190)
        outer.addWidget(self.scan_log)

        outer.addSpacing(14)
        row = QHBoxLayout()
        row.addStretch(1)
        self.cancel_button = QPushButton("Cancel scan")
        self.cancel_button.clicked.connect(self._cancel_scan)
        row.addWidget(self.cancel_button)
        row.addStretch(1)
        outer.addLayout(row)
        outer.addStretch(1)
        return page

    # ============================================================= RESULTS

    def _build_results(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(34, 28, 34, 24)
        outer.setSpacing(14)

        # Header with score -------------------------------------------------
        header = panel()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(26, 20, 26, 20)
        header_layout.setSpacing(26)

        self.score_ring = ScoreRing(diameter=150)
        header_layout.addWidget(self.score_ring)

        text_col = QVBoxLayout()
        text_col.setSpacing(4)
        self.verdict_label = label("", "H2")
        text_col.addWidget(self.verdict_label)
        self.summary_label = label("", "Dim")
        text_col.addWidget(self.summary_label)
        text_col.addStretch(1)
        header_layout.addLayout(text_col, 1)

        button_col = QVBoxLayout()
        button_col.setSpacing(8)
        self.fix_button = QPushButton("Fix selected")
        self.fix_button.setObjectName("Primary")
        self.fix_button.clicked.connect(self._confirm_repair)
        button_col.addWidget(self.fix_button)

        export_button = QPushButton("Save report…")
        export_button.clicked.connect(self._export_report)
        button_col.addWidget(export_button)

        rescan_button = QPushButton("New scan")
        rescan_button.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        button_col.addWidget(rescan_button)
        button_col.addStretch(1)
        header_layout.addLayout(button_col)
        outer.addWidget(header)

        # Tree + detail ------------------------------------------------------
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Finding", "Severity", "Space"])
        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.tree.setColumnWidth(1, 92)
        self.tree.setColumnWidth(2, 82)
        header.setStretchLastSection(False)
        self.tree.setAlternatingRowColors(False)
        self.tree.itemChanged.connect(self._on_item_changed)
        self.tree.currentItemChanged.connect(self._on_selection_changed)
        splitter.addWidget(self.tree)

        detail_panel = QWidget()
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(14, 0, 0, 0)
        detail_layout.setSpacing(8)
        self.detail_title = label("Select a finding", "H2")
        detail_layout.addWidget(self.detail_title)
        self.detail_body = QTextEdit()
        self.detail_body.setReadOnly(True)
        detail_layout.addWidget(self.detail_body, 1)
        splitter.addWidget(detail_panel)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        outer.addWidget(splitter, 1)

        # Footer controls -----------------------------------------------------
        footer = QHBoxLayout()
        self.restore_point_check = QCheckBox(
            "Create a System Restore point before making changes"
        )
        self.restore_point_check.setChecked(True)
        footer.addWidget(self.restore_point_check)
        footer.addStretch(1)
        self.selection_label = label("", "Dim")
        footer.addWidget(self.selection_label)
        outer.addLayout(footer)
        return page

    # ============================================================== REPAIR

    def _build_repair(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(46, 40, 46, 34)
        outer.setSpacing(14)

        outer.addWidget(label("Applying fixes", "H1"))
        self.repair_status = label("", "Dim")
        outer.addWidget(self.repair_status)
        outer.addSpacing(10)

        self.repair_log = QPlainTextEdit()
        self.repair_log.setReadOnly(True)
        outer.addWidget(self.repair_log, 1)

        row = QHBoxLayout()
        row.addStretch(1)
        self.repair_done_button = QPushButton("Back to results")
        self.repair_done_button.setObjectName("Primary")
        self.repair_done_button.setEnabled(False)
        self.repair_done_button.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        row.addWidget(self.repair_done_button)
        outer.addLayout(row)
        return page

    # ================================================================ MENU

    def _build_menu(self) -> None:
        tools = self.menuBar().addMenu("&Tools")

        undo = QAction("Undo a previous repair…", self)
        undo.triggered.connect(self._undo_dialog)
        tools.addAction(undo)

        open_backups = QAction("Open quarantine folder", self)
        open_backups.triggered.connect(
            lambda: webbrowser.open(str(backup_mod.data_root() / "backups"))
        )
        tools.addAction(open_backups)

        self.purge_action = QAction("Empty quarantine…", self)
        self.purge_action.triggered.connect(self._purge_quarantine)
        tools.addAction(self.purge_action)
        tools.aboutToShow.connect(self._refresh_purge_label)
        tools.addSeparator()

        for name, command in [
            ("Windows Security", "windowsdefender:"),
            ("Task Manager", "taskmgr.exe"),
            ("Disk Cleanup", "cleanmgr.exe"),
            ("Event Viewer", "eventvwr.msc"),
            ("Memory Diagnostic", "mdsched.exe"),
        ]:
            action = QAction(f"Open {name}", self)
            action.triggered.connect(
                lambda _checked=False, c=command: winutil.run(["cmd.exe", "/c", "start", "", c], timeout=10)
            )
            tools.addAction(action)

        help_menu = self.menuBar().addMenu("&Help")
        about = QAction("About", self)
        about.triggered.connect(self._about)
        help_menu.addAction(about)

    # ============================================================== ACTIONS

    def _elevate(self) -> None:
        if winutil.relaunch_as_admin():
            self.close()
        else:
            QMessageBox.warning(
                self, __app_name__,
                "Could not relaunch with administrator rights. Right-click the "
                "shortcut and choose 'Run as administrator' instead.",
            )

    def _start_scan(self, deep: bool) -> None:
        self.scan_log.clear()
        self._live_count = 0
        self.scan_status.setText("Deep scan in progress" if deep else "Scanning")
        self.scan_substatus.setText("Starting…")
        self.pulse.set_progress(0.0)
        self.pulse.start()
        self.cancel_button.setEnabled(True)
        self.stack.setCurrentIndex(1)

        self.scan_worker = ScanWorker(deep=deep, is_admin=self.is_admin)
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.issue_found.connect(self._on_issue_found)
        self.scan_worker.finished_report.connect(self._on_scan_finished)
        self.scan_worker.start()

    def _cancel_scan(self) -> None:
        if self.scan_worker:
            self.scan_worker.cancel()
            self.cancel_button.setEnabled(False)
            self.scan_substatus.setText("Cancelling — finishing the current check…")

    def _on_scan_progress(self, message: str, fraction: float) -> None:
        self.scan_substatus.setText(message)
        self.pulse.set_progress(fraction)

    def _on_issue_found(self, issue: Issue) -> None:
        if issue.counts_as_problem:
            self._live_count += 1
            self.scan_log.appendPlainText(
                f"[{issue.severity.label:<9}] {issue.title}"
            )
            self.scan_status.setText(
                f"Scanning — {self._live_count} issue(s) so far"
            )

    def _on_scan_finished(self, report: ScanReport) -> None:
        self.pulse.stop()
        self.report = report
        self._populate_results(report)
        self.stack.setCurrentIndex(2)

    # --------------------------------------------------------------- results

    def _populate_results(self, report: ScanReport) -> None:
        self.tree.blockSignals(True)
        self.tree.clear()

        for category, issues in report.by_category().items():
            parent = QTreeWidgetItem(self.tree)
            actionable = [i for i in issues if i.fixable]
            parent.setText(
                0,
                f"{category}  ({len(issues)})",
            )
            parent.setFirstColumnSpanned(False)
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            total_size = sum(i.size_bytes for i in issues if i.fixable)
            if total_size:
                parent.setText(2, human_bytes(total_size))
            if actionable:
                parent.setFlags(parent.flags() | Qt.ItemFlag.ItemIsUserCheckable
                                | Qt.ItemFlag.ItemIsAutoTristate)
                parent.setCheckState(0, Qt.CheckState.Unchecked)

            for issue in issues:
                child = QTreeWidgetItem(parent)
                child.setText(0, issue.title)
                child.setText(1, issue.severity.label)
                child.setForeground(1, QColor(issue.severity.color))
                if issue.size_bytes:
                    child.setText(2, human_bytes(issue.size_bytes))
                child.setData(0, ISSUE_ROLE, issue)
                if issue.fixable:
                    needs_admin = issue.requires_admin and not self.is_admin
                    child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    child.setCheckState(0, Qt.CheckState.Unchecked)
                    if needs_admin:
                        child.setDisabled(True)
                        child.setText(0, issue.title + "   (needs administrator)")
                else:
                    child.setFlags(child.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)

            parent.setExpanded(
                any(i.severity >= Severity.MEDIUM for i in issues)
            )

        self.tree.blockSignals(False)

        score = report.health_score()
        self.score_ring.animate_to(score)
        self.verdict_label.setText(report.verdict())
        pieces = [
            f"{len(report.problems)} issue(s) worth acting on",
            f"{human_bytes(report.reclaimable_bytes)} removable",
            f"scanned in {report.duration_s:.0f}s",
        ]
        if not report.was_admin:
            pieces.append("some checks skipped (not elevated)")
        if report.errors:
            pieces.append(f"{len(report.errors)} scanner(s) errored")
        self.summary_label.setText("   ·   ".join(pieces))
        self._update_selection_label()

    def _on_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        if column != 0:
            return
        issue = item.data(0, ISSUE_ROLE)
        if isinstance(issue, Issue):
            issue.selected = item.checkState(0) == Qt.CheckState.Checked
        self._update_selection_label()

    def _on_selection_changed(self, current: QTreeWidgetItem, _previous) -> None:
        if current is None:
            return
        issue = current.data(0, ISSUE_ROLE)
        if not isinstance(issue, Issue):
            self.detail_title.setText(current.text(0))
            self.detail_body.setPlainText("")
            return
        self.detail_title.setText(issue.title)
        body = [issue.detail]
        if issue.remediation_hint:
            body.append("\n\nWhat to do\n" + issue.remediation_hint)
        if issue.fixable:
            body.append(f"\n\nAutomatic fix: {issue.fix_label or 'available'}")
            if issue.fix_kind == FixKind.DELETE_FILES:
                count = len(issue.payload.get("paths", []))
                body.append(
                    f"\n{count:,} file(s) will be moved to Auroch's quarantine "
                    "folder, not deleted. Use Tools > Undo to put them back.\n"
                    "Quarantine is on the same drive, so the space is not "
                    "reclaimed until you run Tools > Empty quarantine."
                )
            elif issue.fix_kind in (FixKind.DELETE_REGKEY, FixKind.DELETE_REGVALUE):
                body.append(
                    "\nThe registry key is exported to a .reg file before removal."
                )
            elif issue.fix_kind == FixKind.RUN_COMMAND:
                argv = issue.payload.get("argv", [])
                body.append("\nCommand that will run:\n  " + " ".join(argv))
        else:
            body.append("\n\nNo automatic fix — this one is for you to decide on.")
        if issue.requires_admin and not self.is_admin:
            body.append("\n\n⚠ Requires administrator rights. Restart Auroch elevated.")
        if issue.requires_restart:
            body.append("\n\n⚠ Takes effect after a restart.")
        self.detail_body.setPlainText("".join(body))

    def _selected_issues(self) -> List[Issue]:
        selected: List[Issue] = []
        for i in range(self.tree.topLevelItemCount()):
            parent = self.tree.topLevelItem(i)
            for j in range(parent.childCount()):
                child = parent.child(j)
                issue = child.data(0, ISSUE_ROLE)
                if (
                    isinstance(issue, Issue)
                    and issue.fixable
                    and not child.isDisabled()
                    and child.checkState(0) == Qt.CheckState.Checked
                ):
                    selected.append(issue)
        return selected

    def _update_selection_label(self) -> None:
        selected = self._selected_issues()
        # Bytes that go to quarantine and bytes that are destroyed outright are
        # different things and must never be added into one number.
        quarantined = sum(
            i.size_bytes for i in selected if i.fix_kind == FixKind.DELETE_FILES
        )
        destroyed = sum(
            i.size_bytes for i in selected if i.fix_kind == FixKind.RUN_COMMAND
        )
        if not selected:
            self.selection_label.setText("Nothing selected")
            self.selection_label.setToolTip("")
            self.fix_button.setEnabled(False)
            self.fix_button.setText("Fix selected")
        else:
            # Deliberately NOT "frees X". Quarantine lives on the same volume
            # the files came from, so nothing is reclaimed until the
            # quarantine is emptied. Saying "frees" here would be a lie.
            parts = [f"{len(selected)} selected"]
            if quarantined:
                parts.append(f"{human_bytes(quarantined)} → quarantine")
            if destroyed:
                parts.append(f"{human_bytes(destroyed)} deleted permanently")
            self.selection_label.setText("  ·  ".join(parts))
            self.selection_label.setToolTip(
                "Quarantined files stay on the same drive, so disk space is not "
                "reclaimed until you empty the quarantine (Tools → Empty quarantine)."
            )
            self.fix_button.setEnabled(True)
            self.fix_button.setText(f"Fix {len(selected)} selected")

    # ---------------------------------------------------------------- repair

    def _confirm_repair(self) -> None:
        issues = self._selected_issues()
        if not issues:
            return

        # Split by whether Auroch can actually take it back. Anything that runs
        # a Windows command directly has no backup and no undo, and the user is
        # told exactly which items those are before confirming.
        reversible = [i for i in issues if i.fix_kind in
                      (FixKind.DELETE_FILES, FixKind.DELETE_REGKEY, FixKind.DELETE_REGVALUE)]
        irreversible = [i for i in issues if i.fix_kind == FixKind.RUN_COMMAND]
        restart = any(i.requires_restart for i in issues)

        lines = [f"  • {i.title}" for i in reversible[:12]]
        if len(reversible) > 12:
            lines.append(f"  … and {len(reversible) - 12} more")

        body = []
        if reversible:
            body.append(
                f"Reversible — {len(reversible)} item(s).\n"
                "Files go to quarantine, registry keys are exported to .reg first. "
                "Tools > Undo puts all of it back.\n" + "\n".join(lines)
            )
        if irreversible:
            body.append(
                f"⚠ CANNOT BE UNDONE — {len(irreversible)} item(s).\n"
                "These run a Windows command directly. Auroch takes no backup and "
                "cannot reverse them.\n"
                + "\n".join(f"  • {i.title}" for i in irreversible[:12])
            )
        if restart:
            body.append("⚠ One or more of these needs a restart to take effect.")

        box = QMessageBox(self)
        box.setWindowTitle("Confirm repairs")
        box.setIcon(
            QMessageBox.Icon.Warning if irreversible else QMessageBox.Icon.Question
        )
        box.setText(f"Apply {len(issues)} fix(es)?")
        box.setInformativeText("\n\n".join(body))
        box.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return

        make_rp = (
            self.restore_point_check.isChecked()
            and needs_restore_point(issues)
            and self.is_admin
        )

        self.repair_log.clear()
        self.repair_status.setText("Working…")
        self.repair_done_button.setEnabled(False)
        self.stack.setCurrentIndex(3)

        self.repair_worker = RepairWorker(issues, make_restore_point=make_rp)
        self.repair_worker.progress.connect(
            lambda msg, frac: self.repair_status.setText(f"{int(frac * 100)}%  ·  {msg}")
        )
        self.repair_worker.step_done.connect(
            lambda result: self.repair_log.appendPlainText(
                f"[{'OK  ' if result.ok else 'FAIL'}] {result.message}"
            )
        )
        self.repair_worker.finished_all.connect(self._on_repair_finished)
        self.repair_worker.start()

    def _on_repair_finished(self, results, backup_path) -> None:
        ok = sum(1 for r in results if r.ok)
        failed = len(results) - ok
        if self.repair_worker and self.repair_worker.restore_point_message:
            self.repair_log.appendPlainText(
                "\n" + self.repair_worker.restore_point_message
            )
        self.repair_status.setText(
            f"Finished — {ok} succeeded"
            + (f", {failed} failed" if failed else "")
        )
        if backup_path:
            quarantined = backup_mod.total_quarantine_size()
            self.repair_log.appendPlainText(
                f"\nBackup written to:\n{backup_path}\n"
                "Tools > Undo a previous repair will restore everything in it."
            )
            if quarantined:
                self.repair_log.appendPlainText(
                    f"\nNote: {human_bytes(quarantined)} now sits in quarantine on "
                    "the same drive it came from, so no disk space has been "
                    "reclaimed yet. Once you are satisfied nothing broke, use "
                    "Tools > Empty quarantine to actually free it."
                )
        if any(r.restart_required for r in results):
            self.repair_log.appendPlainText(
                "\n⚠ Restart Windows for some of these changes to take effect."
            )
        self.repair_done_button.setEnabled(True)

    # ----------------------------------------------------------------- misc

    def _export_report(self) -> None:
        if not self.report:
            return
        default = str(
            Path.home() / "Desktop"
            / f"Auroch-report-{datetime.now():%Y%m%d-%H%M}.html"
        )
        path, _ = QFileDialog.getSaveFileName(
            self, "Save report", default, "HTML files (*.html)"
        )
        if not path:
            return
        save_html(self.report, Path(path), __app_name__)
        if QMessageBox.question(
            self, __app_name__, "Report saved. Open it now?"
        ) == QMessageBox.StandardButton.Yes:
            webbrowser.open(Path(path).as_uri())

    def _refresh_purge_label(self) -> None:
        """Put the real number in the menu so it is visible before clicking."""
        size = backup_mod.total_quarantine_size()
        self.purge_action.setText(
            f"Empty quarantine… ({human_bytes(size)})" if size
            else "Empty quarantine… (empty)"
        )
        self.purge_action.setEnabled(size > 0)

    def _purge_quarantine(self) -> None:
        sessions = backup_mod.list_sessions()
        size = backup_mod.total_quarantine_size()
        if not sessions:
            QMessageBox.information(self, __app_name__, "The quarantine is empty.")
            return

        box = QMessageBox(self)
        box.setWindowTitle("Empty quarantine")
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(f"Permanently delete {human_bytes(size)} of quarantined files?")
        box.setInformativeText(
            f"{len(sessions)} repair backup(s) will be destroyed.\n\n"
            "This is the step that actually reclaims the disk space — until now "
            "those files were only moved, not deleted.\n\n"
            "Once this is done, Undo can no longer restore them. If a repair you "
            "made recently might still need reversing, keep the newest backup."
        )
        keep = box.addButton(
            "Delete all but the newest", QMessageBox.ButtonRole.AcceptRole
        )
        delete_all = box.addButton("Delete everything", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(keep)
        box.exec()

        clicked = box.clickedButton()
        if clicked is keep:
            removed, freed = backup_mod.purge_sessions(keep_newest=1)
        elif clicked is delete_all:
            removed, freed = backup_mod.purge_sessions(keep_newest=0)
        else:
            return

        QMessageBox.information(
            self,
            __app_name__,
            f"Removed {removed} backup(s) and freed {human_bytes(freed)} on disk.",
        )

    def _undo_dialog(self) -> None:
        sessions = backup_mod.list_sessions()
        if not sessions:
            QMessageBox.information(
                self, __app_name__, "There are no repair backups to undo."
            )
            return
        newest = sessions[0]
        if QMessageBox.question(
            self,
            "Undo repair",
            f"Restore everything from the repair run of {newest.name}?\n\n"
            "Files go back to their original locations and exported registry "
            "keys are re-imported.",
        ) != QMessageBox.StandardButton.Yes:
            return
        log = backup_mod.undo_session(newest)
        QMessageBox.information(
            self, __app_name__,
            "\n".join(log[:25]) + ("\n…" if len(log) > 25 else ""),
        )

    def _about(self) -> None:
        QMessageBox.about(
            self,
            f"About {__app_name__}",
            f"<b>{__app_name__} {__version__}</b><br><br>"
            "A PC health and repair tool for Windows.<br><br>"
            "It wraps Microsoft's own repair tools (SFC, DISM, Defender) rather "
            "than replacing them, rates findings conservatively, and backs up "
            "everything it touches.<br><br>"
            "Built for personal use. No telemetry, no network calls except the "
            "ones Windows Update and Defender make on their own.",
        )

    def closeEvent(self, event) -> None:  # noqa: N802
        for worker in (self.scan_worker, self.repair_worker):
            if worker and worker.isRunning():
                if hasattr(worker, "cancel"):
                    worker.cancel()
                worker.wait(3000)
        event.accept()
