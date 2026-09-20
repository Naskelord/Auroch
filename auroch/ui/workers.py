"""Background threads. The GUI thread never blocks on a scan or a repair."""
from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import QThread, Signal

from ..core.actions import Repairer
from ..core.backup import create_restore_point
from ..core.engine import ScanEngine, ScanReport
from ..core.issue import FixResult, Issue


class ScanWorker(QThread):
    progress = Signal(str, float)
    issue_found = Signal(object)
    finished_report = Signal(object)

    def __init__(self, deep: bool, is_admin: bool, parent=None):
        super().__init__(parent)
        self.deep = deep
        self.is_admin = is_admin
        self.engine = ScanEngine()

    def cancel(self) -> None:
        self.engine.cancel()

    def run(self) -> None:  # noqa: D102
        report = self.engine.run(
            deep=self.deep,
            is_admin=self.is_admin,
            on_progress=lambda msg, frac: self.progress.emit(msg, frac),
            on_issue=lambda issue: self.issue_found.emit(issue),
        )
        self.finished_report.emit(report)


class RepairWorker(QThread):
    progress = Signal(str, float)
    step_done = Signal(object)
    finished_all = Signal(list, object)

    def __init__(self, issues: List[Issue], make_restore_point: bool, parent=None):
        super().__init__(parent)
        self.issues = issues
        self.make_restore_point = make_restore_point
        self.restore_point_message = ""

    def run(self) -> None:  # noqa: D102
        if self.make_restore_point:
            self.progress.emit("Creating a System Restore point…", 0.0)
            ok, message = create_restore_point()
            self.restore_point_message = message

        repairer = Repairer()
        results: List[FixResult] = []
        total = max(len(self.issues), 1)
        for index, issue in enumerate(self.issues):
            self.progress.emit(issue.title, index / total)
            result = repairer.apply(issue)
            results.append(result)
            self.step_done.emit(result)

        backup_path: Optional[str] = None
        if repairer.session:
            repairer.session.save()
            repairer.session.discard_if_empty()
            if not repairer.session.is_empty:
                backup_path = str(repairer.session.root)

        self.progress.emit("Done", 1.0)
        self.finished_all.emit(results, backup_path)
