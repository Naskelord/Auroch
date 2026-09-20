"""Auroch entry point.

Run:
    python main.py            standard user
    python main.py --elevate  relaunch with administrator rights first
    python main.py --cli      text-mode scan, no GUI (useful from a scheduled task)
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make `python main.py` work regardless of the working directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from auroch import __app_name__, __version__  # noqa: E402
from auroch.core import winutil  # noqa: E402
import auroch.scanners  # noqa: F401,E402  (registers every scanner)


def run_cli(deep: bool = False) -> int:
    from auroch.core.engine import ScanEngine
    from auroch.core.issue import human_bytes
    from auroch.core.report import save_html

    print(f"{__app_name__} {__version__} — command line scan")
    print("Elevated:" , winutil.is_admin())
    print()

    engine = ScanEngine()

    def progress(message: str, fraction: float) -> None:
        sys.stdout.write(f"\r[{int(fraction * 100):3d}%] {message[:70]:<70}")
        sys.stdout.flush()

    report = engine.run(deep=deep, is_admin=winutil.is_admin(), on_progress=progress)
    print("\n")

    for category, issues in report.by_category().items():
        print(f"== {category}")
        for issue in issues:
            size = f"  [{human_bytes(issue.size_bytes)}]" if issue.size_bytes else ""
            print(f"   {issue.severity.label:<9} {issue.title}{size}")
        print()

    print(f"Health score: {report.health_score()}/100 — {report.verdict()}")
    print(f"{len(report.problems)} issue(s) worth acting on, "
          f"{human_bytes(report.reclaimable_bytes)} reclaimable.")

    out = Path.home() / "Desktop" / "Auroch-report.html"
    try:
        save_html(report, out, __app_name__)
        print(f"Report written to {out}")
    except Exception as exc:
        print(f"Could not write report: {exc}")
    return 0


def run_gui() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print(
            "PySide6 is not installed.\n\n"
            "    pip install -r requirements.txt\n\n"
            "Or run the text-mode scan instead:  python main.py --cli"
        )
        return 1

    from auroch.ui import theme
    from auroch.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName(__app_name__)
    app.setApplicationVersion(__version__)
    app.setStyle("Fusion")
    app.setStyleSheet(theme.QSS)

    window = MainWindow()
    window.show()
    return app.exec()


def main() -> int:
    args = set(sys.argv[1:])

    if "--elevate" in args and not winutil.is_admin():
        if winutil.relaunch_as_admin():
            return 0
        print("Could not elevate. Continuing as a standard user.")

    if "--cli" in args:
        return run_cli(deep="--deep" in args)
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
