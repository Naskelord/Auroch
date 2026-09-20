"""Dark theme. One palette, defined once."""
from __future__ import annotations

# Aurochs-horn gold against gunmetal.
BG = "#12161c"
PANEL = "#1a2029"
PANEL_HI = "#212936"
LINE = "#2a3340"
TEXT = "#e6ebf2"
DIM = "#93a0b1"
ACCENT = "#c9a227"
ACCENT_DIM = "#8f741c"
GOOD = "#4fae6a"
WARN = "#d0a03f"
BAD = "#d0453f"

QSS = f"""
QWidget {{
    background: {BG};
    color: {TEXT};
    font-family: "Segoe UI", "Inter", system-ui, sans-serif;
    font-size: 14px;
}}
QFrame#Panel {{
    background: {PANEL};
    border: 1px solid {LINE};
    border-radius: 12px;
}}
/* Labels must not paint their own background, or every caption inside a
   panel renders as a darker rectangle. */
QLabel {{ background: transparent; }}
QCheckBox {{ background: transparent; }}

QLabel#H1 {{ font-size: 26px; font-weight: 600; }}
QLabel#H2 {{ font-size: 18px; font-weight: 600; }}
QLabel#Dim {{ color: {DIM}; }}
QLabel#Mono {{ font-family: "Cascadia Mono", Consolas, monospace; font-size: 13px; }}

QPushButton {{
    background: {PANEL_HI};
    border: 1px solid {LINE};
    border-radius: 8px;
    padding: 9px 18px;
    color: {TEXT};
}}
QPushButton:hover {{ background: #283242; border-color: #3a4657; }}
QPushButton:pressed {{ background: #1c2431; }}
QPushButton:disabled {{ color: #5c6774; background: #171d25; }}

QPushButton#Primary {{
    background: {ACCENT};
    border: 1px solid {ACCENT};
    color: #14100a;
    font-weight: 600;
    padding: 11px 26px;
}}
QPushButton#Primary:hover {{ background: #d8b13a; border-color: #d8b13a; }}
QPushButton#Primary:disabled {{ background: {ACCENT_DIM}; color: #2a2414; }}

QPushButton#Danger {{
    background: {BAD}; border-color: {BAD}; color: #fff; font-weight: 600;
}}
QPushButton#Danger:hover {{ background: #e0574f; }}

QTreeWidget {{
    background: {PANEL};
    border: 1px solid {LINE};
    border-radius: 10px;
    outline: 0;
    padding: 4px;
}}
QTreeWidget::item {{ padding: 7px 4px; border-radius: 6px; }}
QTreeWidget::item:selected {{ background: {PANEL_HI}; color: {TEXT}; }}
QTreeWidget::item:hover {{ background: #1f2733; }}
QHeaderView::section {{
    background: {BG}; color: {DIM}; border: 0; border-bottom: 1px solid {LINE};
    padding: 8px 6px; font-weight: 600;
}}

QTextEdit, QPlainTextEdit {{
    background: {PANEL};
    border: 1px solid {LINE};
    border-radius: 10px;
    padding: 10px;
    selection-background-color: {ACCENT_DIM};
}}

QProgressBar {{
    background: {PANEL_HI};
    border: 0; border-radius: 5px; height: 8px; text-align: center; color: transparent;
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}

QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{
    width: 17px; height: 17px; border-radius: 4px;
    border: 1px solid #455263; background: {PANEL_HI};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QCheckBox::indicator:indeterminate {{ background: {ACCENT_DIM}; border-color: {ACCENT_DIM}; }}

QScrollBar:vertical {{ background: transparent; width: 11px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #333e4d; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: #404d5f; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #333e4d; border-radius: 5px; min-width: 30px; }}

QMenuBar {{ background: {BG}; border-bottom: 1px solid {LINE}; padding: 3px 6px; }}
QMenuBar::item {{ padding: 6px 12px; border-radius: 6px; background: transparent; }}
QMenuBar::item:selected {{ background: {PANEL_HI}; }}
QMenu {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 8px; padding: 6px; }}
QMenu::item {{ padding: 7px 22px; border-radius: 6px; }}
QMenu::item:selected {{ background: {PANEL_HI}; }}
QMenu::separator {{ height: 1px; background: {LINE}; margin: 6px 8px; }}

QStatusBar {{ color: {DIM}; border-top: 1px solid {LINE}; }}
QStatusBar::item {{ border: 0; }}
QToolTip {{
    background: {PANEL_HI}; color: {TEXT}; border: 1px solid {LINE};
    padding: 6px; border-radius: 6px;
}}
QSplitter::handle {{ background: transparent; }}
"""
