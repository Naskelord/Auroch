"""Custom widgets: the score ring and the scanning pulse."""
from __future__ import annotations

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPropertyAnimation,
    QRectF,
    Qt,
    QTimer,
)
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget

from . import theme


class ScoreRing(QWidget):
    """Circular health score, 0-100, animated."""

    def __init__(self, parent=None, diameter: int = 200):
        super().__init__(parent)
        self._value = 0.0
        self._diameter = diameter
        self._caption = ""
        self.setFixedSize(diameter, diameter)
        self._anim = QPropertyAnimation(self, b"value", self)
        self._anim.setDuration(900)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def get_value(self) -> float:
        return self._value

    def set_value(self, v: float) -> None:
        self._value = max(0.0, min(100.0, float(v)))
        self.update()

    value = Property(float, get_value, set_value)

    def animate_to(self, target: float, caption: str = "") -> None:
        self._caption = caption
        self._anim.stop()
        self._anim.setStartValue(self._value)
        self._anim.setEndValue(float(target))
        self._anim.start()

    def set_caption(self, text: str) -> None:
        self._caption = text
        self.update()

    def _color(self) -> QColor:
        if self._value >= 85:
            return QColor(theme.GOOD)
        if self._value >= 60:
            return QColor(theme.WARN)
        return QColor(theme.BAD)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        margin = 12.0
        rect = QRectF(margin, margin,
                      self.width() - 2 * margin, self.height() - 2 * margin)

        track = QPen(QColor(theme.PANEL_HI), 13)
        track.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track)
        painter.drawArc(rect, 0, 360 * 16)

        if self._value > 0:
            arc = QPen(self._color(), 13)
            arc.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(arc)
            span = int(-self._value / 100.0 * 360 * 16)
            painter.drawArc(rect, 90 * 16, span)

        painter.setPen(QColor(theme.TEXT))
        font = QFont(self.font())
        font.setPointSize(int(self._diameter * 0.20))
        font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(font)
        number_rect = QRectF(0, self.height() * 0.26, self.width(), self.height() * 0.34)
        painter.drawText(number_rect, Qt.AlignmentFlag.AlignCenter, f"{int(round(self._value))}")

        painter.setPen(QColor(theme.DIM))
        small = QFont(self.font())
        small.setPointSize(9)
        painter.setFont(small)
        caption_rect = QRectF(0, self.height() * 0.58, self.width(), self.height() * 0.18)
        painter.drawText(
            caption_rect,
            Qt.AlignmentFlag.AlignCenter,
            self._caption or "HEALTH SCORE",
        )
        painter.end()


class PulseRing(QWidget):
    """Indeterminate spinner shown while a scan runs."""

    def __init__(self, parent=None, diameter: int = 200):
        super().__init__(parent)
        self._angle = 0
        self._progress = 0.0
        self.setFixedSize(diameter, diameter)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._diameter = diameter

    def start(self) -> None:
        self._timer.start(16)

    def stop(self) -> None:
        self._timer.stop()

    def set_progress(self, fraction: float) -> None:
        self._progress = max(0.0, min(1.0, fraction))
        self.update()

    def _tick(self) -> None:
        self._angle = (self._angle + 3) % 360
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        margin = 12.0
        rect = QRectF(margin, margin,
                      self.width() - 2 * margin, self.height() - 2 * margin)

        track = QPen(QColor(theme.PANEL_HI), 13)
        track.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track)
        painter.drawArc(rect, 0, 360 * 16)

        # Real progress arc.
        if self._progress > 0:
            done = QPen(QColor(theme.ACCENT_DIM), 13)
            done.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(done)
            painter.drawArc(rect, 90 * 16, int(-self._progress * 360 * 16))

        # Sweeping highlight so it never looks frozen during a long step.
        sweep = QPen(QColor(theme.ACCENT), 13)
        sweep.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(sweep)
        painter.drawArc(rect, -self._angle * 16, 50 * 16)

        painter.setPen(QColor(theme.TEXT))
        font = QFont(self.font())
        font.setPointSize(int(self._diameter * 0.15))
        font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(font)
        painter.drawText(
            QRectF(0, self.height() * 0.32, self.width(), self.height() * 0.3),
            Qt.AlignmentFlag.AlignCenter,
            f"{int(self._progress * 100)}%",
        )
        painter.end()
