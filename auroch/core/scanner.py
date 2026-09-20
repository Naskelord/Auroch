"""Scanner base class and the global registry."""
from __future__ import annotations

from typing import Callable, Iterable, List, Optional, Type

from .issue import Issue


class ScanContext:
    """Passed to every scanner. Carries settings and a progress callback."""

    def __init__(
        self,
        is_admin: bool = False,
        deep: bool = False,
        progress: Optional[Callable[[str, float], None]] = None,
        cancelled: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.is_admin = is_admin
        self.deep = deep
        self._progress = progress
        self._cancelled = cancelled

    def report(self, message: str, fraction: float = -1.0) -> None:
        if self._progress:
            self._progress(message, fraction)

    @property
    def cancelled(self) -> bool:
        return bool(self._cancelled and self._cancelled())


class Scanner:
    """Subclass and implement `scan`.

    A scanner reports findings. It never changes the system. All mutation goes
    through core.actions, which takes backups first.
    """

    id: str = "scanner"
    name: str = "Scanner"
    description: str = ""
    category: str = ""
    requires_admin: bool = False
    #: Rough relative cost, used to weight the progress bar.
    weight: float = 1.0
    #: Only run when the user asked for a deep scan.
    deep_only: bool = False

    def scan(self, ctx: ScanContext) -> Iterable[Issue]:  # pragma: no cover
        raise NotImplementedError


_REGISTRY: List[Type[Scanner]] = []


def register(cls: Type[Scanner]) -> Type[Scanner]:
    _REGISTRY.append(cls)
    return cls


def all_scanners() -> List[Scanner]:
    """Instantiate every registered scanner, in declaration order."""
    return [cls() for cls in _REGISTRY]
