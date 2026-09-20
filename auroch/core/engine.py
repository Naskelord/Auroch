"""Scan orchestration. UI-agnostic: talks to the caller through callbacks."""
from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .issue import Category, Issue, Severity
from .scanner import ScanContext, Scanner, all_scanners


@dataclass
class ScanReport:
    issues: List[Issue] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)
    duration_s: float = 0.0
    was_admin: bool = False
    deep: bool = False
    started_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------- queries

    def by_category(self) -> Dict[str, List[Issue]]:
        buckets: Dict[str, List[Issue]] = {}
        for issue in self.issues:
            buckets.setdefault(issue.category, []).append(issue)
        for bucket in buckets.values():
            bucket.sort(key=lambda i: (-int(i.severity), -i.size_bytes, i.title))
        return {
            cat: buckets[cat]
            for cat in Category.ORDER
            if cat in buckets
        } | {cat: v for cat, v in buckets.items() if cat not in Category.ORDER}

    @property
    def problems(self) -> List[Issue]:
        return [i for i in self.issues if i.counts_as_problem]

    @property
    def reclaimable_bytes(self) -> int:
        return sum(i.size_bytes for i in self.issues if i.fixable)

    @property
    def worst(self) -> Severity:
        return max((i.severity for i in self.problems), default=Severity.INFO)

    def health_score(self) -> int:
        """0-100. Weighted by severity, not by raw count.

        Two separate accumulators, because they should behave differently:

        * Minor and moderate findings accumulate with diminishing returns. A
          thousand temp files is not a broken PC, and no quantity of them
          should imply one. This is the specific lie commercial cleaners tell.
        * Important and critical findings accumulate linearly and hit hard. One
          drive predicting its own failure *is* a broken PC.
        """
        minor = 0.0
        major = 0.0
        for issue in self.problems:
            if issue.severity == Severity.LOW:
                minor += 0.7
            elif issue.severity == Severity.MEDIUM:
                minor += 4.5
            elif issue.severity == Severity.HIGH:
                major += 17.0
            elif issue.severity == Severity.CRITICAL:
                major += 60.0

        # Hard ceiling on the minor contribution. Without it, a machine with
        # nothing wrong but a large temp folder scores like a failing one —
        # which is precisely the scare tactic this tool exists to avoid.
        minor_penalty = min(minor ** 0.82, 22.0) if minor > 0 else 0.0
        penalty = minor_penalty + major
        return max(0, min(100, int(round(100.0 - min(penalty, 100.0)))))

    def verdict(self) -> str:
        if not self.problems:
            return "No issues found. Your PC is in good shape."

        # The wording is driven by the worst thing found, not by the count.
        # Nothing but housekeeping is never described as a problem, however
        # much of it there is.
        if self.worst <= Severity.LOW:
            return "Healthy. Only housekeeping to do — nothing is wrong."
        if self.worst == Severity.MEDIUM:
            return "Healthy overall, with a few moderate things worth fixing."

        score = self.health_score()
        # Name the band that actually exists in this report, so the sentence
        # can never point the user at a severity nothing was filed under.
        band = "Critical" if self.worst == Severity.CRITICAL else "Important"
        if score >= 70:
            return "Mostly fine, but one or more important issues need attention."
        if score >= 40:
            return f"Several real problems need attention. Start with the {band} items."
        return f"Serious problems found. Read the {band} items first."


class ScanEngine:
    def __init__(self) -> None:
        # Importing the package is what populates the scanner registry, so do
        # it here rather than relying on the caller having done it.
        import auroch.scanners  # noqa: F401  pylint: disable=unused-import

        self.scanners: List[Scanner] = all_scanners()
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(
        self,
        deep: bool = False,
        is_admin: bool = False,
        enabled_ids: Optional[List[str]] = None,
        on_progress: Optional[Callable[[str, float], None]] = None,
        on_issue: Optional[Callable[[Issue], None]] = None,
    ) -> ScanReport:
        self._cancel = False
        report = ScanReport(was_admin=is_admin, deep=deep)
        started = time.perf_counter()

        active = [
            s
            for s in self.scanners
            if (enabled_ids is None or s.id in enabled_ids)
            and (deep or not s.deep_only)
        ]
        total_weight = sum(s.weight for s in active) or 1.0
        done_weight = 0.0

        for scanner in active:
            if self._cancel:
                break

            def progress(message: str, frac: float = -1.0, _s=scanner, _d=done_weight):
                if frac < 0:
                    overall = _d / total_weight
                else:
                    overall = (_d + _s.weight * max(0.0, min(1.0, frac))) / total_weight
                if on_progress:
                    on_progress(message, overall)

            ctx = ScanContext(
                is_admin=is_admin,
                deep=deep,
                progress=progress,
                cancelled=lambda: self._cancel,
            )
            progress(f"Scanning: {scanner.name}", 0.0)

            try:
                for issue in scanner.scan(ctx) or []:
                    if self._cancel:
                        break
                    report.issues.append(issue)
                    if on_issue:
                        on_issue(issue)
            except Exception as exc:
                report.errors[scanner.name] = f"{exc.__class__.__name__}: {exc}"
                traceback.print_exc()

            done_weight += scanner.weight
            if on_progress:
                on_progress(f"Finished: {scanner.name}", done_weight / total_weight)

        report.duration_s = time.perf_counter() - started
        if on_progress:
            on_progress("Scan complete", 1.0)
        return report
