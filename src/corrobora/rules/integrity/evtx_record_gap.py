"""EVTX record-number gap detection rule."""

from __future__ import annotations

import itertools
from pathlib import Path

from ..base import CorrelationContext, CorrelationFinding, CorrelationRule, Severity

# Corroboration-strength scores for this rule's two finding shapes.
# A significant, individually-reported gap is a more deliberate-looking
# anomaly than the small, scattered gaps that get aggregated into a
# routine-behavior summary -- see the rule's own docstring.
_SIGNIFICANT_GAP_SCORE = 55
_MINOR_GAP_SUMMARY_SCORE = 10


class EvtxRecordNumberGapRule(CorrelationRule):  # pylint: disable=too-few-public-methods
    """Flags gaps in EVTX record number sequences within a single log file.

    EVTX record numbers are assigned sequentially. A gap in the
    sequence can indicate normal log rotation/overwrite behavior, but
    can also indicate selective record wiping by an anti-forensic
    tool. In practice, small (often size-1) gaps are extremely common
    in normal Windows telemetry -- Operational/Diagnostic channels in
    particular routinely skip record numbers for filtered or
    unlogged event types, with no forensic significance at all.
    Reporting every such gap as its own finding buries any genuinely
    suspicious gap in noise and trains analysts to ignore this rule.

    To keep the signal meaningful, this rule distinguishes two cases:

    - Gaps at or above ``significant_gap_size`` are reported
      individually at MEDIUM severity -- a run of several
      consecutive missing records is much less consistent with
      routine filtering and more worth a specific look.
    - Smaller gaps are aggregated into a single INFO-severity summary
      finding per source file (count, total records missing, largest
      gap seen), so the information isn't hidden entirely but also
      doesn't dominate the findings list.
    """

    rule_name = "evtx_record_number_gap"
    category = "integrity"

    def __init__(self, significant_gap_size: int = 10) -> None:
        """Initialize the rule.

        Args:
            significant_gap_size: The minimum number of consecutive
                missing record numbers required to report a gap as
                its own individual finding. Gaps smaller than this
                are aggregated into one summary finding per file
                instead. Defaults to 10.
        """
        self._significant_gap_size = significant_gap_size

    def evaluate(self, context: CorrelationContext) -> list[CorrelationFinding]:
        by_source: dict[str, list[int]] = {}
        for entry in context.evtx_entries:
            by_source.setdefault(entry.source_path, []).append(entry.record.record_number)

        findings: list[CorrelationFinding] = []
        for source_path, record_numbers in by_source.items():
            findings.extend(self._evaluate_source(source_path, record_numbers))
        return findings

    def _evaluate_source(
        self, source_path: str, record_numbers: list[int]
    ) -> list[CorrelationFinding]:
        """Evaluate gaps within a single source file's record numbers.

        Args:
            source_path: The EVTX file these record numbers came from.
            record_numbers: The record numbers found in that file.

        Returns:
            Individual findings for significant gaps, plus at most
            one aggregated summary finding for smaller gaps.
        """
        record_numbers = sorted(record_numbers)
        findings: list[CorrelationFinding] = []
        minor_gaps: list[tuple[int, int, int]] = []  # (previous, current, gap_size)

        for previous, current in itertools.pairwise(record_numbers):
            gap_size = current - previous - 1
            if gap_size <= 0:
                continue
            if gap_size >= self._significant_gap_size:
                findings.append(self._build_significant_finding(source_path, previous, current))
            else:
                minor_gaps.append((previous, current, gap_size))

        if minor_gaps:
            findings.append(self._build_summary_finding(source_path, minor_gaps))
        return findings

    def _build_significant_finding(
        self, source_path: str, previous: int, current: int
    ) -> CorrelationFinding:
        """Build an individual finding for a single significant gap.

        Args:
            source_path: The EVTX file this gap was found in.
            previous: The record number immediately before the gap.
            current: The record number immediately after the gap.

        Returns:
            The populated :class:`CorrelationFinding`.
        """
        gap_size = current - previous - 1
        return CorrelationFinding(
            rule_name=self.rule_name,
            severity=Severity.MEDIUM,
            description=(
                f"EVTX record number gap in '{Path(source_path).name}': "
                f"{gap_size} consecutive missing record(s) between "
                f"#{previous} and #{current}. A gap this large is less "
                f"consistent with routine channel filtering and may "
                f"warrant a closer look."
            ),
            evidence=(
                f"EVTX source: {source_path}",
                f"Gap range: {previous + 1}-{current - 1}",
            ),
            source_paths=(source_path,),
            score=_SIGNIFICANT_GAP_SCORE,
        )

    def _build_summary_finding(
        self, source_path: str, minor_gaps: list[tuple[int, int, int]]
    ) -> CorrelationFinding:
        """Build one aggregated finding summarizing routine small gaps.

        Args:
            source_path: The EVTX file these gaps were found in.
            minor_gaps: The ``(previous, current, gap_size)`` tuples
                for every gap below the significance threshold.

        Returns:
            A single INFO-severity :class:`CorrelationFinding`
            summarizing all minor gaps in this file.
        """
        total_missing = sum(gap_size for _, _, gap_size in minor_gaps)
        largest = max(gap_size for _, _, gap_size in minor_gaps)
        return CorrelationFinding(
            rule_name=self.rule_name,
            severity=Severity.INFO,
            description=(
                f"EVTX record number gaps in '{Path(source_path).name}': "
                f"{len(minor_gaps)} small gap(s) totaling {total_missing} "
                f"missing record(s) (largest single gap: {largest}). "
                f"Small, scattered gaps like this are common in "
                f"Operational/Diagnostic channels and are usually routine "
                f"log behavior rather than tampering."
            ),
            evidence=tuple(
                f"Gap range: {previous + 1}-{current - 1} ({gap_size} missing)"
                for previous, current, gap_size in minor_gaps[:10]
            )
            + ((f"... and {len(minor_gaps) - 10} more",) if len(minor_gaps) > 10 else ()),
            source_paths=(source_path,),
            score=_MINOR_GAP_SUMMARY_SCORE,
        )
