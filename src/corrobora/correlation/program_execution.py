"""Program-execution corroboration across independent artifact sources.

Given program-execution :class:`~corrobora.models.evidence.EvidenceRecord`
objects for one subject (e.g. ``powershell.exe``), this module asks: do
multiple independent artifact sources contain evidence that is
consistent within a defined time window?

Method:

1. Keep the ``PROGRAM_EXECUTION`` records for the subject.
2. Group them by artifact source. Each :class:`ArtifactType` counts as
   one source: two EVTX files (e.g. Security and Sysmon) are one source,
   not two, which is the conservative choice.
3. Build an agreeing group from timestamps according to what they
   record (:class:`~corrobora.models.evidence.TimestampAnchor`):

   - **Start-anchored** timestamps (Prefetch run times, 4688/Sysmon 1)
     agree if their total spread (latest minus earliest) is within the
     window.
   - **End-anchored** timestamps (BAM, which records process exit) are
     not compared with the window: their distance from the start is
     however long the program ran. An end-anchored record joins a
     start group if it is at or after the group's latest start and no
     other start for the subject falls in between, i.e. it records the
     exit of the most recent run that started before it. BAM keeps only
     one time per user and program, so it can support at most one run.

   The best group covers the most distinct sources; ties go to the most
   recent group, then the tightest.
4. Classify:

   - ``CORROBORATED``: at least two sources fall in that group, and every
     examined source is among them.
   - ``PARTIALLY_CORROBORATED``: at least two sources fall in the group,
     but some examined source is absent from it (no evidence, evidence
     outside the window, or evidence with no timestamp).
   - ``NEEDS_REVIEW``: fewer than two sources agree, or fewer than two
     sources were examined.

The window is a required argument with no default. What each artifact's
timestamp records, and how far apart genuinely related timestamps can be,
is still being established (see
:class:`~corrobora.models.evidence.TimestampSemantics`), so this module
does not presume a correct value. The window used is carried on every
finding so reports can state it.

The window applies to start-anchored timestamps only. Only the single
best-agreeing group is evaluated. Other recorded runs of
the same program (Prefetch keeps up to eight) are not individually
assessed, and their lack of corroboration is not reported as a
discrepancy.

Nothing here treats missing evidence as evidence of deletion or
anti-forensic activity; explanations say so explicitly.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from corrobora.models.evidence import EvidenceRecord, EvidenceType, TimestampAnchor
from corrobora.parsers.Base import ArtifactType

# Display order for sources in findings and reports; any other artifact
# type follows, in enum order.
_SOURCE_ORDER = (ArtifactType.PREFETCH, ArtifactType.EVTX, ArtifactType.REGISTRY)

SOURCE_LABELS: dict[ArtifactType, str] = {
    ArtifactType.PREFETCH: "Prefetch",
    ArtifactType.EVTX: "EVTX",
    ArtifactType.REGISTRY: "Registry",
    ArtifactType.MFT: "MFT",
    ArtifactType.AMCACHE: "Amcache",
    ArtifactType.SRUM: "SRUM",
    ArtifactType.SHELLBAGS: "ShellBags",
    ArtifactType.EXTERNAL_CSV: "External CSV",
}

_NOT_ANTI_FORENSIC = (
    "This discrepancy does not establish deletion or anti-forensic activity. "
    "Examiner review is required."
)


class CorroborationStatus(str, Enum):
    """How well independent sources agree about a program's execution."""

    CORROBORATED = "corroborated"
    PARTIALLY_CORROBORATED = "partially_corroborated"
    NEEDS_REVIEW = "needs_review"


@dataclass(frozen=True, slots=True)
class SourceObservation:
    """What one examined artifact source contributed to a finding.

    Attributes:
        artifact_type: The artifact source.
        evidence: Every execution record for the subject from this
            source, in input order. Empty if the source was examined but
            contained no evidence for the subject.
        representative: The record to present for this source: the one
            inside the agreeing group if ``in_window``; otherwise the
            timed record nearest the group (or the most recent timed
            record if there is no group); otherwise an untimed record;
            ``None`` if ``evidence`` is empty.
        in_window: Whether this source is part of the agreeing group
            (for an end-anchored source, whether its exit time follows
            the group's starts as described in the module docstring).
    """

    artifact_type: ArtifactType
    evidence: tuple[EvidenceRecord, ...]
    representative: EvidenceRecord | None
    in_window: bool

    @property
    def observed(self) -> bool:
        """Whether this source contained any evidence for the subject."""
        return bool(self.evidence)

    @property
    def label(self) -> str:
        """Human-readable name of this source."""
        return SOURCE_LABELS.get(self.artifact_type, self.artifact_type.value)


@dataclass(frozen=True, slots=True)
class ProgramExecutionFinding:
    """The corroboration result for one subject.

    Attributes:
        subject: The normalized subject (e.g. ``"powershell.exe"``).
        status: The corroboration outcome.
        window: The correlation window the result was computed with.
        sources: One observation per examined source, in display order.
        explanation: Plain-language sentences explaining ``status``,
            suitable for printing as-is.
    """

    subject: str
    status: CorroborationStatus
    window: timedelta
    sources: tuple[SourceObservation, ...]
    explanation: tuple[str, ...]


def correlate_program_execution(
    records: Iterable[EvidenceRecord],
    subject: str,
    examined_sources: Iterable[ArtifactType],
    window: timedelta,
) -> ProgramExecutionFinding | None:
    """Assess whether independent sources corroborate a program's execution.

    Args:
        records: Evidence from any number of sources and subjects; only
            ``PROGRAM_EXECUTION`` records for ``subject`` are used.
        subject: The normalized subject to assess (e.g.
            ``"powershell.exe"``).
        examined_sources: The artifact sources that were actually
            analyzed, whether or not they yielded evidence. This is what
            separates "no Registry evidence was identified" from "the
            Registry was not examined". Any source that contributed
            evidence is treated as examined even if not listed.
        window: The maximum spread between the earliest and latest
            start-anchored timestamps counted as agreeing. Must be
            positive. End-anchored timestamps are not bounded by it.

    Returns:
        The finding, or ``None`` if no source contains execution evidence
        for ``subject``.

    Raises:
        ValueError: If ``window`` is not positive.
    """
    if window <= timedelta(0):
        raise ValueError("window must be positive")

    relevant = [
        record
        for record in records
        if record.evidence_type is EvidenceType.PROGRAM_EXECUTION and record.subject == subject
    ]
    if not relevant:
        return None

    by_source: dict[ArtifactType, list[EvidenceRecord]] = {}
    for record in relevant:
        by_source.setdefault(record.artifact_type, []).append(record)
    examined = set(examined_sources) | set(by_source)

    group = _best_group(relevant, window)
    if len({record.artifact_type for record in group}) < 2:
        # A single source "agreeing with itself" is not corroboration.
        group = []
    group_sources = {record.artifact_type: record for record in group}
    group_midpoint = _midpoint(
        [r for r in group if _anchor(r) is TimestampAnchor.PROCESS_START]
    )

    sources = tuple(
        _observe(
            source,
            tuple(by_source.get(source, ())),
            group_sources.get(source),
            group_midpoint,
        )
        for source in _ordered(examined)
    )
    status = _classify(len(group_sources), len(examined))
    return ProgramExecutionFinding(
        subject=subject,
        status=status,
        window=window,
        sources=sources,
        explanation=_explain(status, subject, sources),
    )


def correlate_all_program_execution(
    records: Iterable[EvidenceRecord],
    examined_sources: Iterable[ArtifactType],
    window: timedelta,
) -> list[ProgramExecutionFinding]:
    """Run :func:`correlate_program_execution` for every subject present.

    Args:
        records: Evidence from any number of sources and subjects.
        examined_sources: See :func:`correlate_program_execution`.
        window: See :func:`correlate_program_execution`.

    Returns:
        One finding per subject with execution evidence, sorted by
        subject.
    """
    records = list(records)
    examined = list(examined_sources)
    subjects = sorted(
        {r.subject for r in records if r.evidence_type is EvidenceType.PROGRAM_EXECUTION}
    )
    findings = []
    for subject in subjects:
        finding = correlate_program_execution(records, subject, examined, window)
        if finding is not None:
            findings.append(finding)
    return findings


# --------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------


def _anchor(record: EvidenceRecord) -> TimestampAnchor:
    """The record's anchor, or ``NOT_EXECUTION_TIME`` if it has no timestamp."""
    if record.timestamp is None:
        return TimestampAnchor.NOT_EXECUTION_TIME
    return record.timestamp_semantics.anchor


def _is_timed(record: EvidenceRecord) -> bool:
    return _anchor(record) is not TimestampAnchor.NOT_EXECUTION_TIME


def _best_group(records: list[EvidenceRecord], window: timedelta) -> list[EvidenceRecord]:
    """Find the agreeing group covering the most distinct sources.

    Slides over the start-anchored records in time order, considering
    every run of records whose spread is within ``window``. Each run keeps
    one record per source (the one closest to the run's midpoint), then
    gains one end-anchored record per source that records the exit of
    that run (see the module docstring). The best group covers the most
    distinct sources; ties go to the most recent run, then the tightest.

    Returns:
        One record per source in the best group, or an empty list if
        there is no start-anchored record.
    """
    starts = sorted(
        (r for r in records if _anchor(r) is TimestampAnchor.PROCESS_START),
        key=lambda r: r.timestamp,
    )
    ends = sorted(
        (r for r in records if _anchor(r) is TimestampAnchor.PROCESS_END),
        key=lambda r: r.timestamp,
    )
    best: list[EvidenceRecord] = []
    best_key: tuple[int, datetime, timedelta] | None = None
    first = 0
    for last, record in enumerate(starts):
        while record.timestamp - starts[first].timestamp > window:
            first += 1
        run = starts[first : last + 1]
        next_start = next(
            (r.timestamp for r in starts[last + 1 :] if r.timestamp > record.timestamp), None
        )
        group = _one_per_source(run)
        for end_record in ends:
            if end_record.artifact_type in group:
                continue
            if end_record.timestamp >= record.timestamp and (
                next_start is None or end_record.timestamp < next_start
            ):
                group[end_record.artifact_type] = end_record
        key = (len(group), record.timestamp, -(record.timestamp - run[0].timestamp))
        if best_key is None or key > best_key:
            best_key, best = key, list(group.values())
    return best


def _one_per_source(run: list[EvidenceRecord]) -> dict[ArtifactType, EvidenceRecord]:
    """Keep, per source, the record in ``run`` closest to the run's midpoint."""
    midpoint = _midpoint(run)
    chosen: dict[ArtifactType, EvidenceRecord] = {}
    for record in run:
        current = chosen.get(record.artifact_type)
        if current is None or _distance(record, midpoint) < _distance(current, midpoint):
            chosen[record.artifact_type] = record
    return chosen


def _midpoint(records: list[EvidenceRecord]) -> datetime | None:
    times = [r.timestamp for r in records if r.timestamp is not None]
    if not times:
        return None
    earliest, latest = min(times), max(times)
    return earliest + (latest - earliest) / 2


def _distance(record: EvidenceRecord, moment: datetime) -> timedelta:
    return abs(record.timestamp - moment)


def _ordered(sources: set[ArtifactType]) -> list[ArtifactType]:
    known = [s for s in _SOURCE_ORDER if s in sources]
    others = [s for s in ArtifactType if s in sources and s not in _SOURCE_ORDER]
    return known + others


def _observe(
    source: ArtifactType,
    evidence: tuple[EvidenceRecord, ...],
    matched: EvidenceRecord | None,
    group_midpoint: datetime | None,
) -> SourceObservation:
    if matched is not None:
        return SourceObservation(source, evidence, matched, in_window=True)
    timed = [r for r in evidence if _is_timed(r)]
    if timed and group_midpoint is not None:
        representative = min(timed, key=lambda r: _distance(r, group_midpoint))
    elif timed:
        representative = max(timed, key=lambda r: r.timestamp)
    else:
        representative = evidence[0] if evidence else None
    return SourceObservation(source, evidence, representative, in_window=False)


def _classify(agreeing: int, examined: int) -> CorroborationStatus:
    if examined < 2 or agreeing < 2:
        return CorroborationStatus.NEEDS_REVIEW
    if agreeing == examined:
        return CorroborationStatus.CORROBORATED
    return CorroborationStatus.PARTIALLY_CORROBORATED


def _join(labels: list[str]) -> str:
    if len(labels) <= 2:
        return " and ".join(labels)
    return ", ".join(labels[:-1]) + f", and {labels[-1]}"


def _absence_sentence(source: SourceObservation) -> str:
    if not source.observed:
        return f"No corresponding {source.label} evidence was identified."
    record = source.representative
    if record is not None and _anchor(record) is TimestampAnchor.PROCESS_END:
        return (
            f"{source.label} evidence was identified, but the exit time it records does "
            "not follow the other sources' most recent start. This is expected if the "
            "program was still running when the evidence was collected."
        )
    if record is not None and _is_timed(record):
        return (
            f"{source.label} evidence was identified, but not within the "
            "configured correlation window of the other sources."
        )
    return f"{source.label} evidence was identified but has no usable timestamp."


def _explain(
    status: CorroborationStatus, subject: str, sources: tuple[SourceObservation, ...]
) -> tuple[str, ...]:
    agreeing = [s.label for s in sources if s.in_window]
    others = [s for s in sources if not s.in_window]

    exit_labels = [
        s.label
        for s in sources
        if s.in_window
        and s.representative is not None
        and _anchor(s.representative) is TimestampAnchor.PROCESS_END
    ]
    exit_note = (
        (
            f"{_join(exit_labels)} records the program's exit after these start times, "
            "consistent with the same run.",
        )
        if exit_labels
        else ()
    )

    if status is CorroborationStatus.CORROBORATED:
        return (
            f"{len(agreeing)} independent artifact sources contain evidence consistent "
            f"with {subject} execution within the configured correlation window.",
            *exit_note,
            "Examiner review is recommended.",
        )
    if status is CorroborationStatus.PARTIALLY_CORROBORATED:
        return (
            f"{_join(agreeing)} contain consistent evidence.",
            *exit_note,
            *(_absence_sentence(s) for s in others),
            _NOT_ANTI_FORENSIC,
        )

    observed = [s for s in sources if s.observed]
    if len(sources) < 2:
        lead = (
            f"Only {sources[0].label} was examined. Corroboration requires at least "
            "two independent artifact sources."
        )
    elif len(observed) == 1:
        lead = (
            f"Only {observed[0].label} contains evidence of {subject} execution. "
            "No other examined source corroborates it."
        )
    else:
        lead = (
            f"Evidence of {subject} execution exists in {_join([s.label for s in observed])}, "
            "but no two sources are consistent with the same run within the "
            "configured correlation window."
        )
    missing = [s for s in sources if not s.observed]
    return (
        lead,
        *(_absence_sentence(s) for s in missing),
        _NOT_ANTI_FORENSIC,
    )
