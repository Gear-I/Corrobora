"""Plain-text rendering of program-execution corroboration findings.

The output is intentionally plain: what each source showed, the result,
and a short explanation. It states the configured correlation window
and never labels a discrepancy as anti-forensic activity.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from corrobora.correlation.program_execution import (
    SOURCE_LABELS,
    CorroborationStatus,
    ProgramExecutionFinding,
    SourceObservation,
)
from corrobora.models.evidence import EvidenceRecord, EvidenceType, TimestampAnchor
from corrobora.parsers.Base import ArtifactType

_RULE = "-" * 48

STATUS_LABELS = {
    CorroborationStatus.CORROBORATED: "CORROBORATED",
    CorroborationStatus.PARTIALLY_CORROBORATED: "PARTIALLY CORROBORATED",
    CorroborationStatus.NEEDS_REVIEW: "NEEDS REVIEW",
}


def render_program_execution_report(finding: ProgramExecutionFinding) -> str:
    """Render one finding as a plain-text report.

    Args:
        finding: The finding to render.

    Returns:
        The report text, ending with a newline.
    """
    lines = [
        "CORROBORA",
        "Cross-Artifact Analysis",
        "",
        "Finding: Program Execution",
        f"Subject: {finding.subject}",
        f"Correlation window: {_format_window(finding.window)} "
        "(configured; not a validated forensic threshold)",
        "",
        "Evidence",
        _RULE,
    ]
    for source in finding.sources:
        lines.append("")
        lines.extend(_source_lines(source, finding.status))
    lines += ["", _RULE, "", f"Result: {STATUS_LABELS[finding.status]}", ""]
    for sentence in finding.explanation:
        lines.append(sentence)
    return "\n".join(lines) + "\n"


def _source_lines(source: SourceObservation, status: CorroborationStatus) -> list[str]:
    lines = [source.label, f"Observed: {'Yes' if source.observed else 'No'}"]
    record = source.representative
    if record is None:
        return lines

    if record.timestamp is None:
        lines.append("Timestamp: none recorded")
    else:
        stamp = record.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        is_exit = record.timestamp_semantics.anchor is TimestampAnchor.PROCESS_END
        if is_exit:
            stamp += " (process exit)"
        if not source.in_window and status is not CorroborationStatus.NEEDS_REVIEW:
            stamp += (
                " (does not follow the agreeing start times)"
                if is_exit
                else " (outside correlation window)"
            )
        lines.append(f"Timestamp: {stamp}")
    lines.extend(_detail_lines(record))
    if record.artifact_type is ArtifactType.REGISTRY:
        # record_ref is the full key path plus value name, too long to
        # read inline; the key is summarized in the Location line above.
        lines.append(f"Source: {record.source_path}")
        lines.append(f"Value: {record.subject_raw}")
    else:
        lines.append(f"Source: {record.source_path} ({record.record_ref})")
    if len(source.evidence) > 1:
        lines.append(f"Records for this subject: {len(source.evidence)}")
    return lines


def _detail_lines(record: EvidenceRecord) -> list[str]:
    metadata = record.metadata
    if record.artifact_type is ArtifactType.EVTX and metadata.get("event_id") is not None:
        return [f"Event ID: {metadata['event_id']}"]
    if record.artifact_type is ArtifactType.PREFETCH and metadata.get("run_count") is not None:
        return [f"Run count: {metadata['run_count']}"]
    if record.artifact_type is ArtifactType.REGISTRY and metadata.get("moderator"):
        return [f"Location: {str(metadata['moderator']).upper()} ({metadata.get('user_sid')})"]
    return []


def _format_window(window: timedelta) -> str:
    seconds = window.total_seconds()
    if seconds == int(seconds):
        seconds = int(seconds)
    return f"{seconds} second{'s' if seconds != 1 else ''}"


_ANCHOR_LABELS = {
    TimestampAnchor.PROCESS_START: "start",
    TimestampAnchor.PROCESS_END: "exit",
    TimestampAnchor.NOT_EXECUTION_TIME: "-",
}


def render_evidence_list(
    records: Iterable[EvidenceRecord], finding: ProgramExecutionFinding
) -> str:
    """List every execution record for a finding's subject, for examiner review.

    The report shows one record per source; this shows all of them, in
    time order with millisecond precision, so each recorded run can be
    checked individually. Records that make up the agreeing group in the
    report are marked with ``*``. Untimed records are listed last.

    Args:
        records: Evidence from any number of subjects; only
            ``PROGRAM_EXECUTION`` records for ``finding.subject`` are listed.
        finding: The finding the list accompanies.

    Returns:
        The listing, ending with a newline.
    """
    relevant = [
        r
        for r in records
        if r.evidence_type is EvidenceType.PROGRAM_EXECUTION and r.subject == finding.subject
    ]
    agreeing = {
        id(s.representative)
        for s in finding.sources
        if s.in_window and s.representative is not None
    }
    earliest = datetime.min.replace(tzinfo=UTC)
    relevant.sort(key=lambda r: (r.timestamp is None, r.timestamp or earliest))

    counts: dict[str, int] = {}
    for record in relevant:
        label = SOURCE_LABELS.get(record.artifact_type, record.artifact_type.value)
        counts[label] = counts.get(label, 0) + 1
    summary = ", ".join(f"{count} {label}" for label, count in counts.items())

    rows = [("", "Time (UTC)", "Source", "Marks", "Record", "Detail")]
    for record in relevant:
        rows.append(
            (
                "*" if id(record) in agreeing else "",
                _format_time_ms(record),
                SOURCE_LABELS.get(record.artifact_type, record.artifact_type.value),
                (
                    _ANCHOR_LABELS[record.timestamp_semantics.anchor]
                    if record.timestamp is not None
                    else "-"
                ),
                _short_ref(record),
                _list_detail(record),
            )
        )
    widths = [max(len(row[col]) for row in rows) for col in range(len(rows[0]) - 1)]
    lines = [
        f"All execution evidence for {finding.subject} ({summary or 'none'})",
        _RULE,
    ]
    for row in rows:
        cells = [cell.ljust(width) for cell, width in zip(row[:-1], widths)]
        lines.append(("  ".join(cells) + "  " + row[-1]).rstrip())
    lines += [
        _RULE,
        "* = part of the agreeing group in the report above. "
        "Marks: start = process start, exit = process exit.",
    ]
    return "\n".join(lines) + "\n"


def _format_time_ms(record: EvidenceRecord) -> str:
    if record.timestamp is None:
        return "no timestamp"
    stamp = record.timestamp
    return f"{stamp:%Y-%m-%d %H:%M:%S}.{stamp.microsecond // 1000:03d}"


def _short_ref(record: EvidenceRecord) -> str:
    if record.artifact_type is ArtifactType.REGISTRY:
        # The full key path is too long for a table; moderator and
        # control set identify the entry within the hive.
        moderator = str(record.metadata.get("moderator", "")).upper()
        return f"{moderator} {record.metadata.get('control_set') or ''}".strip()
    return record.record_ref


def _list_detail(record: EvidenceRecord) -> str:
    name = Path(record.source_path).name
    metadata = record.metadata
    if record.artifact_type is ArtifactType.EVTX and metadata.get("event_id") is not None:
        return f"{name}, Event ID {metadata['event_id']}"
    if record.artifact_type is ArtifactType.PREFETCH and metadata.get("run_count") is not None:
        return f"{name}, run count {metadata['run_count']}"
    return name
