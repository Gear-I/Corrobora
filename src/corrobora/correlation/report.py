"""Plain-text rendering of program-execution corroboration findings.

The output is intentionally plain: what each source showed, the result,
and a short explanation. It states the configured correlation window
and never labels a discrepancy as anti-forensic activity.
"""

from __future__ import annotations

from datetime import timedelta

from corrobora.correlation.program_execution import (
    CorroborationStatus,
    ProgramExecutionFinding,
    SourceObservation,
)
from corrobora.models.evidence import EvidenceRecord, TimestampAnchor
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
