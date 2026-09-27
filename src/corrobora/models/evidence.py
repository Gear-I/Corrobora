"""Corrobora's normalized evidence model.

An :class:`EvidenceRecord` is a single, interpreted claim that one
artifact makes about one subject: "Prefetch says ``powershell.exe`` ran
at 14:31:42 UTC", or "Security.evtx says a ``powershell.exe`` process
was created at 14:31:47 UTC". Correlation logic compares
``EvidenceRecord`` objects only; it never needs to know the Prefetch
binary format, EVTX XML, or registry hive structure.

Relationship to :class:`~corrobora.parsers.Base.ArtifactRecord`:
    ``ArtifactRecord`` (produced by each parser's ``parse_common()``) is
    a *raw* normalized view: one record per parsed item, with no claim
    about what the item means. A registry hive's ``parse_common()``
    returns every key and value in the hive, almost none of which are
    execution evidence. ``EvidenceRecord`` is the *interpreted* layer on
    top: it is produced by artifact-aware extractors that decide which
    native records constitute evidence of something, and what that
    something is. Parsers stay generic; interpretation lives in the
    extractors.

Timestamp semantics:
    Two timestamps from different artifacts are only comparable once
    you know what each one records. Every ``EvidenceRecord`` therefore
    carries a :class:`TimestampSemantics` value alongside its
    timestamp. The descriptions on that enum state what each timestamp
    is understood to mean, what has been measured, and what still needs
    verifying. Each value also has a :class:`TimestampAnchor` stating
    whether it marks a process's start or its end, which correlation
    logic uses to decide how the timestamp may be compared. Nothing here
    asserts a correct correlation window.

Measurements:
    Values marked "Measured" come from a controlled test on one machine
    (Windows 11 Home, build 26200): ``powershell.exe`` launched three
    times, each run kept open for 60 seconds, with process start and exit
    times recorded independently and compared to the collected Prefetch
    file, Security log (4688), and SYSTEM hive (BAM). One machine and one
    build is a starting point, not a general result.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from corrobora.parsers.Base import ArtifactType

# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------


class EvidenceType(str, Enum):
    """What an evidence record claims happened.

    Kept deliberately small: a member is added only when an extractor
    actually produces it.
    """

    PROGRAM_EXECUTION = "program_execution"
    """The subject executable was run (e.g. a Prefetch run time, a
    4688/Sysmon 1 process creation, a BAM entry)."""

    SCRIPT_EXECUTION = "script_execution"
    """A script was executed by a scripting engine (e.g. a PowerShell
    4104 script block). Does not by itself identify the host process:
    the PowerShell engine logs 4104 whether it runs in powershell.exe,
    pwsh.exe, the ISE, or an embedding application."""


class TimestampAnchor(str, Enum):
    """Which point in a process's life a timestamp marks."""

    PROCESS_START = "process_start"
    """At or near process creation. Start-anchored timestamps from
    different sources can be compared directly within a window."""

    PROCESS_END = "process_end"
    """At or near process exit. Its distance from the start is however
    long the process ran, which is unbounded, so it cannot be compared
    to start times with a fixed window."""

    NOT_EXECUTION_TIME = "not_execution_time"
    """Not a point in a process's life (or not established). Not used in
    time comparisons."""


class TimestampSemantics(str, Enum):
    """What an evidence record's timestamp actually records.

    Each member's description separates what the timestamp is understood
    or measured to represent from open questions. :attr:`anchor` gives
    the corresponding :class:`TimestampAnchor`.
    """

    PREFETCH_LAST_RUN = "prefetch_last_run"
    """One of up to eight run times stored in a Prefetch file (one on
    pre-Windows 8 formats). Runs older than the eighth-most-recent have
    no Prefetch timestamp at all. Measured: within one second of process
    start on two of two runs checked. This does not support the offset of
    roughly ten seconds that is commonly reported. TO VERIFY: other
    Windows builds, and sub-second precision."""

    EVTX_TIME_CREATED = "evtx_time_created"
    """The ``TimeCreated`` of an event log record: when the event was
    written, to sub-second precision. The only EVTX evidence currently
    extracted is process creation (Security 4688, Sysmon 1), whose
    ``TimeCreated`` is anchored to process start. Measured (4688): within
    one second of process start on two of two runs checked. For other
    events it means something else (e.g. 4104 is when a script block ran,
    possibly long after the host process started); a new extractor for
    such events should add its own semantics value rather than reuse this
    one. TO VERIFY: Sysmon 1, and other Windows builds."""

    REGISTRY_BAM_LAST_EXECUTION = "registry_bam_last_execution"
    """The FILETIME stored in a Background Activity Moderator value's
    data: one per user and executable, overwritten on each run, so only
    the most recent run is represented. Measured: matched process *exit*
    within one second, 61 seconds after process start, for a run kept
    open for 60 seconds. It is therefore anchored to process end: its
    offset from start-anchored evidence is however long the program ran.
    TO VERIFY: other Windows builds, and whether BAM is written while a
    process is still running."""

    REGISTRY_KEY_LAST_WRITE = "registry_key_last_write"
    """A registry key's LastWrite time: when *any* value under that
    key, or the key itself, last changed. It does not identify which
    value changed and is not an execution time. Useful for
    persistence (when a Run entry was written), not for execution."""

    UNKNOWN = "unknown"
    """The timestamp's meaning has not been established. Records with
    this semantics should not participate in time-window comparisons."""

    @property
    def anchor(self) -> TimestampAnchor:
        """Which point in a process's life this timestamp marks."""
        return _ANCHORS[self]


_ANCHORS: dict[TimestampSemantics, TimestampAnchor] = {
    TimestampSemantics.PREFETCH_LAST_RUN: TimestampAnchor.PROCESS_START,
    TimestampSemantics.EVTX_TIME_CREATED: TimestampAnchor.PROCESS_START,
    TimestampSemantics.REGISTRY_BAM_LAST_EXECUTION: TimestampAnchor.PROCESS_END,
    TimestampSemantics.REGISTRY_KEY_LAST_WRITE: TimestampAnchor.NOT_EXECUTION_TIME,
    TimestampSemantics.UNKNOWN: TimestampAnchor.NOT_EXECUTION_TIME,
}


# --------------------------------------------------------------------------
# Evidence record
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvidenceRecord:  # pylint: disable=too-many-instance-attributes
    """A single interpreted piece of evidence from one artifact source.

    Note:
        Each field answers one of the questions every piece of evidence
        must answer (what, who/what, when, where, what else), plus the
        traceability link back to the source record; the field count
        reflects that, so ``too-many-instance-attributes`` is
        intentionally suppressed.

    Attributes:
        artifact_type: Which artifact source this evidence came from.
        evidence_type: What this evidence claims happened.
        subject: The normalized subject this evidence concerns, used for
            matching across artifacts (for executables, the lowercased
            filename with no directory, via
            :func:`normalize_executable_name`).
        subject_raw: The subject exactly as the source artifact recorded
            it (e.g. Prefetch's uppercase, possibly truncated
            ``POWERSHELL.EXE``, or EVTX's full image path). Retained so
            the examiner can see what the artifact actually said.
        timestamp: The timezone-aware UTC time this evidence refers to,
            or ``None`` if the source provides no applicable time.
        timestamp_semantics: What ``timestamp`` records. Required even
            when ``timestamp`` is ``None`` so the reason for its
            absence is explicit.
        source_path: The artifact file this evidence was extracted from.
        record_ref: A stable identifier for the specific native record
            within ``source_path`` (e.g. an EVTX record number, a
            Prefetch run index, a registry value path), so any finding
            can be traced to the exact item that produced it.
        metadata: Artifact-specific details worth preserving (e.g.
            ``run_count``, ``event_id``, ``channel``). Not used for
            matching; carried through for reporting and examiner review.
    """

    artifact_type: ArtifactType
    evidence_type: EvidenceType
    subject: str
    subject_raw: str
    timestamp: datetime | None
    timestamp_semantics: TimestampSemantics
    source_path: str
    record_ref: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate invariants that correlation logic relies on.

        Raises:
            ValueError: If ``subject`` is empty, or ``timestamp`` is a
                naive ``datetime`` (comparing naive and aware times
                across artifacts would silently mix time zones).
        """
        if not self.subject:
            raise ValueError("EvidenceRecord.subject must not be empty")
        if self.timestamp is not None and self.timestamp.utcoffset() is None:
            raise ValueError("EvidenceRecord.timestamp must be timezone-aware (UTC)")


# --------------------------------------------------------------------------
# Subject normalization
# --------------------------------------------------------------------------


def normalize_executable_name(raw: str) -> str:
    """Normalize an executable reference to a comparable subject string.

    Strips any directory component (either separator), surrounding
    whitespace and quotes, and lowercases the result, so that
    ``"POWERSHELL.EXE"``,
    ``"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"``
    and ``"\\DEVICE\\HARDDISKVOLUME3\\...\\POWERSHELL.EXE"`` all become
    ``"powershell.exe"``.

    Note:
        Prefetch truncates long executable names (to 29 characters on
        the formats Corrobora parses). This function cannot restore a
        truncated name, so a truncated Prefetch subject will not equal
        the full name from another artifact. Handling that is a matching
        concern for correlation logic, not a normalization concern.

    Args:
        raw: The executable name or path as recorded by an artifact.

    Returns:
        The lowercased bare filename, or an empty string if ``raw``
        contains no filename.
    """
    cleaned = raw.strip().strip('"').strip()
    basename = cleaned.replace("/", "\\").rsplit("\\", 1)[-1]
    return basename.lower()
