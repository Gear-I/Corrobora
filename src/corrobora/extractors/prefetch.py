"""Prefetch evidence extractor.

Turns a parsed :class:`~corrobora.parsers.prefetch.PrefetchRecord` into
:class:`~corrobora.models.evidence.EvidenceRecord` objects describing
program execution.

A Prefetch file records up to eight most-recent run times (one on older
format versions). Each run time is a separate claim that the executable
ran at that moment, so each becomes its own ``EvidenceRecord``: a
correlation rule can then look for corroboration of every recorded run,
not only the most recent one.

A Prefetch file whose run times could not be read is still evidence
that the executable ran at some point. That case produces a single
record with ``timestamp=None``, which correlation logic can count as
presence without placing it in time.
"""

from __future__ import annotations

from datetime import datetime

from corrobora.models.evidence import (
    EvidenceRecord,
    EvidenceType,
    TimestampSemantics,
    normalize_executable_name,
)
from corrobora.parsers.Base import ArtifactType
from corrobora.parsers.prefetch import PrefetchRecord

# Prefetch stores the executable name in a fixed 60-byte UTF-16 field
# including a terminating null, so names are cut off at 29 characters.
# A name of exactly this length may therefore be a truncated prefix of
# the real filename.
PREFETCH_MAX_EXECUTABLE_NAME_LENGTH = 29


def extract_prefetch_evidence(record: PrefetchRecord) -> list[EvidenceRecord]:
    """Extract program-execution evidence from one Prefetch record.

    Args:
        record: A record produced by
            :meth:`~corrobora.parsers.prefetch.PrefetchParser.parse`.

    Returns:
        One :class:`EvidenceRecord` per recorded run time, most recent
        first (``record_ref`` ``"run[0]"``, ``"run[1]"``, ...). If the
        record has no readable run times, a single record with
        ``timestamp=None`` and ``record_ref`` ``"run[unknown]"``. An
        empty list if the record has no usable executable name, since
        evidence without a subject cannot be correlated.
    """
    if not record.executable_name:
        return []
    subject = normalize_executable_name(record.executable_name)
    if not subject:
        return []

    base_metadata = {
        "run_count": record.run_count,
        "run_times_recorded": len(record.last_run_times),
        "prefetch_hash": record.prefetch_hash,
        "filename_hash_matches": record.filename_hash_matches,
        "format_version": record.format_version,
        "subject_possibly_truncated": (
            len(record.executable_name) >= PREFETCH_MAX_EXECUTABLE_NAME_LENGTH
        ),
        "executable_path": _find_executable_path(record, subject),
        "volumes": tuple(
            {"device_path": v.device_path, "serial_number": v.serial_number}
            for v in record.volumes
        ),
    }

    def _make(timestamp: datetime | None, record_ref: str, run_index: int | None) -> EvidenceRecord:
        return EvidenceRecord(
            artifact_type=ArtifactType.PREFETCH,
            evidence_type=EvidenceType.PROGRAM_EXECUTION,
            subject=subject,
            subject_raw=record.executable_name,
            timestamp=timestamp,
            timestamp_semantics=TimestampSemantics.PREFETCH_LAST_RUN,
            source_path=record.source_path,
            record_ref=record_ref,
            metadata={**base_metadata, "run_index": run_index},
        )

    if not record.last_run_times:
        return [_make(None, "run[unknown]", None)]
    return [
        _make(run_time, f"run[{index}]", index)
        for index, run_time in enumerate(record.last_run_times)
    ]


def _find_executable_path(record: PrefetchRecord, subject: str) -> str | None:
    """Find the executable's own full path among the referenced filenames.

    Prefetch's executable name has no directory, but the executable
    itself normally appears in the file's referenced-filenames list with
    its full device path. When the name may be truncated, a referenced
    file whose name starts with the truncated subject is accepted.

    Args:
        record: The Prefetch record being extracted.
        subject: The normalized executable name.

    Returns:
        The first matching referenced path as recorded, or ``None`` if
        no referenced filename matches.
    """
    truncated = len(subject) >= PREFETCH_MAX_EXECUTABLE_NAME_LENGTH
    for path in record.referenced_filenames:
        name = normalize_executable_name(path)
        if name == subject or (truncated and name.startswith(subject)):
            return path
    return None
