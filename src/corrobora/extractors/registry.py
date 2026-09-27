"""Registry evidence extractor: Background Activity Moderator (BAM/DAM).

Turns :class:`~corrobora.parsers.registry.RegistryValue` objects from a
SYSTEM hive's BAM (and DAM) keys into
:class:`~corrobora.models.evidence.EvidenceRecord` objects describing
program execution.

Where BAM lives, per user SID, under each control set:

- ``ControlSetNNN\\Services\\bam\\State\\UserSettings\\<SID>`` (Windows 10
  1809 and later)
- ``ControlSetNNN\\Services\\bam\\UserSettings\\<SID>`` (Windows 10
  1709 / 1803)

DAM (Desktop Activity Moderator) uses the same layout under
``Services\\dam``.

Each value under a SID key is named with the executable's full device
path (e.g. ``\\Device\\HarddiskVolume3\\Windows\\System32\\...\\powershell.exe``)
and holds binary data whose first 8 bytes are a little-endian FILETIME.
The generic registry parser keeps those bytes in ``raw_data_bytes``; this
extractor decodes them. What that FILETIME records is described (and its
open questions listed) on
:attr:`~corrobora.models.evidence.TimestampSemantics.REGISTRY_BAM_LAST_EXECUTION`.

Values that are not executable entries are skipped: the bookkeeping
values ``Version`` and ``SequenceNumber`` (DWORDs), and packaged-app
entries whose names are package family names rather than paths.

Each control set is extracted independently, so a hive with both
``ControlSet001`` and ``ControlSet002`` can yield two records for the
same executable; ``metadata["control_set"]`` tells them apart.
Deduplication is left to correlation logic.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from corrobora.models.evidence import (
    EvidenceRecord,
    EvidenceType,
    TimestampSemantics,
    normalize_executable_name,
)
from corrobora.parsers.Base import ArtifactType
from corrobora.parsers.registry import RegistryValue

_REG_BINARY = 3
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_FILETIME_SIZE = 8
_MODERATORS = ("bam", "dam")


def extract_registry_evidence(value: RegistryValue, source_path: str) -> list[EvidenceRecord]:
    """Extract program-execution evidence from one BAM/DAM registry value.

    Args:
        value: A value produced by
            :meth:`~corrobora.parsers.registry.RegistryHiveParser.parse`.
        source_path: The hive file the value was parsed from.
            ``RegistryValue`` does not carry its own source path.

    Returns:
        A single-element list for a BAM/DAM executable entry; otherwise
        an empty list (a value outside a BAM/DAM user key, a non-binary
        or too-short value, or a value name that is not a path). A
        FILETIME of zero yields a record with ``timestamp=None``.
    """
    location = _parse_bam_location(value.key_path)
    if location is None:
        return []
    if value.value_type != _REG_BINARY or len(value.raw_data_bytes) < _FILETIME_SIZE:
        return []
    if "\\" not in value.name:
        return []
    subject = normalize_executable_name(value.name)
    if not subject:
        return []

    moderator, control_set, sid = location
    return [
        EvidenceRecord(
            artifact_type=ArtifactType.REGISTRY,
            evidence_type=EvidenceType.PROGRAM_EXECUTION,
            subject=subject,
            subject_raw=value.name,
            timestamp=_filetime_to_datetime(value.raw_data_bytes[:_FILETIME_SIZE]),
            timestamp_semantics=TimestampSemantics.REGISTRY_BAM_LAST_EXECUTION,
            source_path=source_path,
            record_ref=f"{value.key_path}\\{value.name}",
            metadata={
                "moderator": moderator,
                "control_set": control_set,
                "user_sid": sid,
                "key_path": value.key_path,
                "raw_data": value.raw_data,
            },
        )
    ]


def _parse_bam_location(key_path: str) -> tuple[str, str | None, str] | None:
    """Recognize a BAM/DAM per-user key path.

    Matching is by path segment, case-insensitively, so the hive's root
    key name (which varies between hives and tools) does not matter.

    Args:
        key_path: A registry key path as produced by the registry parser.

    Returns:
        ``(moderator, control_set, sid)`` where ``moderator`` is
        ``"bam"`` or ``"dam"`` and ``control_set`` is the ``ControlSetNNN``
        segment (``None`` if the path has none), or ``None`` if the key is
        not a BAM/DAM per-user key.
    """
    segments = key_path.split("\\")
    lowered = [segment.lower() for segment in segments]
    for index, segment in enumerate(lowered[:-1]):
        if segment != "services" or lowered[index + 1] not in _MODERATORS:
            continue
        rest = lowered[index + 2 :]
        if rest[:1] == ["state"]:
            rest = rest[1:]
        # Exactly "UserSettings\<SID>" must remain: values directly under
        # the SID key, not under UserSettings itself or deeper.
        if len(rest) != 2 or rest[0] != "usersettings":
            return None
        control_set = segments[index - 1] if index > 0 else None
        if control_set is not None and not control_set.lower().startswith("controlset"):
            control_set = None
        return lowered[index + 1], control_set, segments[-1]
    return None


def _filetime_to_datetime(raw: bytes) -> datetime | None:
    """Convert an 8-byte little-endian FILETIME to a UTC datetime.

    Args:
        raw: Exactly 8 bytes.

    Returns:
        The timezone-aware UTC time, or ``None`` for a zero FILETIME
        (no time recorded) or one beyond the range ``datetime`` can
        represent (corrupt data).
    """
    ticks = int.from_bytes(raw, "little")
    if ticks == 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    except OverflowError:
        return None
