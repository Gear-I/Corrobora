"""Corrobora MFT Parser — single-file module.

Parses a raw NTFS Master File Table (``$MFT``) file into structured,
immutable ``MftRecord`` objects, with built-in detection of
**timestomping** — one of the most direct anti-forensic techniques
that exists on Windows.

Background:
    NTFS stores two independent sets of timestamps for every file:

    - ``$STANDARD_INFORMATION`` (SI) — the timestamps Windows Explorer,
      PowerShell, and most tools display. Trivially rewritten by
      common "timestomping" utilities to make a malicious file look
      old/benign.
    - ``$FILE_NAME`` (FN) — timestamps stored in the directory index
      entry. Ordinary user-mode tools do not update or forge these;
      doing so requires direct manipulation of NTFS metadata
      structures, which is far less common and far more detectable.

    Under normal, non-tampered use, a file's SI timestamps are set
    equal to its FN timestamps at creation and only move *forward*
    from there (as the file is modified/accessed). An SI timestamp
    that is *earlier* than the file's FN creation time is not
    achievable through normal filesystem activity — it is a strong,
    well-established indicator that SI was deliberately backdated.
    This module flags exactly that condition.

This module has no third-party dependencies: the MFT record binary
format is parsed directly from the raw ``$MFT`` file using the
standard library only, including verification and application of
NTFS's per-sector "fixup" (update sequence array) mechanism, which
also lets it flag structurally corrupted records — themselves a
possible sign of tampering.

This module is self-contained: exceptions, data models, extraction
logic, and file-level orchestration all live here so the parser can
be dropped into a project as a single file.

Example:
    >>> from mft import MftParser
    >>> parser = MftParser("C_MFT")
    >>> records = parser.parse()
    >>> for record in records:
    ...     if record.likely_timestomped:
    ...         print(record.record_number, record.filename, record.timestamp_anomalies)

Command-line usage:
    python mft.py <path-to-$MFT-file> [--record-size 1024]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_RECORD_SIGNATURE = b"FILE"
_CORRUPT_SIGNATURE = b"BAAD"
_DEFAULT_RECORD_SIZE = 1024
_SECTOR_SIZE = 512

_ATTR_TYPE_STANDARD_INFORMATION = 0x10
_ATTR_TYPE_FILE_NAME = 0x30
_ATTR_TYPE_END_MARKER = 0xFFFFFFFF

# $FILE_NAME "namespace" byte: 0=POSIX, 1=Win32, 2=DOS (8.3), 3=Win32 & DOS.
# Preference order for selecting a display name when multiple $FILE_NAME
# attributes exist (hard links / long+short name pairs).
_FILENAME_NAMESPACE_PREFERENCE = (1, 3, 0, 2)

_WINDOWS_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Tolerance for SI-vs-FN timestamp comparison, to absorb filesystem
# timestamp rounding/precision differences rather than flagging noise.
_ANOMALY_TOLERANCE = timedelta(seconds=1)


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class MftParsingError(Exception):
    """Base exception for all errors raised by the MFT parsing subsystem.

    All other exceptions in this module inherit from this class, so
    calling code that wants to catch any MFT-related failure can
    catch ``MftParsingError`` alone.
    """


class MftFileError(MftParsingError):
    """Raised for file-level failures that prevent parsing from starting.

    Examples include a missing file, an unreadable file, or a file
    that is not a plausible size for the configured record size.
    """


class RecordExtractionError(MftParsingError):
    """Raised when a single 1024-byte (or configured size) MFT record fails.

    Scoped to a single record so that :class:`MftParser` can catch
    it, log it, and continue processing the remaining records rather
    than aborting the entire ``$MFT`` file. Causes include a
    ``BAAD`` signature (NTFS's own corruption marker), an unexpected
    signature, or a fixup (update sequence array) verification
    failure — the latter meaning the record's on-disk content does
    not match what NTFS itself expects, which is itself a corruption
    or tampering indicator worth surfacing rather than silently
    guessing at the "real" bytes.
    """


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MftTimestamps:
    """One attribute's set of four NTFS timestamps.

    Attributes:
        creation_time: UTC file creation timestamp, or ``None`` if
            unavailable/zero.
        modification_time: UTC last-content-modification timestamp,
            or ``None`` if unavailable/zero.
        mft_modification_time: UTC last-metadata-modification
            timestamp (i.e. when this MFT record itself was last
            updated), or ``None`` if unavailable/zero.
        access_time: UTC last-access timestamp, or ``None`` if
            unavailable/zero.
    """

    creation_time: datetime | None
    modification_time: datetime | None
    mft_modification_time: datetime | None
    access_time: datetime | None


@dataclass(frozen=True, slots=True)
class MftRecord:  # pylint: disable=too-many-instance-attributes
    """A single parsed NTFS MFT file record.

    Note:
        Each field below is a distinct, independently meaningful
        forensic attribute of an MFT record; the field count reflects
        the NTFS schema itself, not incidental class complexity, so
        ``too-many-instance-attributes`` is intentionally suppressed
        for this dataclass.

    Attributes:
        record_number: This record's position (0-indexed) within the
            ``$MFT`` file, used as its stable identifier.
        embedded_record_number: The record number the record reports
            about itself, read from its own header (present in NTFS
            3.1+/Windows XP and later). Comparing this to
            ``record_number`` can reveal MFT slot manipulation; a
            mismatch is unusual and worth investigating, though this
            module does not itself flag it as an anomaly. ``None`` if
            unavailable.
        filename: The file's name, taken from its preferred
            ``$FILE_NAME`` attribute (Win32 namespace preferred over
            DOS 8.3), or ``None`` if no ``$FILE_NAME`` attribute was
            found.
        parent_record_number: The MFT record number of this file's
            parent directory, or ``None`` if unavailable.
        is_directory: Whether this record represents a directory.
        is_allocated: Whether this record is currently in use (i.e.
            not a deleted file). Deleted-but-still-readable records
            are valuable forensic evidence in their own right and are
            still parsed and returned, not filtered out.
        standard_information: This file's ``$STANDARD_INFORMATION``
            timestamps, or ``None`` if the attribute was missing.
        file_name_information: This file's ``$FILE_NAME`` timestamps
            (from the preferred name attribute), or ``None`` if no
            ``$FILE_NAME`` attribute was found.
        timestamp_anomalies: Names of the specific
            ``$STANDARD_INFORMATION`` timestamp fields found to
            predate the ``$FILE_NAME`` creation time by more than the
            comparison tolerance (e.g. ``("creation_time",)``). Empty
            if no anomaly was found or if either timestamp set is
            unavailable.
        likely_timestomped: ``True`` if ``timestamp_anomalies`` is
            non-empty. Provided as a convenience boolean for
            filtering/reporting.
    """

    record_number: int
    embedded_record_number: int | None
    filename: str | None
    parent_record_number: int | None
    is_directory: bool
    is_allocated: bool
    standard_information: MftTimestamps | None
    file_name_information: MftTimestamps | None
    timestamp_anomalies: tuple[str, ...]
    likely_timestomped: bool


@dataclass(frozen=True, slots=True)
class ParseFailure:
    """Details about a single MFT record that failed extraction.

    Retaining failure details supports anti-forensic detection: a
    cluster of ``BAAD``/corrupt records at a particular offset range
    can indicate deliberate MFT corruption or slack-space wiping,
    distinct from the normal, sparse "never allocated" slots found
    throughout any ``$MFT`` file (which are not treated as failures
    at all — see :class:`MftRecordExtractor`).

    Attributes:
        record_number: The 0-indexed position of the record that
            failed to parse.
        reason: A human-readable description of why extraction failed.
    """

    record_number: int
    reason: str


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------


class MftRecordExtractor:  # pylint: disable=too-few-public-methods
    """Extracts a :class:`MftRecord` from a single raw MFT record's bytes.

    Note:
        This class exposes a single public entry point (``extract``)
        backed by several private helper methods — a deliberate
        single-responsibility design, so
        ``too-few-public-methods`` is intentionally suppressed here.

    This class is stateless and has no dependency on file I/O, which
    makes it straightforward to unit test against hand-crafted raw
    record bytes instead of a real ``$MFT`` file.

    Example:
        >>> extractor = MftRecordExtractor()
        >>> record = extractor.extract(raw_1024_bytes, record_index=5)
    """

    def extract(  # pylint: disable=too-many-locals
        self, raw_record: bytes, record_index: int
    ) -> MftRecord:
        """Convert one raw MFT record's bytes into an :class:`MftRecord`.

        Note:
            Local variable count is intentionally suppressed here:
            each local directly corresponds to one field of the
            resulting immutable, data-rich ``MftRecord``, so further
            splitting would fragment one coherent assembly step
            (already delegating to four private helpers) into
            artificial pieces.

        Args:
            raw_record: The raw, fixed-size bytes of a single MFT
                record (before fixup application).
            record_index: This record's 0-indexed position within the
                ``$MFT`` file.

        Returns:
            The populated :class:`MftRecord`.

        Raises:
            RecordExtractionError: If the record has the ``BAAD``
                corruption signature, an unrecognized signature, or
                fails NTFS fixup (update sequence array) verification.
        """
        signature = raw_record[0:4]
        if signature == _CORRUPT_SIGNATURE:
            raise RecordExtractionError(
                f"Record {record_index}: NTFS marked this record 'BAAD' (corrupt)"
            )
        if signature != _RECORD_SIGNATURE:
            raise RecordExtractionError(
                f"Record {record_index}: unrecognized signature {signature!r}"
            )

        fixed_record = self._apply_fixup(raw_record, record_index)

        flags = int.from_bytes(fixed_record[22:24], "little")
        is_allocated = bool(flags & 0x0001)
        is_directory = bool(flags & 0x0002)
        first_attribute_offset = int.from_bytes(fixed_record[20:22], "little")
        used_size = int.from_bytes(fixed_record[24:28], "little")
        embedded_record_number = self._read_embedded_record_number(fixed_record)

        standard_information, file_name_information, filename, parent_record_number = (
            self._parse_attributes(fixed_record, first_attribute_offset, used_size, record_index)
        )

        anomalies = self._detect_timestamp_anomalies(
            standard_information, file_name_information
        )

        return MftRecord(
            record_number=record_index,
            embedded_record_number=embedded_record_number,
            filename=filename,
            parent_record_number=parent_record_number,
            is_directory=is_directory,
            is_allocated=is_allocated,
            standard_information=standard_information,
            file_name_information=file_name_information,
            timestamp_anomalies=anomalies,
            likely_timestomped=bool(anomalies),
        )

    @staticmethod
    def _apply_fixup(raw_record: bytes, record_index: int) -> bytes:
        """Verify and apply NTFS's per-sector fixup (update sequence array).

        NTFS replaces the last 2 bytes of every 512-byte sector in a
        record with a copy of an "update sequence number" (USN) when
        writing to disk, storing the real original bytes in the
        Update Sequence Array (USA) near the start of the record.
        This lets NTFS detect a torn/incomplete disk write: if the
        trailing bytes don't match the expected USN, the sector
        wasn't fully written (or was tampered with). Attribute data
        must have the real bytes restored before parsing, since it
        can span a sector boundary.

        Args:
            raw_record: The raw, unfixed record bytes.
            record_index: This record's 0-indexed position, used in
                the raised error message.

        Returns:
            A new ``bytes`` object with the real sector-boundary bytes
            restored.

        Raises:
            RecordExtractionError: If a sector's trailing bytes don't
                match the expected USN (fixup verification failure),
                indicating corruption or an incompletely written
                record.
        """
        usa_offset = int.from_bytes(raw_record[4:6], "little")
        usa_count = int.from_bytes(raw_record[6:8], "little")
        usa = raw_record[usa_offset : usa_offset + usa_count * 2]

        if usa_count < 1 or len(usa) < usa_count * 2:
            raise RecordExtractionError(
                f"Record {record_index}: update sequence array is truncated"
            )

        fixed = bytearray(raw_record)
        expected_usn = usa[0:2]

        for sector_index in range(1, usa_count):
            sector_end = sector_index * _SECTOR_SIZE
            if sector_end > len(fixed):
                break
            actual_bytes = bytes(fixed[sector_end - 2 : sector_end])
            if actual_bytes != expected_usn:
                raise RecordExtractionError(
                    f"Record {record_index}: fixup verification failed at sector "
                    f"{sector_index} (expected {expected_usn!r}, found {actual_bytes!r})"
                )
            real_bytes = usa[sector_index * 2 : sector_index * 2 + 2]
            fixed[sector_end - 2 : sector_end] = real_bytes

        return bytes(fixed)

    @staticmethod
    def _read_embedded_record_number(fixed_record: bytes) -> int | None:
        """Read the record's self-reported MFT record number, if present.

        This field only exists in NTFS 3.1+ (Windows XP and later);
        older volumes' records don't have it.

        Args:
            fixed_record: The fixup-applied record bytes.

        Returns:
            The embedded record number, or ``None`` if the record is
            too short to contain this field.
        """
        if len(fixed_record) < 48:
            return None
        return int.from_bytes(fixed_record[44:48], "little")

    def _parse_attributes(  # pylint: disable=too-many-locals
        self,
        fixed_record: bytes,
        first_attribute_offset: int,
        used_size: int,
        record_index: int,
    ) -> tuple[MftTimestamps | None, MftTimestamps | None, str | None, int | None]:
        """Walk a record's attribute list and extract SI/FN information.

        Note:
            Local variable count is intentionally suppressed here:
            this method walks a binary attribute list and selects the
            best-namespace ``$FILE_NAME`` candidate, a single coherent
            algorithm whose intermediate values don't decompose
            further without adding indirection for its own sake.

        Args:
            fixed_record: The fixup-applied record bytes.
            first_attribute_offset: Byte offset of the first attribute,
                from the record header.
            used_size: The record's reported used size, used as an
                upper bound while walking attributes.
            record_index: This record's 0-indexed position, used in
                warning log messages.

        Returns:
            A tuple of ``(standard_information, file_name_information,
            filename, parent_record_number)``. Any element may be
            ``None`` if the corresponding attribute was absent or
            unreadable.
        """
        standard_information: MftTimestamps | None = None
        best_file_name_attr: tuple[int, MftTimestamps, str, int] | None = None

        offset = first_attribute_offset
        upper_bound = min(used_size, len(fixed_record))

        while offset + 4 <= upper_bound:
            attr_type = int.from_bytes(fixed_record[offset : offset + 4], "little")
            if attr_type in (_ATTR_TYPE_END_MARKER, 0):
                break
            if offset + 8 > len(fixed_record):
                break
            attr_length = int.from_bytes(fixed_record[offset + 4 : offset + 8], "little")
            if attr_length == 0 or offset + attr_length > len(fixed_record):
                logger.debug(
                    "Record %d: stopping attribute walk at offset %d "
                    "(invalid attribute length)",
                    record_index,
                    offset,
                )
                break

            if attr_type == _ATTR_TYPE_STANDARD_INFORMATION:
                standard_information = self._parse_standard_information(
                    fixed_record, offset, record_index
                )
            elif attr_type == _ATTR_TYPE_FILE_NAME:
                candidate = self._parse_file_name_attribute(fixed_record, offset, record_index)
                if candidate is not None:
                    namespace, timestamps, name, parent = candidate
                    should_replace = True
                    if best_file_name_attr is not None:
                        current_namespace = best_file_name_attr[0]
                        should_replace = self._is_preferred_namespace(
                            namespace, current_namespace
                        )
                    if should_replace:
                        best_file_name_attr = (namespace, timestamps, name, parent)

            offset += attr_length

        if best_file_name_attr is not None:
            _namespace, fn_timestamps, filename, parent = best_file_name_attr
            return standard_information, fn_timestamps, filename, parent
        return standard_information, None, None, None

    @staticmethod
    def _is_preferred_namespace(candidate_namespace: int, current_namespace: int) -> bool:
        """Check whether a candidate $FILE_NAME namespace outranks the current best.

        Args:
            candidate_namespace: The namespace byte of the candidate
                attribute.
            current_namespace: The namespace byte of the currently
                selected best attribute.

        Returns:
            ``True`` if the candidate should replace the current best.
        """
        preference = _FILENAME_NAMESPACE_PREFERENCE
        candidate_rank = preference.index(candidate_namespace) if (
            candidate_namespace in preference
        ) else len(preference)
        current_rank = preference.index(current_namespace) if (
            current_namespace in preference
        ) else len(preference)
        return candidate_rank < current_rank

    def _parse_standard_information(
        self, fixed_record: bytes, attr_offset: int, record_index: int
    ) -> MftTimestamps | None:
        """Parse a $STANDARD_INFORMATION attribute's timestamps.

        Args:
            fixed_record: The fixup-applied record bytes.
            attr_offset: Byte offset of this attribute within the
                record.
            record_index: This record's 0-indexed position, used in
                warning log messages.

        Returns:
            The parsed :class:`MftTimestamps`, or ``None`` if the
            attribute's content could not be located/read.
        """
        content = self._get_resident_content(fixed_record, attr_offset, record_index, "$SI")
        if content is None or len(content) < 32:
            return None
        return MftTimestamps(
            creation_time=self._filetime_to_datetime(content[0:8]),
            modification_time=self._filetime_to_datetime(content[8:16]),
            mft_modification_time=self._filetime_to_datetime(content[16:24]),
            access_time=self._filetime_to_datetime(content[24:32]),
        )

    def _parse_file_name_attribute(
        self, fixed_record: bytes, attr_offset: int, record_index: int
    ) -> tuple[int, MftTimestamps, str, int] | None:
        """Parse a $FILE_NAME attribute's timestamps, name, and parent reference.

        Args:
            fixed_record: The fixup-applied record bytes.
            attr_offset: Byte offset of this attribute within the
                record.
            record_index: This record's 0-indexed position, used in
                warning log messages.

        Returns:
            A tuple of ``(namespace, timestamps, name,
            parent_record_number)``, or ``None`` if the attribute's
            content could not be located/read.
        """
        content = self._get_resident_content(fixed_record, attr_offset, record_index, "$FN")
        if content is None or len(content) < 66:
            return None

        parent_reference = int.from_bytes(content[0:8], "little")
        parent_record_number = parent_reference & 0x0000FFFFFFFFFFFF

        timestamps = MftTimestamps(
            creation_time=self._filetime_to_datetime(content[8:16]),
            modification_time=self._filetime_to_datetime(content[16:24]),
            mft_modification_time=self._filetime_to_datetime(content[24:32]),
            access_time=self._filetime_to_datetime(content[32:40]),
        )

        name_length_chars = content[64]
        namespace = content[65]
        name_end = 66 + name_length_chars * 2
        if name_end > len(content):
            logger.debug(
                "Record %d: $FILE_NAME name field truncated, skipping name", record_index
            )
            return namespace, timestamps, "", parent_record_number

        try:
            name = content[66:name_end].decode("utf-16-le")
        except UnicodeDecodeError:
            logger.warning("Record %d: failed to decode $FILE_NAME name", record_index)
            name = ""

        return namespace, timestamps, name, parent_record_number

    @staticmethod
    def _get_resident_content(
        fixed_record: bytes, attr_offset: int, record_index: int, attr_label: str
    ) -> bytes | None:
        """Extract a resident attribute's content bytes.

        ``$STANDARD_INFORMATION`` and ``$FILE_NAME`` are always
        resident per the NTFS specification, so non-resident content
        is not handled here.

        Args:
            fixed_record: The fixup-applied record bytes.
            attr_offset: Byte offset of the attribute within the
                record.
            record_index: This record's 0-indexed position, used in
                warning log messages.
            attr_label: A short label for the attribute (used in log
                messages only).

        Returns:
            The attribute's content bytes, or ``None`` if the
            attribute is non-resident or its content could not be
            located.
        """
        non_resident_flag = fixed_record[attr_offset + 8]
        if non_resident_flag != 0:
            logger.debug(
                "Record %d: %s attribute unexpectedly non-resident, skipping",
                record_index,
                attr_label,
            )
            return None

        content_length = int.from_bytes(fixed_record[attr_offset + 16 : attr_offset + 20], "little")
        content_offset = int.from_bytes(fixed_record[attr_offset + 20 : attr_offset + 22], "little")
        start = attr_offset + content_offset
        end = start + content_length
        if end > len(fixed_record):
            logger.warning(
                "Record %d: %s attribute content extends past record bounds",
                record_index,
                attr_label,
            )
            return None
        return fixed_record[start:end]

    @staticmethod
    def _filetime_to_datetime(raw_bytes: bytes) -> datetime | None:
        """Convert an 8-byte little-endian Windows FILETIME to a UTC datetime.

        Args:
            raw_bytes: 8 bytes representing a FILETIME (100-nanosecond
                intervals since 1601-01-01 UTC).

        Returns:
            A timezone-aware UTC :class:`~datetime.datetime`, or
            ``None`` if the value is zero (commonly used to mean
            "not set").
        """
        raw_value = int.from_bytes(raw_bytes, "little")
        if raw_value == 0:
            return None
        try:
            return _WINDOWS_FILETIME_EPOCH + timedelta(microseconds=raw_value / 10)
        except OverflowError:
            return None

    @staticmethod
    def _detect_timestamp_anomalies(
        standard_information: MftTimestamps | None,
        file_name_information: MftTimestamps | None,
    ) -> tuple[str, ...]:
        """Flag $STANDARD_INFORMATION fields that predate $FILE_NAME creation.

        This is the core timestomping check: under normal filesystem
        activity, no ``$STANDARD_INFORMATION`` timestamp can be
        earlier than the file's ``$FILE_NAME`` creation time, since
        SI is initialized equal to FN at creation and only advances
        from there. An SI value earlier than FN creation (beyond the
        comparison tolerance) means SI was set backward — i.e.
        deliberately forged.

        Args:
            standard_information: The record's $SI timestamps, or
                ``None`` if unavailable.
            file_name_information: The record's $FN timestamps
                (already the preferred name attribute), or ``None``
                if unavailable.

        Returns:
            A tuple of field names (from :class:`MftTimestamps`) whose
            SI value predates FN creation time by more than the
            comparison tolerance. Empty if no anomaly was found or
            either timestamp set is unavailable.
        """
        if standard_information is None or file_name_information is None:
            return ()
        fn_creation = file_name_information.creation_time
        if fn_creation is None:
            return ()

        anomalies = []
        for field_name in (
            "creation_time",
            "modification_time",
            "mft_modification_time",
            "access_time",
        ):
            si_value = getattr(standard_information, field_name)
            if si_value is not None and si_value < fn_creation - _ANOMALY_TOLERANCE:
                anomalies.append(field_name)
        return tuple(anomalies)


# --------------------------------------------------------------------------
# File-level orchestration
# --------------------------------------------------------------------------


class MftParser:  # pylint: disable=too-few-public-methods
    """Parses a raw NTFS ``$MFT`` file into a list of :class:`MftRecord` objects.

    Note:
        This class exposes a single public entry point (``parse``)
        backed by several private helper methods — a deliberate
        single-responsibility design, so
        ``too-few-public-methods`` is intentionally suppressed here.

    The parser is resilient to per-record corruption: if an
    individual record cannot be read (e.g. a ``BAAD`` signature or a
    fixup verification failure), the failure is logged and recorded
    in :attr:`parse_failures`, and parsing continues with the next
    record — consistent with the resilience philosophy used
    throughout Corrobora's parsers. Never-allocated record slots
    (all-zero bytes) are silently skipped, since they are normal and
    not evidence of anything.

    Attributes:
        file_path: The path to the ``$MFT`` file being parsed.
        record_size: The size, in bytes, of each MFT record. 1024 is
            standard for the overwhelming majority of NTFS volumes;
            override only if you know your source volume uses a
            different value.
        parse_failures: Details of any records that failed to parse,
            populated after calling :meth:`parse`.

    Example:
        >>> parser = MftParser("C_MFT")
        >>> records = parser.parse()
        >>> timestomped = [r for r in records if r.likely_timestomped]
    """

    def __init__(
        self,
        file_path: str | Path,
        record_size: int = _DEFAULT_RECORD_SIZE,
        extractor: MftRecordExtractor | None = None,
    ) -> None:
        """Initialize the parser for a given file.

        Args:
            file_path: Path to the raw ``$MFT`` file to parse.
            record_size: The size, in bytes, of each MFT record.
                Defaults to 1024, standard for the overwhelming
                majority of NTFS volumes.
            extractor: An :class:`MftRecordExtractor` instance to use
                for converting each record's raw bytes into an
                :class:`MftRecord`. Defaults to a new instance if not
                provided. Accepting this as a constructor parameter
                allows a mock/stub extractor to be injected in unit
                tests.
        """
        self.file_path = Path(file_path)
        self.record_size = record_size
        self._extractor = extractor if extractor is not None else MftRecordExtractor()
        self.parse_failures: list[ParseFailure] = []

    def parse(self) -> list[MftRecord]:
        """Parse the configured ``$MFT`` file into MFT records.

        Returns:
            A list of successfully extracted :class:`MftRecord`
            objects, in the order they appear in the file. Records
            that fail to parse are omitted from this list but are
            recorded in :attr:`parse_failures`. Never-allocated
            (all-zero) slots are silently omitted from both.

        Raises:
            MftFileError: If the file does not exist, is not a
                regular file, or cannot be read.
        """
        self._validate_file_path()
        self.parse_failures = []
        records: list[MftRecord] = []

        logger.info("Starting MFT parse: %s (record_size=%d)", self.file_path, self.record_size)

        try:
            with self.file_path.open("rb") as mft_file:
                record_index = 0
                while True:
                    raw_record = mft_file.read(self.record_size)
                    if len(raw_record) < self.record_size:
                        break
                    self._process_record(raw_record, record_index, records)
                    record_index += 1
        except OSError as exc:
            raise MftFileError(f"Failed to read MFT file '{self.file_path}': {exc}") from exc

        logger.info(
            "Completed MFT parse: %s (%d records extracted, %d failures)",
            self.file_path,
            len(records),
            len(self.parse_failures),
        )
        return records

    def _process_record(
        self, raw_record: bytes, record_index: int, records: list[MftRecord]
    ) -> None:
        """Extract a single raw record and append it to ``records`` on success.

        Never-allocated slots (all-zero bytes) are silently skipped —
        this is normal and expected throughout any ``$MFT`` file, not
        a parsing failure. Failures are caught, logged, and appended
        to :attr:`parse_failures` rather than propagated, so that one
        damaged record does not halt processing of the rest of the
        file.

        Args:
            raw_record: The raw bytes of one record.
            record_index: This record's 0-indexed position within the
                file.
            records: The accumulator list to append a successfully
                extracted :class:`MftRecord` to.
        """
        if raw_record.count(b"\x00") == len(raw_record):
            logger.debug("Record %d: never-allocated (all-zero) slot, skipping", record_index)
            return

        try:
            record = self._extractor.extract(raw_record, record_index)
            records.append(record)
        except RecordExtractionError as exc:
            logger.warning("Skipping record %d: %s", record_index, exc)
            self.parse_failures.append(ParseFailure(record_number=record_index, reason=str(exc)))
        except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
            # Deliberately broad: isolates ANY unexpected failure to a
            # single record so one corrupt/damaged record cannot abort
            # parsing of the rest of the $MFT file.
            logger.warning(
                "Skipping record %d due to unexpected error: %s", record_index, exc
            )
            self.parse_failures.append(ParseFailure(record_number=record_index, reason=str(exc)))

    def _validate_file_path(self) -> None:
        """Validate that the configured file path is a readable file.

        Raises:
            MftFileError: If the path does not exist or is not a
                file.
        """
        if not self.file_path.exists():
            raise MftFileError(f"File not found: {self.file_path}")
        if not self.file_path.is_file():
            raise MftFileError(f"Path is not a file: {self.file_path}")


# --------------------------------------------------------------------------
# Command-line entry point
# --------------------------------------------------------------------------


def _main() -> None:
    """Run the parser as a script: ``python mft.py <path-to-$MFT-file>``."""
    import argparse  # pylint: disable=import-outside-toplevel

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="mft.py", description="Parse an NTFS $MFT file and detect timestomping."
    )
    parser.add_argument("target", help="Path to the raw $MFT file.")
    parser.add_argument(
        "--record-size", type=int, default=_DEFAULT_RECORD_SIZE, help="MFT record size in bytes."
    )
    args = parser.parse_args()

    mft_parser = MftParser(args.target, record_size=args.record_size)
    try:
        records = mft_parser.parse()
    except MftFileError as exc:
        logger.error("Parsing failed: %s", exc)
        raise SystemExit(1) from exc

    flagged = [r for r in records if r.likely_timestomped]
    logger.info(
        "Parsed %d record(s), %d failure(s), %d likely timestomped.",
        len(records),
        len(mft_parser.parse_failures),
        len(flagged),
    )
    for record in flagged:
        logger.warning(
            "TIMESTOMP SUSPECTED: record #%d '%s' — anomalous fields: %s",
            record.record_number,
            record.filename,
            ", ".join(record.timestamp_anomalies),
        )


if __name__ == "__main__":
    _main()