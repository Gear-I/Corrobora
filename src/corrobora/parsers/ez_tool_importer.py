"""Corrobora EZ Tools import module.

Reads CSV output produced by Eric Zimmerman's EZ Tools suite
(EvtxECmd, RECmd, PECmd, MFTECmd, etc.) and normalizes it into
:class:`~corrobora.parsers.base.ArtifactRecord` objects, so evidence
already processed by the tools examiners already trust and use daily
can flow into Corrobora's analysis without needing Corrobora's own
from-scratch parsers to touch the source artifacts at all.

Background:
    EZ Tools are C#/.NET, not Python, so importing their source code
    directly was never realistic. What makes interoperability
    practical instead is that every EZ Tool writes standardized,
    well-documented CSV/JSON/XML output -- a format boundary that is
    completely language-agnostic. This module reads that output; it
    has no dependency on .NET and does not invoke the EZ Tools
    executables itself.

    In practice, EZ Tools are most often run via KAPE's ``!EZParser``
    module, which produces a ``Processed`` folder containing one CSV
    per tool (e.g. ``20240408132435_EvtxECmd_Output.csv``,
    ``..._RECmd_Output.csv``). :func:`discover_ez_tools_csvs` scans a
    folder like that and classifies each file by its EZ-Tools-style
    filename, mirroring how ``case_ingest.py`` classifies raw
    artifact files.

Current coverage:
    Only **EvtxECmd** CSV output is fully parsed and normalized right
    now, using its confirmed real column schema (``RecordNumber``,
    ``EventRecordId``, ``TimeCreated``, ``EventId``, ``Level``,
    ``Provider``, ``Channel``, ``Computer``, ``UserName``,
    ``MapDescription``, ``PayloadData1``-``PayloadData6``, and
    others). RECmd, PECmd, MFTECmd, and AmcacheParser CSVs are
    *detected and classified* by :func:`discover_ez_tools_csvs`, but
    attempting to actually parse one with :class:`EzToolsCsvParser`
    raises :class:`UnsupportedEzToolError` with a clear message,
    rather than silently mis-parsing an unfamiliar schema. Extending
    coverage to another tool means adding one normalizer function and
    one entry in ``_TOOL_NORMALIZERS`` below.

Example:
    >>> from corrobora.parsers.ez_tools_import import (
    ...     EzToolsCsvParser, discover_ez_tools_csvs
    ... )
    >>> discovered = discover_ez_tools_csvs("C:/Cases/Case001/Processed")
    >>> for csv_path in discovered.evtxecmd_csvs:
    ...     parser = EzToolsCsvParser(csv_path)
    ...     records = parser.parse_common()

Command-line usage:
    corrobora-ez-import <path-to-Processed-folder>
"""

from __future__ import annotations

import argparse
import csv
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import ClassVar

from .Base import (
    ArtifactFileError,
    ArtifactRecord,
    ArtifactType,
    BaseArtifactParser,
    ParseFailure,
)

logger = logging.getLogger(__name__)

# EZ Tools / KAPE's !EZParser module names output files following the
# pattern "<timestamp>_<ToolName>_Output.csv" (or a user-chosen name via
# --csvf when run manually, which won't match). Detection here favors the
# common KAPE-driven naming; files run manually with custom names won't be
# auto-classified and can still be parsed directly via EzToolsCsvParser.
_TOOL_FILENAME_MARKERS: dict[str, str] = {
    "evtxecmd": "evtxecmd",
    "recmd": "recmd",
    "pecmd": "pecmd",
    "mftecmd": "mftecmd",
    "amcacheparser": "amcacheparser",
}

# The confirmed, real EvtxECmd CSV column schema.
_EVTXECMD_REQUIRED_COLUMNS = frozenset({"RecordNumber", "TimeCreated", "EventId"})


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class EzToolsImportError(Exception):
    """Base exception for all errors raised by the EZ Tools import subsystem."""


class EzToolsFileError(EzToolsImportError, ArtifactFileError):
    """Raised for file-level failures that prevent parsing from starting.

    Inherits from :class:`base.ArtifactFileError` so file-level
    failures from this importer can be caught alongside failures from
    Corrobora's own artifact parsers with a single ``except`` clause.
    """


class UnsupportedEzToolError(EzToolsImportError):
    """Raised when asked to parse a CSV from an EZ Tool that isn't supported yet.

    Deliberately distinct from a generic parsing failure: this means
    the file was *recognized* (by filename or header) as coming from
    a known EZ Tool, but that tool's column schema hasn't been wired
    up for normalization yet -- as opposed to the file being
    unreadable or corrupt.
    """


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DiscoveredEzToolsCsvs:
    """EZ Tools CSV files found within a folder, grouped by producing tool.

    Attributes:
        evtxecmd_csvs: Paths to discovered EvtxECmd output CSVs.
        recmd_csvs: Paths to discovered RECmd output CSVs.
        pecmd_csvs: Paths to discovered PECmd output CSVs.
        mftecmd_csvs: Paths to discovered MFTECmd output CSVs.
        amcacheparser_csvs: Paths to discovered AmcacheParser output CSVs.
        unclassified_count: Number of ``.csv`` files scanned that did
            not match any known EZ Tools filename pattern.
    """

    evtxecmd_csvs: tuple[str, ...]
    recmd_csvs: tuple[str, ...]
    pecmd_csvs: tuple[str, ...]
    mftecmd_csvs: tuple[str, ...]
    amcacheparser_csvs: tuple[str, ...]
    unclassified_count: int

    @property
    def total_count(self) -> int:
        """The total number of recognized EZ Tools CSV files discovered."""
        return (
            len(self.evtxecmd_csvs)
            + len(self.recmd_csvs)
            + len(self.pecmd_csvs)
            + len(self.mftecmd_csvs)
            + len(self.amcacheparser_csvs)
        )


def _classify_csv_filename(name_lower: str) -> str | None:
    """Classify a CSV filename by which EZ Tool likely produced it.

    Args:
        name_lower: The lowercased filename to classify.

    Returns:
        One of the keys in ``_TOOL_FILENAME_MARKERS``, or ``None`` if
        no known marker was found in the filename.
    """
    for tool_key, marker in _TOOL_FILENAME_MARKERS.items():
        if marker in name_lower:
            return tool_key
    return None


def discover_ez_tools_csvs(folder: str | Path) -> DiscoveredEzToolsCsvs:
    """Recursively scan a folder and classify EZ Tools CSV output by producing tool.

    Designed around KAPE's ``!EZParser`` module output layout (a
    ``Processed`` folder containing one CSV per tool run), but works
    against any folder containing EZ-Tools-named CSV files.

    Args:
        folder: Path to the folder to scan (e.g. a KAPE ``Processed``
            directory).

    Returns:
        The classified CSV paths found.

    Raises:
        EzToolsFileError: If ``folder`` does not exist or is not a
            directory.
    """
    folder_path = Path(folder)
    if not folder_path.exists():
        raise EzToolsFileError(f"Folder not found: {folder_path}")
    if not folder_path.is_dir():
        raise EzToolsFileError(f"Path is not a directory: {folder_path}")

    by_tool: dict[str, list[str]] = {key: [] for key in _TOOL_FILENAME_MARKERS}
    unclassified = 0

    for entry in folder_path.rglob("*.csv"):
        if not entry.is_file():
            continue
        tool_key = _classify_csv_filename(entry.name.lower())
        if tool_key is None:
            unclassified += 1
            continue
        by_tool[tool_key].append(str(entry))

    logger.info(
        "EZ Tools CSV scan of '%s': %d EvtxECmd, %d RECmd, %d PECmd, "
        "%d MFTECmd, %d AmcacheParser, %d unclassified .csv file(s).",
        folder_path,
        len(by_tool["evtxecmd"]),
        len(by_tool["recmd"]),
        len(by_tool["pecmd"]),
        len(by_tool["mftecmd"]),
        len(by_tool["amcacheparser"]),
        unclassified,
    )

    return DiscoveredEzToolsCsvs(
        evtxecmd_csvs=tuple(sorted(by_tool["evtxecmd"])),
        recmd_csvs=tuple(sorted(by_tool["recmd"])),
        pecmd_csvs=tuple(sorted(by_tool["pecmd"])),
        mftecmd_csvs=tuple(sorted(by_tool["mftecmd"])),
        amcacheparser_csvs=tuple(sorted(by_tool["amcacheparser"])),
        unclassified_count=unclassified,
    )


# --------------------------------------------------------------------------
# Per-tool row normalizers
# --------------------------------------------------------------------------


def _parse_evtxecmd_timestamp(raw_value: str) -> datetime | None:
    """Parse an EvtxECmd ``TimeCreated`` value into a UTC datetime.

    EvtxECmd's default format is ISO 8601 with a UTC offset (e.g.
    ``2024-02-14T03:41:58.4101450+00:00``); Python's
    ``fromisoformat`` cannot handle the 7-digit fractional-second
    precision Windows FILETIME produces, so this trims to
    microsecond (6-digit) precision first.

    Args:
        raw_value: The raw ``TimeCreated`` cell value.

    Returns:
        A parsed UTC :class:`~datetime.datetime`, or ``None`` if the
        value is empty or unparseable.
    """
    if not raw_value:
        return None
    try:
        if "." in raw_value:
            head, _, tail = raw_value.partition(".")
            frac_and_offset = tail
            for sep in ("+", "-"):
                if sep in tail:
                    frac, _, offset = tail.partition(sep)
                    frac_and_offset = f"{frac[:6]:0<6}{sep}{offset}"
                    break
            else:
                frac_and_offset = f"{tail[:6]:0<6}"
            raw_value = f"{head}.{frac_and_offset}"
        return datetime.fromisoformat(raw_value)
    except ValueError:
        logger.warning("Could not parse EvtxECmd TimeCreated value: %r", raw_value)
        return None


def _normalize_evtxecmd_row(row: dict[str, str], source_path: str) -> ArtifactRecord:
    """Normalize a single EvtxECmd CSV row into an :class:`ArtifactRecord`.

    Tagged as :data:`ArtifactType.EVTX` (not ``EXTERNAL_CSV``) since
    the row fundamentally represents an EVTX event record -- just
    parsed by a different, trusted tool. Provenance is preserved via
    ``metadata["source_tool"]``.

    Args:
        row: One CSV row, as a column-name-to-value mapping.
        source_path: The CSV file this row came from.

    Returns:
        The normalized :class:`ArtifactRecord`.
    """
    timestamp = _parse_evtxecmd_timestamp(row.get("TimeCreated", ""))
    event_id = row.get("EventId", "")
    provider = row.get("Provider", "")
    map_description = row.get("MapDescription", "")
    record_number = row.get("RecordNumber", "")

    payload_fields = {
        f"payload_data_{i}": row.get(f"PayloadData{i}", "") or None for i in range(1, 7)
    }

    summary = (
        f"Event ID {event_id} ({provider or 'unknown provider'})"
        + (f" -- {map_description}" if map_description else "")
    )

    return ArtifactRecord(
        artifact_type=ArtifactType.EVTX,
        source_path=source_path,
        record_id=record_number or f"{source_path}:{row.get('EventRecordId', '?')}",
        timestamp=timestamp,
        summary=summary,
        metadata={
            "source_tool": "EvtxECmd",
            "event_id": event_id,
            "provider_name": provider,
            "computer_name": row.get("Computer"),
            "channel": row.get("Channel"),
            "level": row.get("Level"),
            "user_name": row.get("UserName"),
            "remote_host": row.get("RemoteHost"),
            "map_description": map_description,
            "executable_info": row.get("ExecutableInfo"),
            **payload_fields,
        },
        raw=dict(row),
    )


# Maps a classified tool key to its row-normalizer function. Adding
# support for another EZ Tool means writing one function matching this
# signature and adding one entry here.
_TOOL_NORMALIZERS: dict[str, Callable[[dict[str, str], str], ArtifactRecord]] = {
    "evtxecmd": _normalize_evtxecmd_row,
}


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------


class EzToolsCsvParser(BaseArtifactParser):  # pylint: disable=too-few-public-methods
    """Parses a single EZ Tools CSV output file into normalized records.

    Note:
        ``too-few-public-methods`` is intentionally suppressed: this
        class exposes a single public entry point (``parse_common``)
        -- a deliberate single-responsibility design.

    Which EZ Tool produced the CSV is auto-detected from the
    filename (see :func:`discover_ez_tools_csvs`'s classification
    logic); parsing raises :class:`UnsupportedEzToolError` for a
    recognized-but-not-yet-implemented tool, and a generic
    :class:`EzToolsFileError` if the tool can't be identified at all.

    Unlike Corrobora's own artifact parsers, this class does not
    implement a "native" ``parse()`` returning a rich, tool-specific
    model -- EZ Tools' CSV *is* the native representation already;
    :meth:`parse_common` is both the primary and only entry point.

    Attributes:
        file_path: The path to the EZ Tools CSV file being parsed.
        parse_failures: Details of any rows that failed to parse,
            populated after calling :meth:`parse_common`.

    Example:
        >>> parser = EzToolsCsvParser("20240408132435_EvtxECmd_Output.csv")
        >>> records = parser.parse_common()
    """

    artifact_type: ClassVar[ArtifactType] = ArtifactType.EXTERNAL_CSV

    def __init__(self, file_path: str | Path) -> None:
        """Initialize the parser for a given EZ Tools CSV file.

        Args:
            file_path: Path to the CSV file to parse.
        """
        super().__init__(file_path)
        self.parse_failures: list[ParseFailure] = []

    def parse_common(self) -> list[ArtifactRecord]:
        """Parse the CSV file and return normalized :class:`ArtifactRecord` objects.

        Returns:
            A list of normalized :class:`ArtifactRecord` objects, one
            per successfully parsed row.

        Raises:
            EzToolsFileError: If the file cannot be opened or its
                producing tool cannot be identified.
            UnsupportedEzToolError: If the file is recognized as
                coming from a known EZ Tool, but that tool's schema
                isn't normalized yet.
        """
        try:
            self._require_existing_file()
        except ArtifactFileError as exc:
            raise EzToolsFileError(str(exc)) from exc
        self.parse_failures = []

        tool_key = _classify_csv_filename(self.file_path.name.lower())
        if tool_key is None:
            raise EzToolsFileError(
                f"Could not identify which EZ Tool produced '{self.file_path}' "
                f"from its filename. Expected a name containing one of: "
                f"{', '.join(_TOOL_FILENAME_MARKERS.values())}."
            )
        normalizer = _TOOL_NORMALIZERS.get(tool_key)
        if normalizer is None:
            raise UnsupportedEzToolError(
                f"'{self.file_path}' was identified as {tool_key} output, but "
                f"normalization for that tool is not implemented yet. "
                f"Currently supported: {', '.join(_TOOL_NORMALIZERS)}."
            )

        logger.info("Starting EZ Tools CSV parse (%s): %s", tool_key, self.file_path)
        records: list[ArtifactRecord] = []
        try:
            with self.file_path.open("r", encoding="utf-8-sig", newline="") as csv_file:
                reader = csv.DictReader(csv_file)
                for line_number, row in enumerate(reader, start=2):
                    self._process_row(row, line_number, normalizer, records)
        except OSError as exc:
            raise EzToolsFileError(f"Failed to read '{self.file_path}': {exc}") from exc

        logger.info(
            "Completed EZ Tools CSV parse: %s (%d record(s), %d failure(s))",
            self.file_path,
            len(records),
            len(self.parse_failures),
        )
        return records

    def _process_row(
        self,
        row: dict[str, str],
        line_number: int,
        normalizer: Callable[[dict[str, str], str], ArtifactRecord],
        records: list[ArtifactRecord],
    ) -> None:
        """Normalize a single CSV row, isolating any per-row failure.

        Args:
            row: The raw CSV row as a column-name-to-value mapping.
            line_number: The row's line number in the file, used for
                failure reporting.
            normalizer: The tool-specific normalizer function to
                apply to this row.
            records: The accumulator list to append a successfully
                normalized :class:`ArtifactRecord` to.
        """
        try:
            records.append(normalizer(row, str(self.file_path)))
        except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
            # Deliberately broad: isolates a single malformed row so one
            # damaged line does not abort parsing of the rest of the CSV.
            logger.warning("Skipping row %d: %s", line_number, exc)
            self.parse_failures.append(
                ParseFailure(identifier=str(line_number), reason=str(exc))
            )

    def get_common_failures(self) -> list[ParseFailure]:
        """Return this parser's row-level failures.

        Returns:
            The list of :class:`base.ParseFailure` objects recorded
            during the most recent :meth:`parse_common` call.
        """
        return self.parse_failures


# --------------------------------------------------------------------------
# Command-line entry point
# --------------------------------------------------------------------------


def _main() -> None:
    """Run the EZ Tools importer as a script.

    Usage:
        corrobora-ez-import <path-to-Processed-folder>
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="ez_tools_import.py",
        description="Discover and parse EZ Tools CSV output (e.g. from a KAPE "
        "Processed folder) into normalized Corrobora records.",
    )
    parser.add_argument("target", help="Path to a folder containing EZ Tools CSV output.")
    args = parser.parse_args()

    try:
        discovered = discover_ez_tools_csvs(args.target)
    except EzToolsFileError as exc:
        logger.error("Discovery failed: %s", exc)
        raise SystemExit(1) from exc

    logger.info(
        "Discovered %d recognized EZ Tools CSV file(s) (%d unclassified).",
        discovered.total_count,
        discovered.unclassified_count,
    )

    total_records = 0
    for csv_path in discovered.evtxecmd_csvs:
        csv_parser = EzToolsCsvParser(csv_path)
        try:
            records = csv_parser.parse_common()
        except (EzToolsFileError, UnsupportedEzToolError) as exc:
            logger.error("Skipping '%s': %s", csv_path, exc)
            continue
        total_records += len(records)
        logger.info("%s: %d record(s) parsed.", Path(csv_path).name, len(records))

    for label, csvs in (
        ("RECmd", discovered.recmd_csvs),
        ("PECmd", discovered.pecmd_csvs),
        ("MFTECmd", discovered.mftecmd_csvs),
        ("AmcacheParser", discovered.amcacheparser_csvs),
    ):
        if csvs:
            logger.warning(
                "%d %s CSV file(s) found but not yet supported for import.",
                len(csvs),
                label,
            )

    logger.info("Total records parsed: %d", total_records)


if __name__ == "__main__":
    _main()
