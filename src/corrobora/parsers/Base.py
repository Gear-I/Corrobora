"""Corrobora's shared artifact parser interface.

Every Corrobora artifact parser (``evtx``, ``registry``, ``prefetch``,
``mft``, and future modules such as an Amcache parser or an EZ Tools
CSV/JSON importer) implements :class:`BaseArtifactParser` in addition
to its own domain-specific, type-safe native API. This gives any
future consumer -- a generic report, a new correlation rule, or an
importer for a different tool's output -- a single, uniform way to
pull normalized records from any artifact source without needing to
know its internal structure, while code that wants the rich,
artifact-specific data (e.g. a raw ``EventRecord`` or ``RegistryKey``)
can still use each parser's native methods directly.

Design rationale:
    Different artifact types have fundamentally different native
    shapes -- EVTX yields a flat list of event records, a registry
    hive yields both keys and values from a tree walk, and an
    imported EZ Tools CSV yields rows with a schema specific to that
    tool. Rather than force every parser into one artificial return
    shape, this interface asks each parser for a *second, normalized*
    view (``parse_common()``) purpose-built for cross-artifact
    consumption, on top of whatever native ``parse()`` method it
    already exposes. Corrobora's correlation engine
    (``correlation_engine.py``) does not currently consume this
    normalized view -- its rules use each parser's native typed
    output directly, since that was already built, tested, and
    validated against real data. ``parse_common()`` is the extension
    point future additions (new artifact types, new input formats)
    are expected to use.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar

# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class ArtifactParsingError(Exception):
    """Base exception for all errors raised by any Corrobora artifact parser.

    Concrete parsers' own exceptions (e.g. ``EvtxParsingError``,
    ``RegistryParsingError``) are not required to subclass this, but
    doing so lets calling code -- especially a future generic
    consumer that handles many artifact types at once -- catch any
    parser failure with a single ``except ArtifactParsingError``.
    """


class ArtifactFileError(ArtifactParsingError):
    """Raised for file-level failures that prevent parsing from starting.

    Examples include a missing file, an unreadable file, or a file
    whose structure is too damaged to begin parsing at all.
    """


# --------------------------------------------------------------------------
# Shared data models
# --------------------------------------------------------------------------


class ArtifactType(str, Enum):
    """The set of artifact types Corrobora knows how to parse.

    Using a shared enum (rather than a free-form string) keeps any
    future cross-artifact consumer consistent as new artifact
    parsers or input formats (e.g. an EZ Tools CSV importer) are
    added.
    """

    EVTX = "evtx"
    REGISTRY = "registry"
    PREFETCH = "prefetch"
    MFT = "mft"
    AMCACHE = "amcache"
    SRUM = "srum"
    SHELLBAGS = "shellbags"
    EXTERNAL_CSV = "external_csv"


@dataclass(frozen=True, slots=True)
class ParseFailure:
    """A normalized description of a single failed record/key/value/row.

    Concrete parsers track richer, type-specific failure details
    internally (e.g. an EVTX record number vs. a registry key path).
    This class is the common shape used when reporting failures
    through the :class:`BaseArtifactParser` interface.

    Attributes:
        identifier: A human-readable identifier for what failed (e.g.
            a record number as a string, or a key path), or ``None``
            if it could not be determined.
        reason: A human-readable description of why extraction failed.
    """

    identifier: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """A normalized, artifact-agnostic view of a single parsed item.

    Each concrete parser is responsible for mapping its own
    domain-specific objects (e.g. ``EventRecord``, ``RegistryValue``)
    into this shape via :meth:`BaseArtifactParser.parse_common`.

    Attributes:
        artifact_type: Which artifact source this record came from.
        source_path: The path to the file (or, for an imported
            report, the original tool's output file) this record was
            extracted from.
        record_id: A stable, source-specific identifier for this
            record (e.g. an EVTX record number, or a registry key
            path), used for referencing this record without needing
            the full ``raw`` object.
        timestamp: The most relevant UTC timestamp for this record
            (e.g. an event's creation time, or a key's last-written
            time), or ``None`` if the source had no applicable
            timestamp.
        summary: A short, human-readable one-line description of the
            record, suitable for display without needing to inspect
            ``raw``.
        metadata: A normalized key-value bag of additional fields
            (e.g. ``provider_name``, ``event_id`` for EVTX;
            ``value_name``, ``value_type`` for registry). Kept as a
            plain mapping rather than a fixed schema since different
            artifact types expose different attributes.
        raw: The original, artifact-specific object this record was
            derived from, retained so consuming code can drill into
            full fidelity detail when needed.
    """

    artifact_type: ArtifactType
    source_path: str
    record_id: str
    timestamp: datetime | None
    summary: str
    metadata: Mapping[str, Any]
    raw: Any = field(repr=False)


# --------------------------------------------------------------------------
# Base parser interface
# --------------------------------------------------------------------------


class BaseArtifactParser(ABC):  # pylint: disable=too-few-public-methods
    """Abstract base class all Corrobora artifact parsers implement.

    Note:
        ``too-few-public-methods`` is intentionally suppressed: this
        is a narrow, deliberately minimal interface (two abstract
        methods), not a design smell.

    Concrete parsers keep their own type-safe, artifact-specific
    ``parse()`` method (e.g. ``EvtxParser.parse() -> list[EventRecord]``)
    for direct, high-fidelity use. This base class additionally
    requires two things so any parser can be used polymorphically by
    a future cross-artifact consumer:

    1. :meth:`parse_common` -- parse the source (reusing the parser's
       own native ``parse()`` internally where applicable) and return
       a normalized ``list[ArtifactRecord]``.
    2. :meth:`get_common_failures` -- return any parse failures,
       normalized to ``list[ParseFailure]``.

    Attributes:
        file_path: The path to the artifact source being parsed.
        artifact_type: A class-level constant identifying which kind
            of artifact this parser handles. Must be overridden by
            every concrete subclass.

    Example:
        >>> parsers: list[BaseArtifactParser] = [
        ...     EvtxParser("Security.evtx"),
        ...     RegistryHiveParser("NTUSER.DAT"),
        ... ]
        >>> all_records: list[ArtifactRecord] = []
        >>> for parser in parsers:
        ...     all_records.extend(parser.parse_common())
    """

    artifact_type: ClassVar[ArtifactType]

    def __init__(self, file_path: str | Path) -> None:
        """Initialize the parser for a given artifact source.

        Args:
            file_path: Path to the artifact file to parse.
        """
        self.file_path = Path(file_path)

    @abstractmethod
    def parse_common(self) -> list[ArtifactRecord]:
        """Parse the artifact source and return normalized records.

        Implementations should internally call the parser's own
        native parsing method(s) and map each resulting item to an
        :class:`ArtifactRecord`.

        Returns:
            A list of normalized :class:`ArtifactRecord` objects.

        Raises:
            ArtifactFileError: If the source cannot be opened or
                parsed at the file level.
        """

    @abstractmethod
    def get_common_failures(self) -> list[ParseFailure]:
        """Return any record/key/value/row parse failures, normalized.

        Should be called after :meth:`parse_common`; behavior before
        the source has been parsed is left to each implementation,
        but returning an empty list is recommended.

        Returns:
            A list of normalized :class:`ParseFailure` objects.
        """

    def _require_existing_file(self) -> None:
        """Validate that :attr:`file_path` exists and is a regular file.

        Shared by concrete parsers to avoid duplicating this check.
        Extension validation (where applicable) is left to each
        concrete parser, since expected extensions vary by artifact
        type and registry hives commonly have no extension at all.

        Raises:
            ArtifactFileError: If the path does not exist or is not a
                file.
        """
        if not self.file_path.exists():
            raise ArtifactFileError(f"File not found: {self.file_path}")
        if not self.file_path.is_file():
            raise ArtifactFileError(f"Path is not a file: {self.file_path}")