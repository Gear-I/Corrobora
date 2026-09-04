"""Shared data model for Corrobora's correlation rules.

Moved out of ``corrobora.parsers.correlation_engine`` as part of the
rules-layer refactor: this module now owns ``Severity``,
``CorrelationFinding``, ``CorrelationContext``, ``CorrelationRule``,
and the per-artifact-type entry wrapper dataclasses, while
``correlation_engine.py`` keeps only the ``CorrelationEngine`` class,
context-building, and the CLI -- and re-exports everything defined
here so existing importers (``case_ingest.py``, ``corrobora_gui.py``)
require no changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from corrobora.parsers.evtx import EventRecord
from corrobora.parsers.mft import MftRecord
from corrobora.parsers.prefetch import PrefetchRecord
from corrobora.parsers.registry import RegistryValue

# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------


class Severity(str, Enum):
    """Severity level of a correlation finding, low to high."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


@dataclass(frozen=True, slots=True)
class CorrelationFinding:
    """A single anti-forensic indicator surfaced by a correlation rule.

    Attributes:
        rule_name: The identifier of the rule that produced this
            finding (e.g. ``"prefetch_execution_without_evtx"``).
        severity: How significant this finding is.
        description: A human-readable explanation of what was found
            and why it matters.
        evidence: Human-readable strings describing the specific
            artifact entries that support this finding (e.g. exact
            timestamps, record numbers, file paths), for inclusion in
            a report without needing to re-run the correlation.
        source_paths: The artifact source file(s) involved in this
            finding.
        score: A 0-100 corroboration-strength score, distinct from
            ``severity``: severity answers "how bad is this if
            true," score answers "how strong is the evidence that
            this finding reflects genuine anti-forensic activity."
            Two findings can share a severity while carrying very
            different evidentiary weight (e.g. an absence-based
            "no corroborating evidence found" finding vs. a positive
            hash-mismatch or timestomping detection).
    """

    rule_name: str
    severity: Severity
    description: str
    evidence: tuple[str, ...]
    source_paths: tuple[str, ...]
    score: int

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 100:
            raise ValueError(f"score must be between 0 and 100, got {self.score}")


@dataclass(frozen=True, slots=True)
class EvtxEntry:
    """A single EVTX event record tagged with its source file.

    Attributes:
        source_path: Path to the ``.evtx`` file this record came from.
        record: The parsed event record.
    """

    source_path: str
    record: EventRecord


@dataclass(frozen=True, slots=True)
class RegistryValueEntry:
    """A single registry value tagged with its source hive file.

    Attributes:
        source_path: Path to the hive file this value came from.
        value: The parsed registry value.
    """

    source_path: str
    value: RegistryValue


@dataclass(frozen=True, slots=True)
class PrefetchEntry:
    """A single Prefetch record tagged with its source ``.pf`` file.

    Attributes:
        source_path: Path to the ``.pf`` file this record came from.
        record: The parsed Prefetch record.
    """

    source_path: str
    record: PrefetchRecord


@dataclass(frozen=True, slots=True)
class MftEntry:
    """A single MFT record tagged with its source ``$MFT`` file.

    Attributes:
        source_path: Path to the ``$MFT`` file this record came from.
        record: The parsed MFT record.
    """

    source_path: str
    record: MftRecord


@dataclass(frozen=True, slots=True)
class CorrelationContext:
    """An in-memory bundle of parsed artifacts to run correlation rules against.

    Building this once and passing it to multiple rules (or multiple
    engine runs) avoids re-parsing files, and keeps
    :class:`CorrelationRule` implementations entirely decoupled from
    file I/O, which is what makes them straightforward to unit test.

    Attributes:
        evtx_entries: All parsed EVTX records, each tagged with its
            source file.
        registry_value_entries: All parsed registry values, each
            tagged with its source hive file.
        prefetch_entries: All parsed Prefetch records, each tagged
            with its source file.
        mft_entries: All parsed MFT records, each tagged with its
            source file.
    """

    evtx_entries: tuple[EvtxEntry, ...]
    registry_value_entries: tuple[RegistryValueEntry, ...]
    prefetch_entries: tuple[PrefetchEntry, ...]
    mft_entries: tuple[MftEntry, ...] = ()


# --------------------------------------------------------------------------
# Rule interface
# --------------------------------------------------------------------------


class CorrelationRule(ABC):  # pylint: disable=too-few-public-methods
    """Abstract base class for a single, independently testable correlation rule.

    Note:
        Each rule exposes a single public entry point (``evaluate``)
        -- a deliberate Strategy-pattern design, so
        ``too-few-public-methods`` is intentionally suppressed
        throughout this module's rule classes.

    Each rule inspects a :class:`CorrelationContext` and returns any
    :class:`CorrelationFinding` objects it identifies. Rules must not
    mutate the context or perform file I/O -- all data they need
    should already be present in the context -- which is what allows
    each rule to be unit tested with a small, hand-built context
    instead of real forensic artifacts.

    Attributes:
        rule_name: A short, stable identifier for this rule, used in
            :attr:`CorrelationFinding.rule_name` and in logs.
        category: Which group of rules this belongs to (e.g.
            ``"program_execution"``, ``"persistence"``,
            ``"integrity"``), letting a future GUI group rules for
            selection without needing to introspect module paths.
    """

    rule_name: str
    category: ClassVar[str]

    @abstractmethod
    def evaluate(self, context: CorrelationContext) -> list[CorrelationFinding]:
        """Evaluate this rule against the given context.

        Args:
            context: The parsed artifacts to check.

        Returns:
            A list of findings this rule identified. Empty if none.
        """
