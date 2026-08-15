"""Corrobora Correlation Engine — single-file module.

Cross-references parsed EVTX, Registry, and Prefetch artifacts to
surface indicators of anti-forensic activity that no single artifact
reveals on its own. This is the core analytical layer of the
Corrobora digital forensics framework: individual parsers extract
data faithfully, but tampering is often only visible as a
*disagreement* between two independent sources of evidence — e.g. a
program with Prefetch evidence of execution but no corresponding
EVTX process-creation event, or registry persistence with no
supporting execution evidence at all.

Design:
    Detection logic is expressed as small, independently testable
    :class:`CorrelationRule` subclasses rather than one large
    function, so new rules can be added without touching engine
    internals, and each rule can be unit tested against a
    hand-built :class:`CorrelationContext` without needing real
    forensic image files. This module intentionally contains no AI
    or machine learning; every rule is deterministic and explainable.

This module is self-contained but depends on Corrobora's other
single-file parser modules (``evtx.py``, ``registry.py``,
``prefetch.py``) being importable from the same location.

Example:
    >>> from correlation_engine import CorrelationEngine, build_context
    >>> context = build_context(
    ...     evtx_paths=["Security.evtx"],
    ...     registry_paths=["NTUSER.DAT"],
    ...     prefetch_paths=["C:/Windows/Prefetch"],
    ... )
    >>> engine = CorrelationEngine()
    >>> findings = engine.run(context)
    >>> for finding in findings:
    ...     print(finding.severity, finding.rule_name, finding.description)

Command-line usage:
    python correlation_engine.py --evtx Security.evtx System.evtx \\
        --registry NTUSER.DAT --prefetch "C:\\Windows\\Prefetch"
"""

# pylint: disable=too-many-lines
# This module is intentionally kept as a single, self-contained file
# (models + rules + engine + context-building + CLI) so it can be
# dropped into a project without pulling in sibling modules beyond the
# other Corrobora parsers it already depends on.

from __future__ import annotations

import argparse
import itertools
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

from Evtx import EventRecord, EvtxFileError, EvtxParser
from mft import MftFileError, MftParser, MftRecord
from prefetch import (
    PrefetchFileError,
    PrefetchParser,
    PrefetchRecord,
)
from prefetch import (
    parse_folder as parse_prefetch_folder,
)
from registry import RegistryFileError, RegistryHiveParser, RegistryValue

logger = logging.getLogger(__name__)

# Registry key path SEGMENTS (i.e. an exact component between backslashes,
# not a substring anywhere in the path) that identify a run-at-startup
# persistence location. Matched case-insensitively.
#
# This must be an exact segment match, not a substring match: a naive
# substring check for "\Run" also matches inside "\RunAs\" (the standard
# Windows shell "Run as..." context-menu verb, present under nearly every
# file type's Classes key -- completely unrelated to startup persistence),
# producing a large number of false positives on any real registry hive.
_DEFAULT_PERSISTENCE_KEY_SEGMENTS = (
    "run",
    "runonce",
    "runservices",
    "runservicesonce",
)

# EVTX Event IDs that represent process creation, used to look for
# corroborating evidence of a Prefetch-recorded execution.
_DEFAULT_PROCESS_CREATION_EVENT_IDS = frozenset({4688, 1})  # Security 4688, Sysmon 1

# Regex to pull an "something.exe" reference out of free-form registry
# value data (e.g. a Run key's command line).
_EXE_REFERENCE_PATTERN = re.compile(r"([^\\/\s\"]+\.exe)", re.IGNORECASE)


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class CorrelationError(Exception):
    """Base exception for all errors raised by the correlation engine."""


class ContextBuildError(CorrelationError):
    """Raised when a :class:`CorrelationContext` cannot be built from source files.

    This is intentionally not raised for individual file failures
    during context building (those are logged and skipped, matching
    the resilience philosophy used throughout Corrobora's parsers) —
    only for structural problems, such as an invalid source path.
    """


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------


class Severity(str, Enum):
    """Severity level of a correlation finding, low to high."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_SEVERITY_ORDER: dict[Severity, int] = {
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
    """

    rule_name: str
    severity: Severity
    description: str
    evidence: tuple[str, ...]
    source_paths: tuple[str, ...]


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
# Correlation rules
# --------------------------------------------------------------------------


class CorrelationRule(ABC):  # pylint: disable=too-few-public-methods
    """Abstract base class for a single, independently testable correlation rule.

    Note:
        Each rule exposes a single public entry point (``evaluate``)
        — a deliberate Strategy-pattern design, so
        ``too-few-public-methods`` is intentionally suppressed
        throughout this module's rule classes.

    Each rule inspects a :class:`CorrelationContext` and returns any
    :class:`CorrelationFinding` objects it identifies. Rules must not
    mutate the context or perform file I/O — all data they need
    should already be present in the context — which is what allows
    each rule to be unit tested with a small, hand-built context
    instead of real forensic artifacts.

    Attributes:
        rule_name: A short, stable identifier for this rule, used in
            :attr:`CorrelationFinding.rule_name` and in logs.
    """

    rule_name: str

    @abstractmethod
    def evaluate(self, context: CorrelationContext) -> list[CorrelationFinding]:
        """Evaluate this rule against the given context.

        Args:
            context: The parsed artifacts to check.

        Returns:
            A list of findings this rule identified. Empty if none.
        """


class PrefetchExecutionWithoutEvtxRule(CorrelationRule):  # pylint: disable=too-few-public-methods
    """Flags Prefetch-recorded executions with no corresponding EVTX event.

    For each Prefetch run timestamp, this rule looks for an EVTX
    process-creation event (by default, Event ID 4688 or Sysmon Event
    ID 1) within a configurable time window whose message text
    references the executable's name. If none is found, the
    execution is flagged: it may indicate the corresponding EVTX
    record was cleared, wiped, or never logged (e.g. auditing was
    disabled), or that a legitimate execution simply predates the
    available Security log data.

    Note:
        Matching relies on a substring search of the executable name
        within each EVTX record's concatenated ``message`` field,
        since Corrobora's EVTX parser does not structurally parse
        named EventData fields (see ``evtx.py``). This is a
        deliberate, documented limitation: it will not catch cases
        where the process name appears only in an unparsed/binary
        field, and can occasionally over-match on short executable
        names. Treat findings as investigative leads, not proof.
    """

    rule_name = "prefetch_execution_without_evtx"

    def __init__(
        self,
        time_window: timedelta = timedelta(minutes=5),
        process_creation_event_ids: frozenset[int] = _DEFAULT_PROCESS_CREATION_EVENT_IDS,
    ) -> None:
        """Initialize the rule.

        Args:
            time_window: How far before/after a Prefetch run
                timestamp to search for a matching EVTX event.
            process_creation_event_ids: The set of EVTX Event IDs
                considered process-creation evidence.
        """
        self._time_window = time_window
        self._process_creation_event_ids = process_creation_event_ids

    def evaluate(self, context: CorrelationContext) -> list[CorrelationFinding]:
        if not context.evtx_entries:
            # No EVTX data was provided at all, so "no matching event
            # found" would be true of every single Prefetch execution --
            # this rule stays silent rather than flagging every recorded
            # execution just because nothing was loaded to check against.
            return []

        candidate_events = [
            entry
            for entry in context.evtx_entries
            if entry.record.event_id in self._process_creation_event_ids
            and entry.record.timestamp is not None
        ]

        findings: list[CorrelationFinding] = []
        for prefetch_entry in context.prefetch_entries:
            record = prefetch_entry.record
            if not record.executable_name:
                continue
            for run_time in record.last_run_times:
                if self._has_matching_event(record.executable_name, run_time, candidate_events):
                    continue
                findings.append(
                    CorrelationFinding(
                        rule_name=self.rule_name,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Prefetch shows '{record.executable_name}' executed at "
                            f"{run_time.isoformat()}, but no matching EVTX "
                            f"process-creation event was found within "
                            f"{self._time_window}."
                        ),
                        evidence=(
                            f"Prefetch source: {prefetch_entry.source_path}",
                            f"Run timestamp: {run_time.isoformat()}",
                        ),
                        source_paths=(prefetch_entry.source_path,),
                    )
                )
        return findings

    def _has_matching_event(
        self,
        executable_name: str,
        run_time: datetime,
        candidate_events: list[EvtxEntry],
    ) -> bool:
        """Check whether any candidate EVTX event corroborates a run timestamp.

        Args:
            executable_name: The Prefetch executable name to search
                for.
            run_time: The Prefetch run timestamp to match against.
            candidate_events: EVTX entries already filtered to
                process-creation event IDs with a known timestamp.

        Returns:
            ``True`` if a matching event was found, ``False``
            otherwise.
        """
        name_lower = executable_name.lower()
        window_start = run_time - self._time_window
        window_end = run_time + self._time_window
        for entry in candidate_events:
            timestamp = entry.record.timestamp
            if timestamp is None or not window_start <= timestamp <= window_end:
                continue
            message = (entry.record.message or "").lower()
            if name_lower in message:
                return True
        return False


class RegistryPersistenceWithoutExecutionRule(
    CorrelationRule
):  # pylint: disable=too-few-public-methods
    """Flags registry run-key persistence with no supporting Prefetch evidence.

    For each registry value under a known persistence key path (Run,
    RunOnce, etc.) whose data references an executable, this rule
    checks whether any Prefetch record shows that executable having
    ever run. A persistence entry with no execution evidence may
    indicate the entry was recently planted and hasn't fired yet, or
    that the corresponding Prefetch file was deliberately deleted to
    hide execution (Prefetch deletion/disabling is a well-known
    anti-forensic technique).

    Note:
        This rule flags an *absence* of evidence, which is inherently
        weaker than flagging a positive contradiction — a program
        genuinely may not have run yet. Treat findings as leads for
        further investigation (e.g. checking install timestamps),
        not confirmed tampering.
    """

    rule_name = "persistence_without_execution"

    def __init__(
        self,
        persistence_key_segments: tuple[str, ...] = _DEFAULT_PERSISTENCE_KEY_SEGMENTS,
    ) -> None:
        """Initialize the rule.

        Args:
            persistence_key_segments: Key-path segment names (matched
                case-insensitively as a full path component, e.g.
                ``"Run"`` matches ``...\\Run\\Foo`` but not
                ``...\\RunAs\\Foo``) that identify a run-at-startup
                persistence location.
        """
        self._persistence_key_segments = frozenset(
            s.lower() for s in persistence_key_segments
        )

    def evaluate(self, context: CorrelationContext) -> list[CorrelationFinding]:
        if not context.prefetch_entries:
            # No Prefetch data was provided at all, so "no execution
            # evidence found" would be true of every single persistence
            # entry -- including completely benign ones -- and wouldn't
            # reflect anything about the entries themselves. Firing here
            # would mean "we never checked," not "we checked and found
            # nothing," so this rule stays silent rather than producing
            # findings that carry no real information.
            return []

        executed_names = {
            entry.record.executable_name.lower()
            for entry in context.prefetch_entries
            if entry.record.executable_name and entry.record.run_count
        }

        findings: list[CorrelationFinding] = []
        for entry in context.registry_value_entries:
            if not self._is_persistence_key(entry.value.key_path):
                continue
            exe_name = self._extract_exe_name(entry.value.data)
            if exe_name is None:
                continue
            if exe_name.lower() in executed_names:
                continue
            findings.append(
                CorrelationFinding(
                    rule_name=self.rule_name,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Registry persistence entry '{entry.value.key_path}\\"
                        f"{entry.value.name or '(default)'}' references "
                        f"'{exe_name}', but no Prefetch evidence of it ever "
                        f"executing was found."
                    ),
                    evidence=(
                        f"Registry source: {entry.source_path}",
                        f"Key path: {entry.value.key_path}",
                        f"Value data: {entry.value.data!r}",
                    ),
                    source_paths=(entry.source_path,),
                )
            )
        return findings

    def _is_persistence_key(self, key_path: str) -> bool:
        """Check whether a key path contains a known persistence key segment.

        Uses exact per-segment matching (splitting on backslash), not
        substring containment -- so ``"...\\Run\\Foo"`` matches but
        ``"...\\RunAs\\Foo"`` does not, even though the latter
        contains ``"Run"`` as a raw substring.

        Args:
            key_path: The registry key path to check.

        Returns:
            ``True`` if any path segment exactly matches (case-insensitively)
            one of the configured persistence key segment names.
        """
        segments = (s.lower() for s in key_path.split("\\"))
        return any(segment in self._persistence_key_segments for segment in segments)

    @staticmethod
    def _extract_exe_name(value_data: object) -> str | None:
        """Extract an ``something.exe`` reference from registry value data.

        Args:
            value_data: The raw value data (typically a string
                command line for persistence entries).

        Returns:
            The referenced executable's filename (no path), or
            ``None`` if no ``.exe`` reference was found.
        """
        if not isinstance(value_data, str):
            return None
        match = _EXE_REFERENCE_PATTERN.search(value_data)
        return match.group(1) if match else None


class PrefetchFilenameHashMismatchRule(CorrelationRule):  # pylint: disable=too-few-public-methods
    """Flags Prefetch files whose filename hash doesn't match their embedded hash.

    Surfaces the single-artifact consistency check already performed
    by ``prefetch.py`` (see
    :attr:`prefetch.PrefetchRecord.filename_hash_matches`) as a
    correlation finding, so it appears alongside cross-artifact
    findings in one unified report. A mismatch is a strong indicator
    that the ``.pf`` file was renamed or tampered with after the
    operating system created it.
    """

    rule_name = "prefetch_filename_hash_mismatch"

    def evaluate(self, context: CorrelationContext) -> list[CorrelationFinding]:
        findings: list[CorrelationFinding] = []
        for entry in context.prefetch_entries:
            if entry.record.filename_hash_matches is not False:
                continue
            findings.append(
                CorrelationFinding(
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    description=(
                        f"Prefetch file '{Path(entry.source_path).name}' has a "
                        f"filename hash that does not match its embedded "
                        f"prefetch hash ({entry.record.prefetch_hash}). This "
                        f"suggests the file was renamed or tampered with."
                    ),
                    evidence=(
                        f"Prefetch source: {entry.source_path}",
                        f"Embedded hash: {entry.record.prefetch_hash}",
                    ),
                    source_paths=(entry.source_path,),
                )
            )
        return findings


class EvtxRecordNumberGapRule(CorrelationRule):  # pylint: disable=too-few-public-methods
    """Flags gaps in EVTX record number sequences within a single log file.

    EVTX record numbers are assigned sequentially. A gap in the
    sequence can indicate normal log rotation/overwrite behavior, but
    can also indicate selective record wiping by an anti-forensic
    tool. In practice, small (often size-1) gaps are extremely common
    in normal Windows telemetry -- Operational/Diagnostic channels in
    particular routinely skip record numbers for filtered or
    unlogged event types, with no forensic significance at all.
    Reporting every such gap as its own finding buries any genuinely
    suspicious gap in noise and trains analysts to ignore this rule.

    To keep the signal meaningful, this rule distinguishes two cases:

    - Gaps at or above ``significant_gap_size`` are reported
      individually at MEDIUM severity -- a run of several
      consecutive missing records is much less consistent with
      routine filtering and more worth a specific look.
    - Smaller gaps are aggregated into a single INFO-severity summary
      finding per source file (count, total records missing, largest
      gap seen), so the information isn't hidden entirely but also
      doesn't dominate the findings list.
    """

    rule_name = "evtx_record_number_gap"

    def __init__(self, significant_gap_size: int = 10) -> None:
        """Initialize the rule.

        Args:
            significant_gap_size: The minimum number of consecutive
                missing record numbers required to report a gap as
                its own individual finding. Gaps smaller than this
                are aggregated into one summary finding per file
                instead. Defaults to 10.
        """
        self._significant_gap_size = significant_gap_size

    def evaluate(self, context: CorrelationContext) -> list[CorrelationFinding]:
        by_source: dict[str, list[int]] = {}
        for entry in context.evtx_entries:
            by_source.setdefault(entry.source_path, []).append(entry.record.record_number)

        findings: list[CorrelationFinding] = []
        for source_path, record_numbers in by_source.items():
            findings.extend(self._evaluate_source(source_path, record_numbers))
        return findings

    def _evaluate_source(
        self, source_path: str, record_numbers: list[int]
    ) -> list[CorrelationFinding]:
        """Evaluate gaps within a single source file's record numbers.

        Args:
            source_path: The EVTX file these record numbers came from.
            record_numbers: The record numbers found in that file.

        Returns:
            Individual findings for significant gaps, plus at most
            one aggregated summary finding for smaller gaps.
        """
        record_numbers = sorted(record_numbers)
        findings: list[CorrelationFinding] = []
        minor_gaps: list[tuple[int, int, int]] = []  # (previous, current, gap_size)

        for previous, current in itertools.pairwise(record_numbers):
            gap_size = current - previous - 1
            if gap_size <= 0:
                continue
            if gap_size >= self._significant_gap_size:
                findings.append(self._build_significant_finding(source_path, previous, current))
            else:
                minor_gaps.append((previous, current, gap_size))

        if minor_gaps:
            findings.append(self._build_summary_finding(source_path, minor_gaps))
        return findings

    def _build_significant_finding(
        self, source_path: str, previous: int, current: int
    ) -> CorrelationFinding:
        """Build an individual finding for a single significant gap.

        Args:
            source_path: The EVTX file this gap was found in.
            previous: The record number immediately before the gap.
            current: The record number immediately after the gap.

        Returns:
            The populated :class:`CorrelationFinding`.
        """
        gap_size = current - previous - 1
        return CorrelationFinding(
            rule_name=self.rule_name,
            severity=Severity.MEDIUM,
            description=(
                f"EVTX record number gap in '{Path(source_path).name}': "
                f"{gap_size} consecutive missing record(s) between "
                f"#{previous} and #{current}. A gap this large is less "
                f"consistent with routine channel filtering and may "
                f"warrant a closer look."
            ),
            evidence=(
                f"EVTX source: {source_path}",
                f"Gap range: {previous + 1}-{current - 1}",
            ),
            source_paths=(source_path,),
        )

    def _build_summary_finding(
        self, source_path: str, minor_gaps: list[tuple[int, int, int]]
    ) -> CorrelationFinding:
        """Build one aggregated finding summarizing routine small gaps.

        Args:
            source_path: The EVTX file these gaps were found in.
            minor_gaps: The ``(previous, current, gap_size)`` tuples
                for every gap below the significance threshold.

        Returns:
            A single INFO-severity :class:`CorrelationFinding`
            summarizing all minor gaps in this file.
        """
        total_missing = sum(gap_size for _, _, gap_size in minor_gaps)
        largest = max(gap_size for _, _, gap_size in minor_gaps)
        return CorrelationFinding(
            rule_name=self.rule_name,
            severity=Severity.INFO,
            description=(
                f"EVTX record number gaps in '{Path(source_path).name}': "
                f"{len(minor_gaps)} small gap(s) totaling {total_missing} "
                f"missing record(s) (largest single gap: {largest}). "
                f"Small, scattered gaps like this are common in "
                f"Operational/Diagnostic channels and are usually routine "
                f"log behavior rather than tampering."
            ),
            evidence=tuple(
                f"Gap range: {previous + 1}-{current - 1} ({gap_size} missing)"
                for previous, current, gap_size in minor_gaps[:10]
            )
            + ((f"... and {len(minor_gaps) - 10} more",) if len(minor_gaps) > 10 else ()),
            source_paths=(source_path,),
        )


class MftTimestompingRule(CorrelationRule):  # pylint: disable=too-few-public-methods
    """Flags MFT records with $STANDARD_INFORMATION/$FILE_NAME timestamp anomalies.

    Surfaces the single-artifact timestomping detection already
    performed by ``mft.py`` (see
    :attr:`mft.MftRecord.likely_timestomped`) as a correlation
    finding, so it appears alongside cross-artifact findings in one
    unified report rather than requiring a separate MFT-specific
    workflow.
    """

    rule_name = "mft_timestomping_detected"

    def evaluate(self, context: CorrelationContext) -> list[CorrelationFinding]:
        findings: list[CorrelationFinding] = []
        for entry in context.mft_entries:
            record = entry.record
            if not record.likely_timestomped:
                continue
            findings.append(
                CorrelationFinding(
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    description=(
                        f"MFT record #{record.record_number} "
                        f"('{record.filename}') has $STANDARD_INFORMATION "
                        f"timestamp(s) that predate its $FILE_NAME creation "
                        f"time -- indicating timestomping."
                    ),
                    evidence=(
                        f"Anomalous fields: {', '.join(record.timestamp_anomalies)}",
                    ),
                    source_paths=(entry.source_path,),
                )
            )
        return findings


DEFAULT_RULES: tuple[CorrelationRule, ...] = (
    PrefetchExecutionWithoutEvtxRule(),
    RegistryPersistenceWithoutExecutionRule(),
    PrefetchFilenameHashMismatchRule(),
    EvtxRecordNumberGapRule(),
    MftTimestompingRule(),
)


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


class CorrelationEngine:  # pylint: disable=too-few-public-methods
    """Runs a configurable set of correlation rules against a context.

    Note:
        This class exposes a single public entry point (``run``)
        backed by a private helper method — a deliberate
        single-responsibility design, so
        ``too-few-public-methods`` is intentionally suppressed here.

    Each rule is run in isolation: if one rule raises an unexpected
    exception, it is logged and skipped so the remaining rules still
    run, consistent with the resilience philosophy used throughout
    Corrobora's parsers.

    Attributes:
        rules: The rules this engine will run, in order.

    Example:
        >>> engine = CorrelationEngine()  # uses DEFAULT_RULES
        >>> findings = engine.run(context)

        >>> # Or with a custom rule set:
        >>> engine = CorrelationEngine(rules=[PrefetchFilenameHashMismatchRule()])
        >>> findings = engine.run(context)
    """

    def __init__(self, rules: list[CorrelationRule] | None = None) -> None:
        """Initialize the engine.

        Args:
            rules: The correlation rules to run. Defaults to
                :data:`DEFAULT_RULES` if not provided.
        """
        self.rules = rules if rules is not None else list(DEFAULT_RULES)

    def run(self, context: CorrelationContext) -> list[CorrelationFinding]:
        """Run all configured rules against a context and aggregate findings.

        Args:
            context: The parsed artifacts to check.

        Returns:
            All findings from all rules, sorted by severity
            (highest first).
        """
        all_findings: list[CorrelationFinding] = []
        for rule in self.rules:
            all_findings.extend(self._run_rule_safely(rule, context))

        all_findings.sort(key=lambda f: _SEVERITY_ORDER[f.severity], reverse=True)
        logger.info("Correlation run complete: %d finding(s).", len(all_findings))
        return all_findings

    @staticmethod
    def _run_rule_safely(
        rule: CorrelationRule, context: CorrelationContext
    ) -> list[CorrelationFinding]:
        """Run a single rule, isolating any unexpected failure.

        Args:
            rule: The rule to run.
            context: The parsed artifacts to check.

        Returns:
            The rule's findings, or an empty list if the rule raised
            an unexpected exception.
        """
        try:
            findings = rule.evaluate(context)
        except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
            # Deliberately broad: isolates a single rule's failure so the
            # rest of the correlation run still completes.
            logger.warning("Rule '%s' failed and was skipped: %s", rule.rule_name, exc)
            return []
        logger.debug("Rule '%s' produced %d finding(s).", rule.rule_name, len(findings))
        return findings


# --------------------------------------------------------------------------
# Context building
# --------------------------------------------------------------------------


def load_evtx_entries(paths: list[str | Path]) -> list[EvtxEntry]:
    """Parse EVTX files and tag each record with its source path.

    Files that fail to open entirely are logged and skipped, matching
    the resilience philosophy of ``evtx.py``.

    Args:
        paths: Paths to ``.evtx`` files.

    Returns:
        All successfully extracted records, tagged with source.
    """
    entries: list[EvtxEntry] = []
    for path in paths:
        parser = EvtxParser(path)
        try:
            records = parser.parse()
        except EvtxFileError as exc:
            logger.error("Skipping EVTX file '%s': %s", path, exc)
            continue
        entries.extend(EvtxEntry(source_path=str(path), record=r) for r in records)
    return entries


def load_registry_value_entries(paths: list[str | Path]) -> list[RegistryValueEntry]:
    """Parse registry hive files and tag each value with its source path.

    Files that fail to open entirely are logged and skipped, matching
    the resilience philosophy of ``registry.py``.

    Args:
        paths: Paths to registry hive files.

    Returns:
        All successfully extracted values, tagged with source.
    """
    entries: list[RegistryValueEntry] = []
    for path in paths:
        parser = RegistryHiveParser(path)
        try:
            _keys, values = parser.parse()
        except RegistryFileError as exc:
            logger.error("Skipping registry file '%s': %s", path, exc)
            continue
        entries.extend(RegistryValueEntry(source_path=str(path), value=v) for v in values)
    return entries


def load_prefetch_entries(paths: list[str | Path]) -> list[PrefetchEntry]:
    """Parse Prefetch files or folders and tag each record with its source path.

    Each path may be an individual ``.pf`` file or a folder
    containing ``.pf`` files (folders are expanded via
    ``prefetch.parse_folder``). Files/folders that fail are logged
    and skipped, matching the resilience philosophy of ``prefetch.py``.

    Args:
        paths: Paths to ``.pf`` files and/or folders of ``.pf`` files.

    Returns:
        All successfully extracted records, tagged with source.
    """
    entries: list[PrefetchEntry] = []
    for path in paths:
        path_obj = Path(path)
        if path_obj.is_dir():
            try:
                results = parse_prefetch_folder(path_obj)
            except PrefetchFileError as exc:
                logger.error("Skipping Prefetch folder '%s': %s", path, exc)
                continue
            for file_path, record in results.items():
                entries.append(PrefetchEntry(source_path=str(file_path), record=record))
        else:
            parser = PrefetchParser(path_obj)
            try:
                record = parser.parse()
            except PrefetchFileError as exc:
                logger.error("Skipping Prefetch file '%s': %s", path, exc)
                continue
            entries.append(PrefetchEntry(source_path=str(path_obj), record=record))
    return entries


def load_mft_entries(paths: list[str | Path]) -> list[MftEntry]:
    """Parse raw ``$MFT`` files and tag each record with its source path.

    Files that fail to open entirely are logged and skipped, matching
    the resilience philosophy of ``mft.py``.

    Args:
        paths: Paths to raw ``$MFT`` files.

    Returns:
        All successfully extracted records, tagged with source.
    """
    entries: list[MftEntry] = []
    for path in paths:
        parser = MftParser(path)
        try:
            records = parser.parse()
        except MftFileError as exc:
            logger.error("Skipping MFT file '%s': %s", path, exc)
            continue
        entries.extend(MftEntry(source_path=str(path), record=r) for r in records)
    return entries


def build_context(
    evtx_paths: list[str | Path] | None = None,
    registry_paths: list[str | Path] | None = None,
    prefetch_paths: list[str | Path] | None = None,
    mft_paths: list[str | Path] | None = None,
) -> CorrelationContext:
    """Parse the given source files and build a :class:`CorrelationContext`.

    This is a convenience wrapper around :func:`load_evtx_entries`,
    :func:`load_registry_value_entries`, :func:`load_prefetch_entries`,
    and :func:`load_mft_entries`. Individual file failures are logged
    and skipped rather than raised, so a single unreadable artifact
    does not prevent correlation from running against the rest of
    the evidence.

    Args:
        evtx_paths: Paths to ``.evtx`` files. Defaults to none.
        registry_paths: Paths to registry hive files. Defaults to
            none.
        prefetch_paths: Paths to ``.pf`` files and/or folders of
            ``.pf`` files. Defaults to none.
        mft_paths: Paths to raw ``$MFT`` files. Defaults to none.

    Returns:
        The populated :class:`CorrelationContext`.
    """
    return CorrelationContext(
        evtx_entries=tuple(load_evtx_entries(evtx_paths or [])),
        registry_value_entries=tuple(load_registry_value_entries(registry_paths or [])),
        prefetch_entries=tuple(load_prefetch_entries(prefetch_paths or [])),
        mft_entries=tuple(load_mft_entries(mft_paths or [])),
    )


# --------------------------------------------------------------------------
# Command-line entry point
# --------------------------------------------------------------------------


def _main() -> None:
    """Run the correlation engine as a script.

    Usage:
        python correlation_engine.py --evtx FILE [FILE ...]
            --registry FILE [FILE ...] --prefetch PATH [PATH ...]
            --mft FILE [FILE ...]

    Any of ``--evtx``, ``--registry``, ``--prefetch``, or ``--mft``
    may be omitted if that artifact type isn't available; rules that
    depend on missing artifact types simply won't find anything to
    flag.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="correlation_engine.py",
        description="Cross-reference EVTX, Registry, Prefetch, and MFT artifacts "
        "to surface anti-forensic indicators.",
    )
    parser.add_argument("--evtx", nargs="*", default=[], metavar="FILE", help=".evtx file(s).")
    parser.add_argument(
        "--registry", nargs="*", default=[], metavar="FILE", help="Registry hive file(s)."
    )
    parser.add_argument(
        "--prefetch",
        nargs="*",
        default=[],
        metavar="PATH",
        help=".pf file(s) and/or folder(s) of .pf files.",
    )
    parser.add_argument(
        "--mft", nargs="*", default=[], metavar="FILE", help="Raw $MFT file(s)."
    )
    args = parser.parse_args()

    if not (args.evtx or args.registry or args.prefetch or args.mft):
        parser.error(
            "At least one of --evtx, --registry, --prefetch, or --mft is required."
        )

    context = build_context(
        evtx_paths=args.evtx,
        registry_paths=args.registry,
        prefetch_paths=args.prefetch,
        mft_paths=args.mft,
    )
    logger.info(
        "Loaded %d EVTX record(s), %d registry value(s), %d Prefetch record(s), "
        "%d MFT record(s).",
        len(context.evtx_entries),
        len(context.registry_value_entries),
        len(context.prefetch_entries),
        len(context.mft_entries),
    )

    engine = CorrelationEngine()
    findings = engine.run(context)

    if not findings:
        logger.info("No findings.")
        return

    for finding in findings:
        logger.info(
            "[%s] %s: %s", finding.severity.value.upper(), finding.rule_name, finding.description
        )

    counts: dict[Severity, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(f"{sev.value}={count}" for sev, count in counts.items())
    logger.info("Summary: %d total finding(s) (%s).", len(findings), summary)


if __name__ == "__main__":
    _main()