"""Corrobora Correlation Engine — orchestration module.

Cross-references parsed EVTX, Registry, Prefetch, and MFT artifacts to
surface indicators of anti-forensic activity that no single artifact
reveals on its own. This is the core analytical layer of the
Corrobora digital forensics framework: individual parsers extract
data faithfully, but tampering is often only visible as a
*disagreement* between two independent sources of evidence — e.g. a
program with Prefetch evidence of execution but no corresponding
EVTX process-creation event, or registry persistence with no
supporting execution evidence at all.

Design:
    Detection logic itself lives in :mod:`corrobora.rules` as small,
    independently testable ``CorrelationRule`` subclasses grouped by
    category (``program_execution``, ``persistence``, ``integrity``),
    with :data:`corrobora.rules.rule_registry.RULE_REGISTRY` as the
    single source of truth for which rules exist. This module stays
    focused on orchestration: building a :class:`CorrelationContext`
    from source files and running a configured set of rules against
    it. It re-exports the rules-layer data model and rule classes so
    existing importers keep working unchanged. This module
    intentionally contains no AI or machine learning; every rule is
    deterministic and explainable.

This module is self-contained but depends on Corrobora's other
single-file parser modules (``evtx.py``, ``registry.py``,
``prefetch.py``, ``mft.py``) and on :mod:`corrobora.rules` being
importable from the same location.

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

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from ..rules.base import (
    CorrelationContext,
    CorrelationFinding,
    CorrelationRule,
    EvtxEntry,
    MftEntry,
    PrefetchEntry,
    RegistryValueEntry,
    Severity,
    SEVERITY_ORDER,
)
from ..rules.integrity.evtx_record_gap import EvtxRecordNumberGapRule
from ..rules.integrity.mft_timestomping import MftTimestompingRule
from ..rules.integrity.prefetch_hash_mismatch import PrefetchFilenameHashMismatchRule
from ..rules.persistence.registry_vs_prefetch import RegistryPersistenceWithoutExecutionRule
from ..rules.program_execution.prefetch_vs_evtx import PrefetchExecutionWithoutEvtxRule
from ..rules.rule_registry import DEFAULT_RULES
from .evtx import EvtxFileError, EvtxParser
from .mft import MftFileError, MftParser
from .prefetch import (
    PrefetchFileError,
    PrefetchParser,
)
from .prefetch import (
    parse_folder as parse_prefetch_folder,
)
from .registry import RegistryFileError, RegistryHiveParser

__all__ = [
    "CorrelationContext",
    "CorrelationEngine",
    "CorrelationFinding",
    "CorrelationRule",
    "DEFAULT_RULES",
    "EvtxEntry",
    "EvtxRecordNumberGapRule",
    "MftEntry",
    "MftTimestompingRule",
    "PrefetchEntry",
    "PrefetchExecutionWithoutEvtxRule",
    "PrefetchFilenameHashMismatchRule",
    "RegistryPersistenceWithoutExecutionRule",
    "RegistryValueEntry",
    "Severity",
    "build_context",
    "load_evtx_entries",
    "load_registry_value_entries",
    "load_prefetch_entries",
    "load_mft_entries",
]

logger = logging.getLogger(__name__)


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

        all_findings.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
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
