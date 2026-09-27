"""Command-line entry point for program-execution corroboration.

Point it at a case (a folder, a ``.zip`` of one, or a disk image, via
:func:`~corrobora.parsers.case_ingest.load_case`), choose a correlation
window, and optionally name one or more programs::

    corrobora-corroborate C:\\cases\\case001 --window 300 --subject powershell.exe

With ``--subject``, a full report is printed for each named program.
Without it, a one-line summary is printed for every program that has
execution evidence.

What is examined, and why:

- **Prefetch:** every discovered ``.pf`` file.
- **EVTX:** by default only logs that can hold the process-creation
  events the extractor understands: files named ``Security.evtx`` and
  files whose name contains ``sysmon``. Parsing every log in a full
  triage collection can take a long time; ``--all-evtx`` parses them
  all. Either way, the files examined are listed in the output.
- **Registry:** only ``SYSTEM`` hives, since BAM/DAM live there. The
  hive's ``Select`` key names the control sets in use, and only their
  ``Services\\bam`` and ``Services\\dam`` subtrees are walked. Other
  hives are not examined.

A source counts as examined only if at least one of its files parsed
successfully. Files that fail to parse are reported, not silently
dropped, and do not stop the analysis.
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from corrobora.correlation.program_execution import (
    SOURCE_LABELS,
    ProgramExecutionFinding,
    correlate_all_program_execution,
    correlate_program_execution,
)
from corrobora.correlation.report import STATUS_LABELS, render_program_execution_report
from corrobora.extractors.evtx import extract_evtx_evidence
from corrobora.extractors.prefetch import extract_prefetch_evidence
from corrobora.extractors.registry import extract_registry_evidence
from corrobora.models.evidence import EvidenceRecord, normalize_executable_name
from corrobora.parsers.Base import ArtifactType
from corrobora.parsers.case_ingest import DiscoveredArtifacts, InvalidCasePathError, load_case
from corrobora.parsers.evtx import EvtxParser
from corrobora.parsers.prefetch import PrefetchParser
from corrobora.parsers.registry import RegistryHiveParser, RegistryValue

logger = logging.getLogger(__name__)

_SELECT_CONTROL_SET_VALUES = ("Current", "Default", "LastKnownGood")
_MODERATOR_SERVICES = ("bam", "dam")


# --------------------------------------------------------------------------
# Evidence collection
# --------------------------------------------------------------------------


@dataclass
class SourceCollection:
    """What happened when one artifact source was collected.

    Attributes:
        parsed: Files that parsed successfully.
        failed: ``(file, reason)`` for each file that failed to parse.
        skipped: Files discovered for this source but deliberately not
            examined (e.g. EVTX logs outside the default selection).
    """

    parsed: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


@dataclass
class CollectionResult:
    """Evidence gathered from a case, plus an account of how.

    Attributes:
        records: All extracted evidence.
        sources: Per-source collection details, keyed by artifact type.
    """

    records: list[EvidenceRecord] = field(default_factory=list)
    sources: dict[ArtifactType, SourceCollection] = field(
        default_factory=lambda: {
            ArtifactType.PREFETCH: SourceCollection(),
            ArtifactType.EVTX: SourceCollection(),
            ArtifactType.REGISTRY: SourceCollection(),
        }
    )

    @property
    def examined(self) -> set[ArtifactType]:
        """Sources with at least one successfully parsed file."""
        return {source for source, info in self.sources.items() if info.parsed}


def collect_evidence(artifacts: DiscoveredArtifacts, all_evtx: bool = False) -> CollectionResult:
    """Parse a case's artifacts and extract program-execution evidence.

    Args:
        artifacts: Artifact files discovered in the case.
        all_evtx: Parse every ``.evtx`` file rather than only Security and
            Sysmon logs.

    Returns:
        The extracted evidence and a per-source account of which files
        were parsed, failed, or skipped.
    """
    result = CollectionResult()

    _collect(
        artifacts.prefetch_paths,
        result.sources[ArtifactType.PREFETCH],
        result.records,
        lambda path: extract_prefetch_evidence(PrefetchParser(path).parse()),
    )

    evtx_info = result.sources[ArtifactType.EVTX]
    selected_evtx = []
    for path in artifacts.evtx_paths:
        if all_evtx or _is_process_creation_log(path):
            selected_evtx.append(path)
        else:
            evtx_info.skipped.append(path)
    _collect(selected_evtx, evtx_info, result.records, _extract_evtx_file)

    registry_info = result.sources[ArtifactType.REGISTRY]
    system_hives = []
    for path in artifacts.registry_paths:
        if Path(path).name.lower() == "system":
            system_hives.append(path)
        else:
            registry_info.skipped.append(path)
    _collect(system_hives, registry_info, result.records, _extract_system_hive)

    return result


def _collect(
    paths: Sequence[str],
    info: SourceCollection,
    records: list[EvidenceRecord],
    extract: Callable[[str], list[EvidenceRecord]],
) -> None:
    for path in paths:
        try:
            extracted = extract(path)
        except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
            # Deliberately broad: one unreadable or corrupt artifact file
            # must not abort analysis of the rest of the case. The failure
            # is recorded and shown to the examiner.
            logger.warning("Could not parse '%s': %s", path, exc)
            info.failed.append((path, str(exc)))
            continue
        info.parsed.append(path)
        records.extend(extracted)


def _is_process_creation_log(path: str) -> bool:
    name = Path(path).name.lower()
    return name == "security.evtx" or "sysmon" in name


def _extract_evtx_file(path: str) -> list[EvidenceRecord]:
    evidence: list[EvidenceRecord] = []
    for record in EvtxParser(path).parse():
        evidence.extend(extract_evtx_evidence(record, path))
    return evidence


def _extract_system_hive(path: str) -> list[EvidenceRecord]:
    """Extract BAM/DAM evidence from one SYSTEM hive.

    Raises:
        RegistryFileError: If the hive cannot be opened or has no
            ``Select`` key (i.e. it is not a readable SYSTEM hive).
    """
    parser = RegistryHiveParser(path)
    _, select_values = parser.parse(root_path="Select")
    evidence: list[EvidenceRecord] = []
    for control_set in _control_sets(select_values):
        for service in _MODERATOR_SERVICES:
            root_path = f"{control_set}\\Services\\{service}"
            try:
                _, values = parser.parse(root_path=root_path)
            except Exception:  # noqa: BLE001 pylint: disable=broad-exception-caught
                # Absent on Windows versions without BAM/DAM, and DAM is
                # absent on most systems: a missing key is not a failure.
                logger.debug("No '%s' key in '%s'", root_path, path)
                continue
            for value in values:
                evidence.extend(extract_registry_evidence(value, path))
    return evidence


def _control_sets(select_values: list[RegistryValue]) -> list[str]:
    """Return the distinct ``ControlSetNNN`` names referenced by ``Select``."""
    numbers: list[int] = []
    for value in select_values:
        if value.name in _SELECT_CONTROL_SET_VALUES and isinstance(value.data, int):
            if value.data > 0 and value.data not in numbers:
                numbers.append(value.data)
    return [f"ControlSet{number:03d}" for number in numbers]


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def render_collection_summary(
    case: str, window: timedelta, collection: CollectionResult, mft_count: int
) -> str:
    """Describe what was examined, so every result can be read in context.

    Args:
        case: The case path given on the command line.
        window: The configured correlation window.
        collection: The collection result.
        mft_count: Number of MFT files discovered (not used by this
            analysis, but listed so their omission is visible).

    Returns:
        The summary text, ending with a newline.
    """
    lines = [
        "CORROBORA",
        "Program Execution Corroboration",
        "",
        f"Case: {case}",
        f"Correlation window: {int(window.total_seconds())} seconds "
        "(configured; not a validated forensic threshold)",
        "",
        "Sources",
    ]
    notes = {
        ArtifactType.EVTX: "other .evtx file(s) not examined (use --all-evtx)",
        ArtifactType.REGISTRY: "non-SYSTEM hive(s) not examined (no BAM/DAM)",
    }
    for source, info in collection.sources.items():
        label = SOURCE_LABELS[source]
        status = "examined" if info.parsed else "NOT examined"
        lines.append(
            f"  {label}: {status} -- {len(info.parsed)} file(s) parsed, "
            f"{len(info.failed)} failed"
        )
        for path in info.parsed:
            lines.append(f"      parsed: {path}")
        for path, reason in info.failed:
            lines.append(f"      failed: {path} ({reason})")
        if info.skipped:
            lines.append(f"      {len(info.skipped)} {notes[source]}")
    if mft_count:
        lines.append(f"  MFT: {mft_count} file(s) found; not used by this analysis")
    return "\n".join(lines) + "\n"


def render_subject_summary(findings: list[ProgramExecutionFinding]) -> str:
    """Render one line per subject: result and the sources that agree.

    Args:
        findings: Findings to summarize.

    Returns:
        The summary table, ending with a newline.
    """
    if not findings:
        return "No program-execution evidence was found in the examined sources.\n"
    width = max(len("Subject"), *(len(f.subject) for f in findings))
    status_width = max(len(label) for label in STATUS_LABELS.values())
    lines = [f"{'Subject':<{width}}  {'Result':<{status_width}}  Sources in window"]
    for finding in findings:
        agreeing = ", ".join(s.label for s in finding.sources if s.in_window) or "-"
        status = STATUS_LABELS[finding.status]
        lines.append(f"{finding.subject:<{width}}  {status:<{status_width}}  {agreeing}")
    lines += [
        "",
        "Run again with --subject <name> for a full report on a program.",
        "Results short of CORROBORATED do not establish deletion or "
        "anti-forensic activity. Examiner review is required.",
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def _positive_seconds(text: str) -> timedelta:
    try:
        seconds = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a whole number of seconds: {text!r}") from exc
    if seconds <= 0:
        raise argparse.ArgumentTypeError("window must be a positive number of seconds")
    return timedelta(seconds=seconds)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="corrobora-corroborate",
        description=(
            "Assess whether independent artifact sources (Prefetch, EVTX, "
            "Registry BAM/DAM) corroborate program execution."
        ),
    )
    parser.add_argument("case", help="A case folder, a .zip of one, or a disk image.")
    parser.add_argument(
        "--window",
        type=_positive_seconds,
        required=True,
        metavar="SECONDS",
        help=(
            "Maximum spread, in seconds, between timestamps counted as agreeing. "
            "Required: there is no validated default."
        ),
    )
    parser.add_argument(
        "--subject",
        action="append",
        metavar="NAME",
        help=(
            "Program to report on (e.g. powershell.exe). Repeatable. "
            "Omit to summarize every program with execution evidence."
        ),
    )
    parser.add_argument(
        "--all-evtx",
        action="store_true",
        help="Parse every .evtx file, not only Security and Sysmon logs.",
    )
    parser.add_argument("--verbose", action="store_true", help="Show parser progress logging.")
    return parser


def _main(argv: Sequence[str] | None = None) -> int:
    """Run program-execution corroboration from the command line.

    Args:
        argv: Arguments (without the program name); ``None`` uses
            ``sys.argv``.

    Returns:
        The process exit code: 0 on success, 1 if the case cannot be
        loaded.
    """
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        artifacts = load_case(args.case)
    except InvalidCasePathError as exc:
        logger.error("Could not load case: %s", exc)
        return 1

    collection = collect_evidence(artifacts, all_evtx=args.all_evtx)
    print(render_collection_summary(args.case, args.window, collection, len(artifacts.mft_paths)))

    if not args.subject:
        findings = correlate_all_program_execution(
            collection.records, collection.examined, args.window
        )
        print(render_subject_summary(findings), end="")
        return 0

    for raw_subject in args.subject:
        subject = normalize_executable_name(raw_subject)
        finding = correlate_program_execution(
            collection.records, subject, collection.examined, args.window
        )
        print("=" * 48)
        if finding is None:
            print(f"\nNo execution evidence for {subject} was found in the examined sources.\n")
        else:
            print()
            print(render_program_execution_report(finding))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
