"""Build execution evidence from an already-parsed correlation context.

The command line (:mod:`corrobora.correlation.cli`) parses artifact files
itself. The GUI instead parses every selected file once into a
:class:`~corrobora.rules.base.CorrelationContext` for the rule engine;
this module extracts program-execution evidence from that same context so
the files are not parsed twice.

"Examined" follows the command line's rules, so both report the same
sources for the same inputs:

- **Prefetch:** examined if any Prefetch record was loaded.
- **EVTX:** examined only if records were loaded from a log that can hold
  process-creation events (``Security.evtx`` or a Sysmon log); other logs
  cannot contain the evidence the extractor looks for.
- **Registry:** examined only if values were loaded from a ``SYSTEM``
  hive, where BAM/DAM live.
"""

from __future__ import annotations

from pathlib import Path

from corrobora.extractors.evtx import extract_evtx_evidence
from corrobora.extractors.prefetch import extract_prefetch_evidence
from corrobora.extractors.registry import extract_registry_evidence
from corrobora.models.evidence import EvidenceRecord
from corrobora.parsers.Base import ArtifactType
from corrobora.rules.base import CorrelationContext


def is_process_creation_log(path: str) -> bool:
    """Whether an ``.evtx`` file can hold the process-creation events extracted.

    Args:
        path: The log file's path.

    Returns:
        ``True`` for ``Security.evtx`` and any file whose name contains
        ``sysmon`` (case-insensitive).
    """
    name = Path(path).name.lower()
    return name == "security.evtx" or "sysmon" in name


def is_system_hive(path: str) -> bool:
    """Whether a registry hive file is a ``SYSTEM`` hive (case-insensitive)."""
    return Path(path).name.lower() == "system"


def evidence_from_context(
    context: CorrelationContext,
) -> tuple[list[EvidenceRecord], set[ArtifactType]]:
    """Extract program-execution evidence from a parsed context.

    Args:
        context: Artifacts already parsed for the rule engine.

    Returns:
        ``(records, examined_sources)``: every extracted
        :class:`EvidenceRecord`, and the artifact sources that count as
        examined (see the module docstring).
    """
    records: list[EvidenceRecord] = []
    examined: set[ArtifactType] = set()

    for prefetch_entry in context.prefetch_entries:
        examined.add(ArtifactType.PREFETCH)
        records.extend(extract_prefetch_evidence(prefetch_entry.record))

    for evtx_entry in context.evtx_entries:
        if not is_process_creation_log(evtx_entry.source_path):
            continue
        examined.add(ArtifactType.EVTX)
        records.extend(extract_evtx_evidence(evtx_entry.record, evtx_entry.source_path))

    for value_entry in context.registry_value_entries:
        if not is_system_hive(value_entry.source_path):
            continue
        examined.add(ArtifactType.REGISTRY)
        records.extend(extract_registry_evidence(value_entry.value, value_entry.source_path))

    return records, examined
