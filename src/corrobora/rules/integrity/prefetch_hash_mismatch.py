"""Prefetch filename/embedded hash mismatch rule."""

from __future__ import annotations

from pathlib import Path

from ..base import CorrelationContext, CorrelationFinding, CorrelationRule, Severity

# Corroboration-strength score for this rule's findings: a direct
# positive tamper indicator (the file's own embedded hash disagrees
# with its filename hash), not an absence-based inference.
_SCORE = 90


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
    category = "integrity"

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
                    score=_SCORE,
                )
            )
        return findings
