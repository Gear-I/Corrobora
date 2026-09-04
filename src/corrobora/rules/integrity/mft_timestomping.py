"""MFT timestomping detection rule."""

from __future__ import annotations

from ..base import CorrelationContext, CorrelationFinding, CorrelationRule, Severity

# Corroboration-strength score for this rule's findings: a direct
# positive tamper indicator ($STANDARD_INFORMATION predates $FILE_NAME
# creation time), not an absence-based inference.
_SCORE = 90


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
    category = "integrity"

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
                    score=_SCORE,
                )
            )
        return findings
