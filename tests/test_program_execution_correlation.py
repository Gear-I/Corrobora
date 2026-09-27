"""Tests for :mod:`corrobora.correlation` (program-execution corroboration)."""

# pylint: disable=missing-function-docstring,too-few-public-methods

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from corrobora.correlation.program_execution import (
    CorroborationStatus,
    correlate_all_program_execution,
    correlate_program_execution,
)
from corrobora.correlation.report import render_program_execution_report
from corrobora.extractors.evtx import SECURITY_AUDITING_PROVIDER, extract_evtx_evidence
from corrobora.extractors.prefetch import extract_prefetch_evidence
from corrobora.extractors.registry import extract_registry_evidence
from corrobora.models.evidence import EvidenceRecord, EvidenceType, TimestampSemantics
from corrobora.parsers.Base import ArtifactType
from corrobora.parsers.evtx import EventRecord
from corrobora.parsers.prefetch import PrefetchRecord
from corrobora.parsers.registry import RegistryValue

PREFETCH, EVTX, REGISTRY = ArtifactType.PREFETCH, ArtifactType.EVTX, ArtifactType.REGISTRY
ALL_SOURCES = (PREFETCH, EVTX, REGISTRY)
WINDOW = timedelta(seconds=300)
BASE = datetime(2026, 9, 27, 14, 31, 42, tzinfo=UTC)

_SEMANTICS = {
    PREFETCH: TimestampSemantics.PREFETCH_LAST_RUN,
    EVTX: TimestampSemantics.EVTX_TIME_CREATED,
    REGISTRY: TimestampSemantics.REGISTRY_BAM_LAST_EXECUTION,
}


def _ev(
    source: ArtifactType,
    offset_seconds: float | None,
    subject: str = "powershell.exe",
    ref: str = "r0",
    evidence_type: EvidenceType = EvidenceType.PROGRAM_EXECUTION,
) -> EvidenceRecord:
    return EvidenceRecord(
        artifact_type=source,
        evidence_type=evidence_type,
        subject=subject,
        subject_raw=subject.upper(),
        timestamp=None if offset_seconds is None else BASE + timedelta(seconds=offset_seconds),
        timestamp_semantics=_SEMANTICS[source],
        source_path=f"{source.value}.bin",
        record_ref=ref,
    )


def _correlate(records, examined=ALL_SOURCES, window=WINDOW):
    return correlate_program_execution(records, "powershell.exe", examined, window)


def _in_window(finding) -> set[ArtifactType]:
    return {s.artifact_type for s in finding.sources if s.in_window}


class TestStatus:
    """Classification into the three corroboration outcomes."""

    def test_all_three_sources_within_window_corroborated(self):
        finding = _correlate([_ev(PREFETCH, 0), _ev(EVTX, 5), _ev(REGISTRY, 9)])
        assert finding.status is CorroborationStatus.CORROBORATED
        assert _in_window(finding) == set(ALL_SOURCES)

    def test_registry_absent_partially_corroborated(self):
        finding = _correlate([_ev(PREFETCH, 0), _ev(EVTX, 5)])
        assert finding.status is CorroborationStatus.PARTIALLY_CORROBORATED
        registry = next(s for s in finding.sources if s.artifact_type is REGISTRY)
        assert not registry.observed
        assert "No corresponding Registry evidence was identified." in finding.explanation

    def test_registry_outside_window_partially_corroborated(self):
        finding = _correlate([_ev(PREFETCH, 0), _ev(EVTX, 5), _ev(REGISTRY, 3600)])
        assert finding.status is CorroborationStatus.PARTIALLY_CORROBORATED
        assert _in_window(finding) == {PREFETCH, EVTX}
        assert any("not within the configured correlation window" in s for s in finding.explanation)

    def test_registry_untimed_partially_corroborated(self):
        finding = _correlate([_ev(PREFETCH, 0), _ev(EVTX, 5), _ev(REGISTRY, None)])
        assert finding.status is CorroborationStatus.PARTIALLY_CORROBORATED
        assert "Registry evidence was identified but has no usable timestamp." in (
            finding.explanation
        )

    def test_single_source_needs_review(self):
        finding = _correlate([_ev(PREFETCH, 0)])
        assert finding.status is CorroborationStatus.NEEDS_REVIEW
        assert not _in_window(finding)
        assert finding.explanation[0].startswith("Only Prefetch contains evidence")

    def test_sources_disagree_in_time_needs_review(self):
        finding = _correlate([_ev(PREFETCH, 0), _ev(EVTX, 3600), _ev(REGISTRY, 7200)])
        assert finding.status is CorroborationStatus.NEEDS_REVIEW
        assert "no two sources fall within" in finding.explanation[0]

    def test_only_one_source_examined_needs_review(self):
        finding = _correlate([_ev(PREFETCH, 0)], examined=[PREFETCH])
        assert finding.status is CorroborationStatus.NEEDS_REVIEW
        assert finding.explanation[0].startswith("Only Prefetch was examined")

    def test_unexamined_source_not_expected(self):
        finding = _correlate([_ev(PREFETCH, 0), _ev(EVTX, 5)], examined=[PREFETCH, EVTX])
        assert finding.status is CorroborationStatus.CORROBORATED
        assert {s.artifact_type for s in finding.sources} == {PREFETCH, EVTX}

    def test_source_with_evidence_counts_as_examined(self):
        finding = _correlate([_ev(PREFETCH, 0), _ev(EVTX, 5)], examined=[PREFETCH])
        assert finding.status is CorroborationStatus.CORROBORATED


class TestWindow:
    """How the window bounds agreement."""

    def test_spread_equal_to_window_is_inside(self):
        finding = _correlate([_ev(PREFETCH, 0), _ev(EVTX, 300)], examined=[PREFETCH, EVTX])
        assert finding.status is CorroborationStatus.CORROBORATED

    def test_spread_just_over_window_is_outside(self):
        finding = _correlate([_ev(PREFETCH, 0), _ev(EVTX, 300.001)], examined=[PREFETCH, EVTX])
        assert finding.status is CorroborationStatus.NEEDS_REVIEW

    def test_window_is_total_spread_not_distance_from_one_record(self):
        # EVTX is within 300 s of each of the others, but Prefetch and
        # Registry are 400 s apart, so all three cannot agree together.
        finding = _correlate([_ev(PREFETCH, 0), _ev(EVTX, 200), _ev(REGISTRY, 400)])
        assert finding.status is CorroborationStatus.PARTIALLY_CORROBORATED
        assert len(_in_window(finding)) == 2

    @pytest.mark.parametrize("window", [timedelta(0), timedelta(seconds=-1)])
    def test_non_positive_window_rejected(self, window):
        with pytest.raises(ValueError, match="window"):
            _correlate([_ev(PREFETCH, 0)], window=window)

    def test_window_recorded_on_finding(self):
        assert _correlate([_ev(PREFETCH, 0)], window=timedelta(seconds=42)).window == timedelta(
            seconds=42
        )


class TestGroupSelection:
    """Choosing the best-agreeing group among many records."""

    def test_picks_the_prefetch_run_that_other_sources_agree_with(self):
        records = [
            _ev(PREFETCH, 0, ref="run[0]"),
            _ev(PREFETCH, -86_400, ref="run[1]"),
            _ev(PREFETCH, -172_800, ref="run[2]"),
            _ev(EVTX, -86_395),
            _ev(REGISTRY, -86_390),
        ]
        finding = _correlate(records)
        assert finding.status is CorroborationStatus.CORROBORATED
        prefetch = next(s for s in finding.sources if s.artifact_type is PREFETCH)
        assert prefetch.representative.record_ref == "run[1]"
        assert len(prefetch.evidence) == 3

    def test_duplicate_records_from_one_source_count_once(self):
        records = [_ev(REGISTRY, 0, ref="cs1"), _ev(REGISTRY, 0, ref="cs2"), _ev(PREFETCH, 5)]
        finding = _correlate(records)
        assert finding.status is CorroborationStatus.PARTIALLY_CORROBORATED
        assert _in_window(finding) == {PREFETCH, REGISTRY}

    def test_other_subjects_and_evidence_types_ignored(self):
        records = [
            _ev(PREFETCH, 0),
            _ev(EVTX, 5, subject="cmd.exe"),
            _ev(REGISTRY, 5, evidence_type=EvidenceType.SCRIPT_EXECUTION),
        ]
        finding = _correlate(records)
        assert finding.status is CorroborationStatus.NEEDS_REVIEW

    def test_no_evidence_returns_none(self):
        assert _correlate([_ev(PREFETCH, 0, subject="cmd.exe")]) is None


class TestCorrelateAll:
    """Running correlation for every subject present."""

    def test_one_finding_per_subject_sorted(self):
        records = [_ev(PREFETCH, 0), _ev(EVTX, 5), _ev(PREFETCH, 0, subject="cmd.exe")]
        findings = correlate_all_program_execution(records, ALL_SOURCES, WINDOW)
        assert [f.subject for f in findings] == ["cmd.exe", "powershell.exe"]


class TestReport:
    """Plain-text report wording."""

    def test_corroborated_report(self):
        report = render_program_execution_report(
            _correlate([_ev(PREFETCH, 0), _ev(EVTX, 5), _ev(REGISTRY, 9)])
        )
        assert "Subject: powershell.exe" in report
        assert "Correlation window: 300 seconds (configured; not a validated" in report
        assert "Timestamp: 2026-09-27 14:31:42 UTC" in report
        assert "Result: CORROBORATED" in report
        assert "3 independent artifact sources" in report
        assert "Examiner review is recommended." in report

    def test_partial_report_never_claims_anti_forensics(self):
        report = render_program_execution_report(_correlate([_ev(PREFETCH, 0), _ev(EVTX, 5)]))
        assert "Result: PARTIALLY CORROBORATED" in report
        assert "Prefetch and EVTX contain consistent evidence." in report
        assert "No corresponding Registry evidence was identified." in report
        assert "does not establish deletion or anti-forensic activity" in report
        assert "Examiner review is required." in report
        assert "DETECTED" not in report.upper()

    def test_outside_window_marked(self):
        report = render_program_execution_report(
            _correlate([_ev(PREFETCH, 0), _ev(EVTX, 5), _ev(REGISTRY, 3600)])
        )
        assert "(outside correlation window)" in report


# --------------------------------------------------------------------------
# End to end: native parser records -> extractors -> correlation -> report
# --------------------------------------------------------------------------

_PS_PATH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


def _prefetch_record() -> PrefetchRecord:
    return PrefetchRecord(
        source_path="POWERSHELL.EXE-12345678.pf",
        executable_name="POWERSHELL.EXE",
        prefetch_hash="12345678",
        filename_hash_matches=True,
        format_version=30,
        run_count=4,
        last_run_times=(BASE,),
        referenced_filenames=(),
        volumes=(),
    )


def _security_4688() -> EventRecord:
    return EventRecord(
        record_number=1234,
        event_id=4688,
        timestamp=BASE + timedelta(seconds=5),
        provider_name=SECURITY_AUDITING_PROVIDER,
        computer_name="WS01",
        channel="Security",
        level=0,
        message=None,
        raw_xml=(
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System/><EventData><Data Name="NewProcessName">{_PS_PATH}</Data>'
            "</EventData></Event>"
        ),
    )


def _bam_value() -> RegistryValue:
    delta = BASE + timedelta(seconds=9) - datetime(1601, 1, 1, tzinfo=UTC)
    ticks = (delta.days * 86_400 + delta.seconds) * 10_000_000
    raw = ticks.to_bytes(8, "little") + b"\x00" * 16
    return RegistryValue(
        key_path=rf"ROOT\ControlSet001\Services\bam\State\UserSettings\{_SID}",
        name=r"\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        value_type=3,
        value_type_str="RegBin",
        data=raw,
        raw_data=raw.hex(),
        raw_data_bytes=raw,
    )


class TestEndToEnd:
    """The PowerShell scenario from native records to report."""

    def _evidence(self, include_registry: bool) -> list[EvidenceRecord]:
        evidence = extract_prefetch_evidence(_prefetch_record())
        evidence += extract_evtx_evidence(_security_4688(), "Security.evtx")
        if include_registry:
            evidence += extract_registry_evidence(_bam_value(), "SYSTEM")
        return evidence

    def test_three_sources_corroborate(self):
        finding = _correlate(self._evidence(include_registry=True))
        assert finding.status is CorroborationStatus.CORROBORATED
        report = render_program_execution_report(finding)
        assert "Event ID: 4688" in report
        assert "Run count: 4" in report
        assert f"Location: BAM ({_SID})" in report
        assert "Source: SYSTEM\n" in report
        assert r"Value: \Device\HarddiskVolume3" in report
        assert "Timestamp: 2026-09-27 14:31:51 UTC" in report

    def test_missing_registry_partially_corroborates(self):
        finding = _correlate(self._evidence(include_registry=False))
        assert finding.status is CorroborationStatus.PARTIALLY_CORROBORATED
        report = render_program_execution_report(finding)
        assert "No corresponding Registry evidence was identified." in report
