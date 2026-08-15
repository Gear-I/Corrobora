"""Unit tests for Corrobora's correlation rules and engine.

All tests build a :class:`CorrelationContext` directly from
hand-constructed model objects -- no real forensic artifact files are
needed, since :class:`CorrelationRule` implementations are pure
functions of in-memory data.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from corrobora.parsers.correlation_engine import (
    CorrelationContext,
    CorrelationEngine,
    CorrelationFinding,
    CorrelationRule,
    EvtxEntry,
    EvtxRecordNumberGapRule,
    MftEntry,
    MftTimestompingRule,
    PrefetchEntry,
    PrefetchExecutionWithoutEvtxRule,
    PrefetchFilenameHashMismatchRule,
    RegistryPersistenceWithoutExecutionRule,
    RegistryValueEntry,
    Severity,
)
from corrobora.parsers.evtx import EventRecord
from corrobora.parsers.mft import MftRecord
from corrobora.parsers.prefetch import PrefetchRecord
from corrobora.parsers.registry import RegistryValue

UTC = timezone.utc


def _make_event(
    record_number: int = 1,
    event_id: int = 4688,
    timestamp: datetime | None = None,
    message: str = "",
) -> EventRecord:
    """Build a minimal EventRecord for testing."""
    return EventRecord(
        record_number=record_number,
        event_id=event_id,
        timestamp=timestamp or datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
        provider_name="Microsoft-Windows-Security-Auditing",
        computer_name="HOST01",
        channel="Security",
        level=0,
        message=message,
        raw_xml="<Event/>",
    )


def _make_prefetch(
    executable_name: str = "MALWARE.EXE",
    run_count: int = 1,
    last_run_times: tuple[datetime, ...] = (),
    filename_hash_matches: bool | None = True,
) -> PrefetchRecord:
    """Build a minimal PrefetchRecord for testing."""
    return PrefetchRecord(
        source_path="MALWARE.EXE-3EA9C6F2.pf",
        executable_name=executable_name,
        prefetch_hash="3EA9C6F2",
        filename_hash_matches=filename_hash_matches,
        format_version=30,
        run_count=run_count,
        last_run_times=last_run_times,
        referenced_filenames=(),
        volumes=(),
    )


def _make_registry_value(
    key_path: str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    name: str = "Updater",
    data: object = "C:\\Users\\Public\\malware.exe",
) -> RegistryValue:
    """Build a minimal RegistryValue for testing."""
    return RegistryValue(
        key_path=key_path,
        name=name,
        value_type=1,
        value_type_str="RegSZ",
        data=data,
        raw_data="00",
        raw_data_bytes=b"\x00",
    )


def _make_mft_record(
    record_number: int = 0,
    filename: str = "evil.exe",
    likely_timestomped: bool = False,
    timestamp_anomalies: tuple[str, ...] = (),
) -> MftRecord:
    """Build a minimal MftRecord for testing."""
    return MftRecord(
        record_number=record_number,
        embedded_record_number=record_number,
        filename=filename,
        parent_record_number=5,
        is_directory=False,
        is_allocated=True,
        standard_information=None,
        file_name_information=None,
        timestamp_anomalies=timestamp_anomalies,
        likely_timestomped=likely_timestomped,
    )


class TestPrefetchExecutionWithoutEvtxRule:
    """Tests for cross-referencing Prefetch execution against EVTX events."""

    def test_flags_execution_with_no_matching_evtx_event(self) -> None:
        run_time = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        prefetch = _make_prefetch(executable_name="MALWARE.EXE", last_run_times=(run_time,))
        # A decoy EVTX event for a different process at an unrelated time, so
        # EVTX data genuinely was checked -- just didn't contain a match.
        decoy_event = _make_event(
            event_id=4688,
            timestamp=datetime(2020, 1, 1, tzinfo=UTC),
            message="notepad.exe",
        )
        context = CorrelationContext(
            evtx_entries=(EvtxEntry("Security.evtx", decoy_event),),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", prefetch),),
        )

        findings = PrefetchExecutionWithoutEvtxRule().evaluate(context)

        assert len(findings) == 1
        assert findings[0].rule_name == "prefetch_execution_without_evtx"
        assert findings[0].severity == Severity.MEDIUM
        assert "MALWARE.EXE" in findings[0].description

    def test_returns_no_findings_when_no_evtx_data_provided_at_all(self) -> None:
        # Regression test: with zero EVTX entries in the context, the rule
        # previously flagged every single Prefetch-recorded execution
        # (since "no matching event" was trivially true for all of them).
        # The rule should recognize it has nothing to check against and
        # stay silent rather than flag every execution as suspicious.
        run_time = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        prefetch = _make_prefetch(executable_name="MALWARE.EXE", last_run_times=(run_time,))
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", prefetch),),
        )

        findings = PrefetchExecutionWithoutEvtxRule().evaluate(context)

        assert findings == []

    def test_does_not_flag_when_matching_evtx_event_exists(self) -> None:
        run_time = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        prefetch = _make_prefetch(executable_name="MALWARE.EXE", last_run_times=(run_time,))
        event = _make_event(
            event_id=4688,
            timestamp=run_time + timedelta(seconds=30),
            message="C:\\Users\\Public\\malware.exe",
        )
        context = CorrelationContext(
            evtx_entries=(EvtxEntry("Security.evtx", event),),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", prefetch),),
        )

        findings = PrefetchExecutionWithoutEvtxRule().evaluate(context)

        assert findings == []

    def test_does_not_match_event_outside_time_window(self) -> None:
        run_time = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        prefetch = _make_prefetch(executable_name="MALWARE.EXE", last_run_times=(run_time,))
        event = _make_event(
            event_id=4688,
            timestamp=run_time + timedelta(hours=2),  # well outside default 5-min window
            message="malware.exe",
        )
        context = CorrelationContext(
            evtx_entries=(EvtxEntry("Security.evtx", event),),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", prefetch),),
        )

        findings = PrefetchExecutionWithoutEvtxRule().evaluate(context)

        assert len(findings) == 1

    def test_does_not_match_wrong_event_id(self) -> None:
        run_time = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        prefetch = _make_prefetch(executable_name="MALWARE.EXE", last_run_times=(run_time,))
        event = _make_event(
            event_id=4624,  # logon event, not process creation
            timestamp=run_time,
            message="malware.exe",
        )
        context = CorrelationContext(
            evtx_entries=(EvtxEntry("Security.evtx", event),),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", prefetch),),
        )

        findings = PrefetchExecutionWithoutEvtxRule().evaluate(context)

        assert len(findings) == 1

    def test_no_last_run_times_produces_no_findings(self) -> None:
        prefetch = _make_prefetch(executable_name="MALWARE.EXE", last_run_times=())
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", prefetch),),
        )

        findings = PrefetchExecutionWithoutEvtxRule().evaluate(context)

        assert findings == []

    def test_custom_time_window_is_respected(self) -> None:
        run_time = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        prefetch = _make_prefetch(executable_name="MALWARE.EXE", last_run_times=(run_time,))
        event = _make_event(
            event_id=4688,
            timestamp=run_time + timedelta(minutes=20),
            message="malware.exe",
        )
        context = CorrelationContext(
            evtx_entries=(EvtxEntry("Security.evtx", event),),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", prefetch),),
        )

        rule = PrefetchExecutionWithoutEvtxRule(time_window=timedelta(minutes=30))
        findings = rule.evaluate(context)

        assert findings == []


class TestRegistryPersistenceWithoutExecutionRule:
    """Tests for cross-referencing registry persistence against Prefetch."""

    def test_flags_persistence_with_no_execution_evidence(self) -> None:
        value = _make_registry_value(
            key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            data="C:\\Users\\Public\\malware.exe",
        )
        # A decoy Prefetch entry for a *different* executable, so Prefetch
        # data genuinely was checked -- just didn't contain a match.
        decoy_prefetch = _make_prefetch(executable_name="NOTEPAD.EXE", run_count=1)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(RegistryValueEntry("NTUSER.DAT", value),),
            prefetch_entries=(PrefetchEntry("NOTEPAD.EXE-DEADBEEF.pf", decoy_prefetch),),
        )

        findings = RegistryPersistenceWithoutExecutionRule().evaluate(context)

        assert len(findings) == 1
        assert findings[0].rule_name == "persistence_without_execution"
        assert "malware.exe" in findings[0].description

    def test_does_not_flag_when_prefetch_shows_execution(self) -> None:
        value = _make_registry_value(data="C:\\Users\\Public\\malware.exe")
        prefetch = _make_prefetch(executable_name="MALWARE.EXE", run_count=3)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(RegistryValueEntry("NTUSER.DAT", value),),
            prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", prefetch),),
        )

        findings = RegistryPersistenceWithoutExecutionRule().evaluate(context)

        assert findings == []

    def test_ignores_non_persistence_keys(self) -> None:
        value = _make_registry_value(
            key_path="Software\\SomeApp\\Settings", data="C:\\App\\app.exe"
        )
        decoy_prefetch = _make_prefetch(executable_name="NOTEPAD.EXE", run_count=1)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(RegistryValueEntry("NTUSER.DAT", value),),
            prefetch_entries=(PrefetchEntry("NOTEPAD.EXE-DEADBEEF.pf", decoy_prefetch),),
        )

        findings = RegistryPersistenceWithoutExecutionRule().evaluate(context)

        assert findings == []

    def test_does_not_misclassify_runas_shell_verb_as_persistence(self) -> None:
        # Regression test: "\RunAs\" contains "\Run" as a raw substring,
        # which previously caused every file type's standard "Run as..."
        # context-menu handler to be misclassified as startup persistence.
        # These keys are extremely common (batfile, cmdfile, cplfile,
        # CLSID handlers, etc.) and have nothing to do with auto-start.
        runas_value = _make_registry_value(
            key_path="ROOT\\Classes\\batfile\\shell\\runas\\command",
            name="(default)",
            data='%SystemRoot%\\System32\\cmd.exe /C "%1" %*',
        )
        decoy_prefetch = _make_prefetch(executable_name="NOTEPAD.EXE", run_count=1)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(RegistryValueEntry("SOFTWARE_copy", runas_value),),
            prefetch_entries=(PrefetchEntry("NOTEPAD.EXE-DEADBEEF.pf", decoy_prefetch),),
        )

        findings = RegistryPersistenceWithoutExecutionRule().evaluate(context)

        assert findings == []

    def test_matches_run_key_as_exact_segment_not_substring(self) -> None:
        # Sanity check the fix in the other direction: a genuine "Run" key
        # segment must still match correctly.
        value = _make_registry_value(
            key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            name="Updater",
            data="C:\\Temp\\evil.exe",
        )
        decoy_prefetch = _make_prefetch(executable_name="NOTEPAD.EXE", run_count=1)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(RegistryValueEntry("NTUSER.DAT", value),),
            prefetch_entries=(PrefetchEntry("NOTEPAD.EXE-DEADBEEF.pf", decoy_prefetch),),
        )

        findings = RegistryPersistenceWithoutExecutionRule().evaluate(context)

        assert len(findings) == 1

    def test_returns_no_findings_when_no_prefetch_data_provided_at_all(self) -> None:
        # Regression test: with zero Prefetch entries in the context, the
        # rule previously flagged every single persistence entry (since
        # "no execution evidence" was trivially true for all of them),
        # even completely benign, well-known startup programs. The rule
        # should recognize it has nothing to check against and stay silent.
        value = _make_registry_value(
            key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            data="C:\\Program Files\\Legit\\legit.exe",
        )
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(RegistryValueEntry("SOFTWARE_copy", value),),
            prefetch_entries=(),
        )

        findings = RegistryPersistenceWithoutExecutionRule().evaluate(context)

        assert findings == []

    def test_ignores_values_with_no_exe_reference(self) -> None:
        value = _make_registry_value(data="just some string, no exe")
        decoy_prefetch = _make_prefetch(executable_name="NOTEPAD.EXE", run_count=1)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(RegistryValueEntry("NTUSER.DAT", value),),
            prefetch_entries=(PrefetchEntry("NOTEPAD.EXE-DEADBEEF.pf", decoy_prefetch),),
        )

        findings = RegistryPersistenceWithoutExecutionRule().evaluate(context)

        assert findings == []

    def test_ignores_non_string_value_data(self) -> None:
        value = _make_registry_value(data=42)
        decoy_prefetch = _make_prefetch(executable_name="NOTEPAD.EXE", run_count=1)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(RegistryValueEntry("NTUSER.DAT", value),),
            prefetch_entries=(PrefetchEntry("NOTEPAD.EXE-DEADBEEF.pf", decoy_prefetch),),
        )

        findings = RegistryPersistenceWithoutExecutionRule().evaluate(context)

        assert findings == []


class TestPrefetchFilenameHashMismatchRule:
    """Tests for surfacing Prefetch filename/hash mismatches."""

    def test_flags_mismatch(self) -> None:
        prefetch = _make_prefetch(filename_hash_matches=False)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("renamed.pf", prefetch),),
        )

        findings = PrefetchFilenameHashMismatchRule().evaluate(context)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_does_not_flag_match(self) -> None:
        prefetch = _make_prefetch(filename_hash_matches=True)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", prefetch),),
        )

        findings = PrefetchFilenameHashMismatchRule().evaluate(context)

        assert findings == []

    def test_does_not_flag_when_unknown(self) -> None:
        prefetch = _make_prefetch(filename_hash_matches=None)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("renamed.pf", prefetch),),
        )

        findings = PrefetchFilenameHashMismatchRule().evaluate(context)

        assert findings == []


class TestMftTimestompingRule:
    """Tests for surfacing MFT timestomping detections as findings."""

    def test_flags_timestomped_record(self) -> None:
        record = _make_mft_record(
            likely_timestomped=True, timestamp_anomalies=("creation_time", "access_time")
        )
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(),
            prefetch_entries=(),
            mft_entries=(MftEntry("C_MFT", record),),
        )

        findings = MftTimestompingRule().evaluate(context)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].rule_name == "mft_timestomping_detected"
        assert "creation_time" in findings[0].evidence[0]

    def test_does_not_flag_normal_record(self) -> None:
        record = _make_mft_record(likely_timestomped=False)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(),
            prefetch_entries=(),
            mft_entries=(MftEntry("C_MFT", record),),
        )

        findings = MftTimestompingRule().evaluate(context)

        assert findings == []

    def test_default_context_has_no_mft_entries(self) -> None:
        # Confirms mft_entries defaults to empty so existing callers that
        # don't pass it (e.g. the GUI before this feature) still work.
        context = CorrelationContext(
            evtx_entries=(), registry_value_entries=(), prefetch_entries=()
        )
        assert context.mft_entries == ()
        assert MftTimestompingRule().evaluate(context) == []


class TestEvtxRecordNumberGapRule:
    """Tests for detecting record number gaps within an EVTX file."""

    def test_no_gap_produces_no_findings(self) -> None:
        events = [_make_event(record_number=n) for n in (1, 2, 3, 4)]
        context = CorrelationContext(
            evtx_entries=tuple(EvtxEntry("Security.evtx", e) for e in events),
            registry_value_entries=(),
            prefetch_entries=(),
        )

        findings = EvtxRecordNumberGapRule().evaluate(context)

        assert findings == []

    def test_small_gaps_are_aggregated_into_one_info_finding(self) -> None:
        # Simulates the real-world pattern seen in Operational/Diagnostic
        # channels: many small (size-1) gaps scattered throughout a file.
        record_numbers = [1, 3, 5, 7, 9, 11]  # 5 gaps of size 1 each
        events = [_make_event(record_number=n) for n in record_numbers]
        context = CorrelationContext(
            evtx_entries=tuple(EvtxEntry("Ntfs.evtx", e) for e in events),
            registry_value_entries=(),
            prefetch_entries=(),
        )

        findings = EvtxRecordNumberGapRule().evaluate(context)

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "5 small gap(s)" in findings[0].description
        assert "totaling 5 missing record(s)" in findings[0].description

    def test_significant_gap_is_reported_individually_at_medium_severity(self) -> None:
        # A gap of 15 missing records, well above the default threshold of 10.
        events = [_make_event(record_number=n) for n in (1, 2, 18, 19)]
        context = CorrelationContext(
            evtx_entries=tuple(EvtxEntry("Security.evtx", e) for e in events),
            registry_value_entries=(),
            prefetch_entries=(),
        )

        findings = EvtxRecordNumberGapRule().evaluate(context)

        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "15 consecutive missing record(s)" in findings[0].description

    def test_mixed_small_and_significant_gaps_in_one_file(self) -> None:
        # One small gap (size 1) and one significant gap (size 15).
        events = [_make_event(record_number=n) for n in (1, 3, 4, 20)]
        context = CorrelationContext(
            evtx_entries=tuple(EvtxEntry("Mixed.evtx", e) for e in events),
            registry_value_entries=(),
            prefetch_entries=(),
        )

        findings = EvtxRecordNumberGapRule().evaluate(context)

        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert severities == {Severity.MEDIUM, Severity.INFO}

    def test_custom_significant_gap_size_threshold(self) -> None:
        # With a lowered threshold, a gap of 3 becomes individually significant.
        events = [_make_event(record_number=n) for n in (1, 2, 6, 7)]
        context = CorrelationContext(
            evtx_entries=tuple(EvtxEntry("Security.evtx", e) for e in events),
            registry_value_entries=(),
            prefetch_entries=(),
        )

        rule = EvtxRecordNumberGapRule(significant_gap_size=3)
        findings = rule.evaluate(context)

        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_gaps_tracked_separately_per_source_file(self) -> None:
        events_a = [_make_event(record_number=n) for n in (1, 20)]  # significant gap
        events_b = [_make_event(record_number=n) for n in (1, 2)]  # no gap
        context = CorrelationContext(
            evtx_entries=(
                *(EvtxEntry("A.evtx", e) for e in events_a),
                *(EvtxEntry("B.evtx", e) for e in events_b),
            ),
            registry_value_entries=(),
            prefetch_entries=(),
        )

        findings = EvtxRecordNumberGapRule().evaluate(context)

        assert len(findings) == 1
        assert findings[0].source_paths == ("A.evtx",)


class TestCorrelationEngine:
    """Tests for the engine's rule orchestration and failure isolation."""

    def test_runs_default_rules_and_sorts_by_severity(self) -> None:
        mismatched_prefetch = _make_prefetch(filename_hash_matches=False)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("renamed.pf", mismatched_prefetch),),
        )

        engine = CorrelationEngine()
        findings = engine.run(context)

        assert len(findings) >= 1
        severities = [f.severity for f in findings]
        assert severities == sorted(
            severities, key=lambda s: {"info": 0, "low": 1, "medium": 2, "high": 3}[s.value],
            reverse=True,
        )

    def test_custom_rule_set(self) -> None:
        prefetch = _make_prefetch(filename_hash_matches=False)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("renamed.pf", prefetch),),
        )

        engine = CorrelationEngine(rules=[PrefetchFilenameHashMismatchRule()])
        findings = engine.run(context)

        assert len(findings) == 1
        assert findings[0].rule_name == "prefetch_filename_hash_mismatch"

    def test_one_broken_rule_does_not_stop_others(self) -> None:
        class BrokenRule(CorrelationRule):  # pylint: disable=too-few-public-methods
            rule_name = "broken_rule"

            def evaluate(self, context: CorrelationContext) -> list[CorrelationFinding]:
                raise RuntimeError("simulated rule failure")

        prefetch = _make_prefetch(filename_hash_matches=False)
        context = CorrelationContext(
            evtx_entries=(),
            registry_value_entries=(),
            prefetch_entries=(PrefetchEntry("renamed.pf", prefetch),),
        )

        engine = CorrelationEngine(
            rules=[BrokenRule(), PrefetchFilenameHashMismatchRule()]
        )
        findings = engine.run(context)

        assert len(findings) == 1
        assert findings[0].rule_name == "prefetch_filename_hash_mismatch"

    def test_empty_context_produces_no_findings(self) -> None:
        context = CorrelationContext(
            evtx_entries=(), registry_value_entries=(), prefetch_entries=()
        )
        engine = CorrelationEngine()
        findings = engine.run(context)
        assert findings == []