"""Tests for program-execution corroboration run from an already-parsed context.

Covers :mod:`corrobora.correlation.context` (which the GUI uses so files
are parsed once) and the GUI's pure helpers around it: ``run_analysis``
with a correlation window, and parsing the window field. Qt widgets are
not exercised.
"""

# pylint: disable=missing-function-docstring,too-few-public-methods,protected-access

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest import mock

import pytest

from corrobora.correlation.context import evidence_from_context
from corrobora.correlation.program_execution import CorroborationStatus
from corrobora.extractors.evtx import SECURITY_AUDITING_PROVIDER
from corrobora.parsers import corrobora_gui
from corrobora.parsers.Base import ArtifactType
from corrobora.parsers.evtx import EventRecord
from corrobora.parsers.prefetch import PrefetchRecord
from corrobora.parsers.registry import RegistryValue
from corrobora.rules.base import CorrelationContext, EvtxEntry, PrefetchEntry, RegistryValueEntry

BASE = datetime(2026, 9, 27, 14, 31, 42, tzinfo=UTC)
_PS_PATH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


def _prefetch() -> PrefetchRecord:
    return PrefetchRecord(
        source_path="POWERSHELL.EXE-12345678.pf",
        executable_name="POWERSHELL.EXE",
        prefetch_hash="12345678",
        filename_hash_matches=True,
        format_version=30,
        run_count=1,
        last_run_times=(BASE,),
        referenced_filenames=(),
        volumes=(),
    )


def _event_4688() -> EventRecord:
    return EventRecord(
        record_number=7,
        event_id=4688,
        timestamp=BASE,
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
    delta = BASE + timedelta(seconds=60) - datetime(1601, 1, 1, tzinfo=UTC)
    raw = ((delta.days * 86_400 + delta.seconds) * 10_000_000).to_bytes(8, "little")
    raw += b"\x00" * 16
    return RegistryValue(
        key_path=rf"ROOT\ControlSet001\Services\bam\State\UserSettings\{_SID}",
        name=r"\Device\HarddiskVolume3" + _PS_PATH[2:],
        value_type=3,
        value_type_str="RegBin",
        data=raw,
        raw_data=raw.hex(),
        raw_data_bytes=raw,
    )


def _context(evtx_file="Security.evtx", hive_file="SYSTEM", prefetch=True) -> CorrelationContext:
    return CorrelationContext(
        evtx_entries=(EvtxEntry(evtx_file, _event_4688()),),
        registry_value_entries=(RegistryValueEntry(hive_file, _bam_value()),),
        prefetch_entries=(
            (PrefetchEntry("POWERSHELL.EXE-12345678.pf", _prefetch()),) if prefetch else ()
        ),
    )


class TestEvidenceFromContext:
    """Extraction and "examined" accounting, matching the command line."""

    def test_all_three_sources(self):
        records, examined = evidence_from_context(_context())
        assert examined == {ArtifactType.PREFETCH, ArtifactType.EVTX, ArtifactType.REGISTRY}
        assert {r.artifact_type for r in records} == examined
        assert {r.subject for r in records} == {"powershell.exe"}

    def test_non_process_creation_log_not_examined(self):
        records, examined = evidence_from_context(_context(evtx_file="System.evtx"))
        assert ArtifactType.EVTX not in examined
        assert all(r.artifact_type is not ArtifactType.EVTX for r in records)

    def test_sysmon_log_counts_as_examined(self):
        _, examined = evidence_from_context(
            _context(evtx_file="Microsoft-Windows-Sysmon%4Operational.evtx")
        )
        assert ArtifactType.EVTX in examined

    def test_non_system_hive_not_examined(self):
        records, examined = evidence_from_context(_context(hive_file="NTUSER.DAT"))
        assert ArtifactType.REGISTRY not in examined
        assert all(r.artifact_type is not ArtifactType.REGISTRY for r in records)

    def test_no_prefetch_loaded(self):
        _, examined = evidence_from_context(_context(prefetch=False))
        assert ArtifactType.PREFETCH not in examined


class TestRunAnalysisExecution:
    """run_analysis() with and without a correlation window."""

    def _run(self, window):
        # build_context parses files; replace it so the synthetic context is used.
        with mock.patch.object(corrobora_gui, "build_context", return_value=_context()):
            return corrobora_gui.run_analysis([], [], [], [], rules=[], execution_window=window)

    def test_window_runs_program_execution_corroboration(self):
        outcome = self._run(timedelta(seconds=5))
        assert outcome.error is None
        assert outcome.execution_window == timedelta(seconds=5)
        assert [f.subject for f in outcome.execution_findings] == ["powershell.exe"]
        assert outcome.execution_findings[0].status is CorroborationStatus.CORROBORATED
        assert len(outcome.execution_evidence) == 3

    def test_no_window_skips_it(self):
        outcome = self._run(None)
        assert outcome.error is None
        assert outcome.execution_window is None
        assert not outcome.execution_findings
        assert not outcome.execution_evidence


class TestParseWindow:
    """The GUI's correlation-window field."""

    @pytest.mark.parametrize(("text", "expected"), [("", None), ("   ", None)])
    def test_empty_skips(self, text, expected):
        assert corrobora_gui._parse_window(text) is expected

    def test_positive_whole_seconds(self):
        assert corrobora_gui._parse_window(" 30 ") == timedelta(seconds=30)

    @pytest.mark.parametrize("text", ["0", "-5", "1.5", "abc"])
    def test_invalid(self, text):
        assert corrobora_gui._parse_window(text) is False
