"""Unit tests for corrobora.rules.app_corroboration.

Same spirit as tests/test_correlation_rules.py: hand-built
CorrelationContext objects, no real forensic artifact files needed.
"""

# pylint: disable=missing-function-docstring
# Test function names are self-descriptive; per-test docstrings would
# just restate the name.

from __future__ import annotations

from datetime import datetime, timezone

from corrobora.parsers.evtx import EventRecord
from corrobora.parsers.mft import MftRecord
from corrobora.parsers.prefetch import PrefetchRecord
from corrobora.parsers.registry import RegistryValue
from corrobora.rules.app_corroboration import build_app_corroboration
from corrobora.rules.base import (
    CorrelationContext,
    EvtxEntry,
    MftEntry,
    PrefetchEntry,
    RegistryValueEntry,
)

UTC = timezone.utc


def _make_prefetch(executable_name: str) -> PrefetchRecord:
    return PrefetchRecord(
        source_path=f"{executable_name}-3EA9C6F2.pf",
        executable_name=executable_name,
        prefetch_hash="3EA9C6F2",
        filename_hash_matches=True,
        format_version=30,
        run_count=1,
        last_run_times=(),
        referenced_filenames=(),
        volumes=(),
    )


def _make_event(message: str) -> EventRecord:
    return EventRecord(
        record_number=1,
        event_id=4688,
        timestamp=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
        provider_name="Microsoft-Windows-Security-Auditing",
        computer_name="HOST01",
        channel="Security",
        level=0,
        message=message,
        raw_xml="<Event/>",
    )


def _make_registry_value(data: object) -> RegistryValue:
    return RegistryValue(
        key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        name="Updater",
        value_type=1,
        value_type_str="RegSZ",
        data=data,
        raw_data="00",
        raw_data_bytes=b"\x00",
    )


def _make_mft_record(filename: str) -> MftRecord:
    return MftRecord(
        record_number=0,
        embedded_record_number=0,
        filename=filename,
        parent_record_number=5,
        is_directory=False,
        is_allocated=True,
        standard_information=None,
        file_name_information=None,
        timestamp_anomalies=(),
        likely_timestomped=False,
    )


def test_app_found_in_all_four_sources_scores_100() -> None:
    context = CorrelationContext(
        evtx_entries=(EvtxEntry("Security.evtx", _make_event("C:\\Temp\\malware.exe started")),),
        registry_value_entries=(
            RegistryValueEntry("NTUSER.DAT", _make_registry_value("C:\\Temp\\malware.exe")),
        ),
        prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", _make_prefetch("MALWARE.EXE")),),
        mft_entries=(MftEntry("C_MFT", _make_mft_record("MALWARE.EXE")),),
    )

    results = build_app_corroboration(context)

    assert len(results) == 1
    assert results[0].application == "malware.exe"
    assert results[0].score == 100
    assert results[0].assessment == "Supported by multiple artifacts."
    assert all(p.found for p in results[0].presence)


def test_app_found_in_prefetch_only_scores_25() -> None:
    context = CorrelationContext(
        evtx_entries=(),
        registry_value_entries=(),
        prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", _make_prefetch("MALWARE.EXE")),),
        mft_entries=(),
    )

    results = build_app_corroboration(context)

    assert len(results) == 1
    assert results[0].score == 25
    assert results[0].assessment == "Artifact inconsistency detected."
    found_types = {p.artifact_type for p in results[0].presence if p.found}
    assert found_types == {"Prefetch"}


def test_app_found_in_prefetch_and_evtx_scores_50() -> None:
    context = CorrelationContext(
        evtx_entries=(EvtxEntry("Security.evtx", _make_event("malware.exe launched")),),
        registry_value_entries=(),
        prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", _make_prefetch("MALWARE.EXE")),),
        mft_entries=(),
    )

    results = build_app_corroboration(context)

    assert results[0].score == 50
    assert results[0].assessment == "Partially corroborated -- some artifacts missing."


def test_matching_is_case_insensitive_across_sources() -> None:
    context = CorrelationContext(
        evtx_entries=(EvtxEntry("Security.evtx", _make_event("ran malware.exe today")),),
        registry_value_entries=(),
        prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", _make_prefetch("MALWARE.EXE")),),
        mft_entries=(),
    )

    results = build_app_corroboration(context)

    assert len(results) == 1
    assert results[0].application == "malware.exe"
    evtx_presence = next(p for p in results[0].presence if p.artifact_type == "Event Log")
    assert evtx_presence.found


def test_mft_only_exe_filename_is_a_candidate() -> None:
    context = CorrelationContext(
        evtx_entries=(),
        registry_value_entries=(),
        prefetch_entries=(),
        mft_entries=(MftEntry("C_MFT", _make_mft_record("svchost_updater.exe")),),
    )

    results = build_app_corroboration(context)

    assert len(results) == 1
    assert results[0].application == "svchost_updater.exe"
    assert results[0].score == 25


def test_empty_context_produces_no_candidates() -> None:
    context = CorrelationContext(
        evtx_entries=(), registry_value_entries=(), prefetch_entries=(), mft_entries=()
    )

    assert not build_app_corroboration(context)


def test_mft_filenames_without_exe_extension_are_not_candidates() -> None:
    context = CorrelationContext(
        evtx_entries=(),
        registry_value_entries=(),
        prefetch_entries=(),
        mft_entries=(MftEntry("C_MFT", _make_mft_record("report.docx")),),
    )

    assert not build_app_corroboration(context)
