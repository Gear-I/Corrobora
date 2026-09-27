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


def _full_context(evtx: str, registry: str, mft: str) -> CorrelationContext:
    """All four artifact types loaded; only Prefetch is fixed to MALWARE.EXE."""
    return CorrelationContext(
        evtx_entries=(EvtxEntry("Security.evtx", _make_event(evtx)),),
        registry_value_entries=(RegistryValueEntry("NTUSER.DAT", _make_registry_value(registry)),),
        prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", _make_prefetch("MALWARE.EXE")),),
        mft_entries=(MftEntry("C_MFT", _make_mft_record(mft)),),
    )


def test_app_found_in_all_four_sources_scores_100() -> None:
    context = _full_context(r"C:\Temp\malware.exe started", r"C:\Temp\malware.exe", "MALWARE.EXE")

    results = build_app_corroboration(context)

    assert len(results) == 1
    assert results[0].application == "malware.exe"
    assert results[0].score == 100
    assert results[0].assessment == (
        "Supported by multiple artifacts (4 of 4 examined artifact types)."
    )
    assert (results[0].found_count, results[0].examined_count) == (4, 4)
    assert all(p.found and p.examined for p in results[0].presence)


def test_app_found_in_prefetch_only_of_four_examined_scores_25() -> None:
    # MFT holds an unrelated .exe, which also becomes a candidate.
    context = _full_context("notepad.exe started", r"C:\Temp\other.exe", "calc.exe")

    results = {r.application: r for r in build_app_corroboration(context)}

    malware = results["malware.exe"]
    assert malware.score == 25
    assert malware.assessment == (
        "Limited corroboration -- found in only 1 of 4 examined artifact types."
    )
    assert {p.artifact_type for p in malware.presence if p.found} == {"Prefetch"}


def test_three_of_four_scores_75_supported() -> None:
    context = _full_context("malware.exe launched", r"C:\Temp\malware.exe", "calc.exe")

    malware = next(r for r in build_app_corroboration(context) if r.application == "malware.exe")

    assert malware.score == 75
    assert malware.assessment == (
        "Supported by multiple artifacts (3 of 4 examined artifact types)."
    )


def test_unloaded_types_are_not_examined_and_not_counted() -> None:
    # Regression test: with no registry or MFT data loaded, the score used
    # to be computed out of four, so Prefetch + EVTX agreeing scored 50.
    context = CorrelationContext(
        evtx_entries=(EvtxEntry("Security.evtx", _make_event("malware.exe launched")),),
        registry_value_entries=(),
        prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", _make_prefetch("MALWARE.EXE")),),
        mft_entries=(),
    )

    results = build_app_corroboration(context)

    assert results[0].score == 100
    assert results[0].assessment == (
        "Supported by multiple artifacts (2 of 2 examined artifact types)."
    )
    presence = {p.artifact_type: p for p in results[0].presence}
    assert [p.artifact_type for p in results[0].presence] == [
        "Prefetch",
        "Registry",
        "Event Log",
        "MFT",
    ]
    for label in ("Registry", "MFT"):
        assert not presence[label].examined
        assert not presence[label].found
        assert presence[label].detail == f"Not examined -- no {label} data was loaded."


def test_one_of_two_examined_is_limited() -> None:
    context = CorrelationContext(
        evtx_entries=(EvtxEntry("Security.evtx", _make_event("notepad.exe launched")),),
        registry_value_entries=(),
        prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", _make_prefetch("MALWARE.EXE")),),
        mft_entries=(),
    )

    results = build_app_corroboration(context)

    assert results[0].score == 50
    assert results[0].assessment == (
        "Limited corroboration -- found in only 1 of 2 examined artifact types."
    )


def test_only_one_type_examined_cannot_be_corroborated() -> None:
    context = CorrelationContext(
        evtx_entries=(),
        registry_value_entries=(),
        prefetch_entries=(PrefetchEntry("MALWARE.EXE-3EA9C6F2.pf", _make_prefetch("MALWARE.EXE")),),
        mft_entries=(),
    )

    results = build_app_corroboration(context)

    assert results[0].score == 0
    assert results[0].assessment == (
        "Cannot be corroborated -- only one artifact type was examined."
    )
    assert results[0].examined_count == 1


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
    assert results[0].examined_count == 1

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
