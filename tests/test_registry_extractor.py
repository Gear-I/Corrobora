"""Tests for :mod:`corrobora.extractors.registry`."""

# pylint: disable=missing-function-docstring,too-few-public-methods

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from corrobora.extractors.registry import extract_registry_evidence
from corrobora.models.evidence import EvidenceType, TimestampSemantics
from corrobora.parsers.Base import ArtifactType
from corrobora.parsers.registry import RegistryValue

_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
_BAM_KEY = rf"ROOT\ControlSet001\Services\bam\State\UserSettings\{_SID}"
_PS_DEVICE_PATH = (
    r"\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)
_TIME = datetime(2026, 9, 27, 14, 31, 51, tzinfo=UTC)


def _filetime(moment: datetime) -> bytes:
    delta = moment - datetime(1601, 1, 1, tzinfo=UTC)
    ticks = (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10
    return ticks.to_bytes(8, "little")


def _value(
    key_path: str = _BAM_KEY,
    name: str = _PS_DEVICE_PATH,
    value_type: int = 3,
    data: bytes | None = None,
) -> RegistryValue:
    raw = _filetime(_TIME) + b"\x00" * 16 if data is None else data
    return RegistryValue(
        key_path=key_path,
        name=name,
        value_type=value_type,
        value_type_str="RegBin",
        data=raw,
        raw_data=raw.hex(),
        raw_data_bytes=raw,
    )


class TestBamEntries:
    """BAM/DAM executable values that should produce evidence."""

    def test_extracts_execution_evidence(self):
        evidence = extract_registry_evidence(_value(), "SYSTEM")
        assert len(evidence) == 1
        item = evidence[0]
        assert item.artifact_type is ArtifactType.REGISTRY
        assert item.evidence_type is EvidenceType.PROGRAM_EXECUTION
        assert item.subject == "powershell.exe"
        assert item.subject_raw == _PS_DEVICE_PATH
        assert item.timestamp == _TIME
        assert item.timestamp_semantics is TimestampSemantics.REGISTRY_BAM_LAST_EXECUTION
        assert item.source_path == "SYSTEM"
        assert item.record_ref == f"{_BAM_KEY}\\{_PS_DEVICE_PATH}"

    def test_metadata(self):
        metadata = extract_registry_evidence(_value(), "SYSTEM")[0].metadata
        assert metadata["moderator"] == "bam"
        assert metadata["control_set"] == "ControlSet001"
        assert metadata["user_sid"] == _SID
        assert metadata["key_path"] == _BAM_KEY

    @pytest.mark.parametrize(
        "key_path",
        [
            rf"ROOT\ControlSet001\Services\bam\UserSettings\{_SID}",
            rf"CMI-CreateHive{{ABC}}\controlset002\services\BAM\state\usersettings\{_SID}",
        ],
    )
    def test_layout_and_case_variants(self, key_path):
        evidence = extract_registry_evidence(_value(key_path=key_path), "SYSTEM")
        assert len(evidence) == 1
        assert evidence[0].metadata["user_sid"] == _SID

    def test_dam(self):
        key_path = rf"ROOT\ControlSet001\Services\dam\State\UserSettings\{_SID}"
        evidence = extract_registry_evidence(_value(key_path=key_path), "SYSTEM")
        assert evidence[0].metadata["moderator"] == "dam"

    def test_zero_filetime_gives_untimed_record(self):
        evidence = extract_registry_evidence(_value(data=b"\x00" * 24), "SYSTEM")
        assert len(evidence) == 1
        assert evidence[0].timestamp is None

    def test_out_of_range_filetime_gives_untimed_record(self):
        evidence = extract_registry_evidence(_value(data=b"\xff" * 24), "SYSTEM")
        assert evidence[0].timestamp is None


class TestIgnoredValues:
    """Values that must not produce execution evidence."""

    def test_non_bam_key(self):
        key_path = r"ROOT\Microsoft\Windows\CurrentVersion\Run"
        assert not extract_registry_evidence(_value(key_path=key_path), "SOFTWARE")

    @pytest.mark.parametrize(
        "key_path",
        [
            r"ROOT\ControlSet001\Services\bam\State\UserSettings",
            rf"ROOT\ControlSet001\Services\bam\State\UserSettings\{_SID}\Extra",
            r"ROOT\ControlSet001\Services\bam\State",
        ],
    )
    def test_wrong_depth_under_bam(self, key_path):
        assert not extract_registry_evidence(_value(key_path=key_path), "SYSTEM")

    def test_bookkeeping_dword_values(self):
        for name in ("Version", "SequenceNumber"):
            value = _value(name=name, value_type=4, data=b"\x01\x00\x00\x00")
            assert not extract_registry_evidence(value, "SYSTEM")

    def test_packaged_app_entry(self):
        value = _value(name="Microsoft.Windows.Photos_8wekyb3d8bbwe")
        assert not extract_registry_evidence(value, "SYSTEM")

    def test_non_binary_or_short_data(self):
        assert not extract_registry_evidence(_value(value_type=1), "SYSTEM")
        assert not extract_registry_evidence(_value(data=b"\x00" * 4), "SYSTEM")
