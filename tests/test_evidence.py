"""Tests for :mod:`corrobora.models.evidence`."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from corrobora.models.evidence import (
    EvidenceRecord,
    EvidenceType,
    TimestampSemantics,
    normalize_executable_name,
)
from corrobora.parsers.Base import ArtifactType


def _record(**overrides) -> EvidenceRecord:
    fields = {
        "artifact_type": ArtifactType.PREFETCH,
        "evidence_type": EvidenceType.PROGRAM_EXECUTION,
        "subject": "powershell.exe",
        "subject_raw": "POWERSHELL.EXE",
        "timestamp": datetime(2026, 9, 27, 14, 31, 42, tzinfo=UTC),
        "timestamp_semantics": TimestampSemantics.PREFETCH_LAST_RUN,
        "source_path": "POWERSHELL.EXE-12345678.pf",
        "record_ref": "run[0]",
    }
    fields.update(overrides)
    return EvidenceRecord(**fields)


class TestEvidenceRecord:
    """Construction and validation of EvidenceRecord."""

    def test_valid_record(self):
        record = _record(metadata={"run_count": 4})
        assert record.subject == "powershell.exe"
        assert record.metadata["run_count"] == 4

    def test_metadata_defaults_to_empty(self):
        assert not _record().metadata

    def test_none_timestamp_allowed(self):
        record = _record(timestamp=None, timestamp_semantics=TimestampSemantics.UNKNOWN)
        assert record.timestamp is None

    def test_naive_timestamp_rejected(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            _record(timestamp=datetime(2026, 9, 27, 14, 31, 42))

    def test_empty_subject_rejected(self):
        with pytest.raises(ValueError, match="subject"):
            _record(subject="")


class TestNormalizeExecutableName:
    """Executable-name normalization across artifact spellings."""

    @pytest.mark.parametrize(
        "raw",
        [
            "POWERSHELL.EXE",
            "powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE",
            '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
            "  C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe  ",
        ],
    )
    def test_variants_normalize_to_same_subject(self, raw):
        assert normalize_executable_name(raw) == "powershell.exe"

    def test_trailing_separator_yields_empty(self):
        assert normalize_executable_name("C:\\Windows\\") == ""
