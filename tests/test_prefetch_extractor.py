"""Tests for :mod:`corrobora.extractors.prefetch`."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

from datetime import UTC, datetime

from corrobora.extractors.prefetch import extract_prefetch_evidence
from corrobora.models.evidence import EvidenceType, TimestampSemantics
from corrobora.parsers.Base import ArtifactType
from corrobora.parsers.prefetch import PrefetchRecord, VolumeInfo

_PS_PATH = r"\VOLUME{01d7}\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE"
_RUN_TIMES = (
    datetime(2026, 9, 27, 14, 31, 42, tzinfo=UTC),
    datetime(2026, 9, 26, 9, 5, 0, tzinfo=UTC),
    datetime(2026, 9, 20, 18, 0, 0, tzinfo=UTC),
)


def _record(**overrides) -> PrefetchRecord:
    fields = {
        "source_path": "POWERSHELL.EXE-12345678.pf",
        "executable_name": "POWERSHELL.EXE",
        "prefetch_hash": "12345678",
        "filename_hash_matches": True,
        "format_version": 30,
        "run_count": 4,
        "last_run_times": _RUN_TIMES,
        "referenced_filenames": (r"\VOLUME{01d7}\WINDOWS\SYSTEM32\NTDLL.DLL", _PS_PATH),
        "volumes": (VolumeInfo(r"\VOLUME{01d7}", "A1B2C3D4", None),),
    }
    fields.update(overrides)
    return PrefetchRecord(**fields)


class TestExtractPrefetchEvidence:
    """Mapping a PrefetchRecord to per-run EvidenceRecords."""

    def test_one_record_per_run_time_most_recent_first(self):
        evidence = extract_prefetch_evidence(_record())
        assert [e.timestamp for e in evidence] == list(_RUN_TIMES)
        assert [e.record_ref for e in evidence] == ["run[0]", "run[1]", "run[2]"]
        assert [e.metadata["run_index"] for e in evidence] == [0, 1, 2]

    def test_common_fields(self):
        first = extract_prefetch_evidence(_record())[0]
        assert first.artifact_type is ArtifactType.PREFETCH
        assert first.evidence_type is EvidenceType.PROGRAM_EXECUTION
        assert first.timestamp_semantics is TimestampSemantics.PREFETCH_LAST_RUN
        assert first.subject == "powershell.exe"
        assert first.subject_raw == "POWERSHELL.EXE"
        assert first.source_path == "POWERSHELL.EXE-12345678.pf"

    def test_metadata_preserves_artifact_details(self):
        metadata = extract_prefetch_evidence(_record())[0].metadata
        assert metadata["run_count"] == 4
        assert metadata["run_times_recorded"] == 3
        assert metadata["prefetch_hash"] == "12345678"
        assert metadata["filename_hash_matches"] is True
        assert metadata["format_version"] == 30
        assert metadata["subject_possibly_truncated"] is False
        assert metadata["executable_path"] == _PS_PATH
        assert metadata["volumes"] == (
            {"device_path": r"\VOLUME{01d7}", "serial_number": "A1B2C3D4"},
        )

    def test_no_run_times_yields_single_untimed_record(self):
        evidence = extract_prefetch_evidence(_record(last_run_times=()))
        assert len(evidence) == 1
        assert evidence[0].timestamp is None
        assert evidence[0].record_ref == "run[unknown]"
        assert evidence[0].metadata["run_index"] is None

    def test_missing_executable_name_yields_nothing(self):
        assert not extract_prefetch_evidence(_record(executable_name=None))
        assert not extract_prefetch_evidence(_record(executable_name=""))

    def test_executable_path_none_when_not_referenced(self):
        evidence = extract_prefetch_evidence(_record(referenced_filenames=()))
        assert evidence[0].metadata["executable_path"] is None

    def test_truncated_name_flagged_and_path_matched_by_prefix(self):
        full_name = "MICROSOFTEDGEUPDATEBROKER.EXE.BAK.EXE"
        truncated = full_name[:29]
        path = rf"\VOLUME{{01d7}}\PROGRAM FILES\{full_name}"
        evidence = extract_prefetch_evidence(
            _record(executable_name=truncated, referenced_filenames=(path,))
        )
        assert evidence[0].metadata["subject_possibly_truncated"] is True
        assert evidence[0].metadata["executable_path"] == path
