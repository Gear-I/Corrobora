"""Tests for :mod:`corrobora.extractors.evtx`."""

# pylint: disable=missing-function-docstring,too-few-public-methods

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from corrobora.extractors.evtx import (
    SECURITY_AUDITING_PROVIDER,
    SYSMON_PROVIDER,
    extract_evtx_evidence,
)
from corrobora.models.evidence import EvidenceType, TimestampSemantics
from corrobora.parsers.Base import ArtifactType
from corrobora.parsers.evtx import EventRecord

_PS_IMAGE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_TIME = datetime(2026, 9, 27, 14, 31, 47, tzinfo=UTC)


def _xml(fields: dict[str, str]) -> str:
    data = "".join(f'<Data Name="{name}">{value}</Data>' for name, value in fields.items())
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f"<System/><EventData>{data}</EventData></Event>"
    )


def _record(event_id: int, provider: str, fields: dict[str, str], **overrides) -> EventRecord:
    values = {
        "record_number": 1234,
        "event_id": event_id,
        "timestamp": _TIME,
        "provider_name": provider,
        "computer_name": "WS01",
        "channel": "Security",
        "level": 0,
        "message": None,
        "raw_xml": _xml(fields),
    }
    values.update(overrides)
    return EventRecord(**values)


_SECURITY_4688_FIELDS = {
    "SubjectUserName": "alice",
    "SubjectDomainName": "CORP",
    "SubjectLogonId": "0x3e7",
    "NewProcessId": "0x1a2c",
    "NewProcessName": _PS_IMAGE,
    "ProcessId": "0x0f10",
    "CommandLine": "powershell.exe -NoProfile",
    "ParentProcessName": r"C:\Windows\explorer.exe",
}

_SYSMON_1_FIELDS = {
    "UtcTime": "2026-09-27 14:31:46.998",
    "ProcessGuid": "{aaaa-bbbb}",
    "ProcessId": "6700",
    "Image": _PS_IMAGE,
    "OriginalFileName": "PowerShell.EXE",
    "CommandLine": "powershell.exe -NoProfile",
    "User": r"CORP\alice",
    "LogonId": "0x3e7",
    "Hashes": "SHA256=ABCD",
    "ParentProcessId": "3856",
    "ParentImage": r"C:\Windows\explorer.exe",
}


class TestSecurity4688:
    """Security 4688 process-creation events."""

    def test_extracts_execution_evidence(self):
        evidence = extract_evtx_evidence(
            _record(4688, SECURITY_AUDITING_PROVIDER, _SECURITY_4688_FIELDS), "Security.evtx"
        )
        assert len(evidence) == 1
        item = evidence[0]
        assert item.artifact_type is ArtifactType.EVTX
        assert item.evidence_type is EvidenceType.PROGRAM_EXECUTION
        assert item.subject == "powershell.exe"
        assert item.subject_raw == _PS_IMAGE
        assert item.timestamp == _TIME
        assert item.timestamp_semantics is TimestampSemantics.EVTX_TIME_CREATED
        assert item.source_path == "Security.evtx"
        assert item.record_ref == "record[1234]"

    def test_metadata(self):
        metadata = extract_evtx_evidence(
            _record(4688, SECURITY_AUDITING_PROVIDER, _SECURITY_4688_FIELDS), "Security.evtx"
        )[0].metadata
        assert metadata["event_id"] == 4688
        assert metadata["channel"] == "Security"
        assert metadata["computer_name"] == "WS01"
        assert metadata["process_id"] == "0x1a2c"
        assert metadata["parent_process_id"] == "0x0f10"
        assert metadata["parent_image"] == r"C:\Windows\explorer.exe"
        assert metadata["command_line"] == "powershell.exe -NoProfile"
        assert metadata["user"] == "alice"
        assert metadata["user_domain"] == "CORP"
        assert metadata["event_data"] == _SECURITY_4688_FIELDS

    def test_optional_fields_absent_become_none(self):
        fields = {"NewProcessName": _PS_IMAGE}
        metadata = extract_evtx_evidence(
            _record(4688, SECURITY_AUDITING_PROVIDER, fields), "Security.evtx"
        )[0].metadata
        assert metadata["command_line"] is None
        assert metadata["parent_image"] is None


class TestSysmon1:
    """Sysmon Event ID 1 process-creation events."""

    def test_extracts_execution_evidence_with_sysmon_fields(self):
        evidence = extract_evtx_evidence(
            _record(
                1, SYSMON_PROVIDER, _SYSMON_1_FIELDS, channel="Microsoft-Windows-Sysmon/Operational"
            ),
            "Sysmon.evtx",
        )
        assert len(evidence) == 1
        item = evidence[0]
        assert item.subject == "powershell.exe"
        assert item.timestamp == _TIME
        assert item.metadata["sysmon_utc_time"] == "2026-09-27 14:31:46.998"
        assert item.metadata["process_guid"] == "{aaaa-bbbb}"
        assert item.metadata["hashes"] == "SHA256=ABCD"
        assert item.metadata["original_file_name"] == "PowerShell.EXE"
        assert item.metadata["user"] == r"CORP\alice"


class TestIgnoredRecords:
    """Records that must not produce execution evidence."""

    def test_event_id_1_from_other_provider(self):
        record = _record(1, "Microsoft-Windows-Kernel-General", {"Image": _PS_IMAGE})
        assert not extract_evtx_evidence(record, "System.evtx")

    def test_4688_from_other_provider(self):
        record = _record(4688, "Some-Other-Provider", _SECURITY_4688_FIELDS)
        assert not extract_evtx_evidence(record, "Security.evtx")

    def test_unrelated_event_id(self):
        record = _record(4624, SECURITY_AUDITING_PROVIDER, _SECURITY_4688_FIELDS)
        assert not extract_evtx_evidence(record, "Security.evtx")

    def test_missing_event_id_or_provider(self):
        record = _record(4688, SECURITY_AUDITING_PROVIDER, _SECURITY_4688_FIELDS)
        assert not extract_evtx_evidence(replace(record, event_id=None), "Security.evtx")
        assert not extract_evtx_evidence(replace(record, provider_name=None), "Security.evtx")

    def test_missing_image_field(self):
        record = _record(4688, SECURITY_AUDITING_PROVIDER, {"SubjectUserName": "alice"})
        assert not extract_evtx_evidence(record, "Security.evtx")

    def test_unparseable_xml(self):
        record = _record(4688, SECURITY_AUDITING_PROVIDER, {}, raw_xml="<Event")
        assert not extract_evtx_evidence(record, "Security.evtx")
