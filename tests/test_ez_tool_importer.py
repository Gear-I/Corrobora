"""Unit tests for :mod:`corrobora.parsers.ez_tools_import`.

Uses a hand-built CSV matching EvtxECmd's confirmed real column
schema (verified against actual shared EvtxECmd output, not
guessed), so these tests exercise genuine field-mapping correctness
rather than an assumed schema.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from corrobora.parsers.Base import ArtifactRecord, ArtifactType
from corrobora.parsers.ez_tool_importer import (
    EzToolsCsvParser,
    EzToolsFileError,
    UnsupportedEzToolError,
    discover_ez_tools_csvs,
)

_EVTXECMD_HEADER = (
    "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,"
    "ProcessId,ThreadId,Computer,ChunkNumber,UserId,MapDescription,UserName,"
    "RemoteHost,PayloadData1,PayloadData2,PayloadData3,PayloadData4,"
    "PayloadData5,PayloadData6,ExecutableInfo,HiddenRecord,SourceFile,"
    "Keywords,ExtraDataOffset"
)


def _write_evtxecmd_csv(path: Path, rows: list[str]) -> None:
    """Write a synthetic EvtxECmd-format CSV file."""
    path.write_text(_EVTXECMD_HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")


class TestDiscoverEzToolsCsvs:
    """Tests for folder-based EZ Tools CSV discovery and classification."""

    def test_raises_on_missing_folder(self, tmp_path: Path) -> None:
        with pytest.raises(EzToolsFileError, match="not found"):
            discover_ez_tools_csvs(tmp_path / "nope")

    def test_raises_on_file_not_directory(self, tmp_path: Path) -> None:
        a_file = tmp_path / "not_a_dir.csv"
        a_file.write_text("x")
        with pytest.raises(EzToolsFileError, match="not a directory"):
            discover_ez_tools_csvs(a_file)

    def test_classifies_by_filename_case_insensitively(self, tmp_path: Path) -> None:
        (tmp_path / "20240408132435_EvtxECmd_Output.csv").write_text("x")
        (tmp_path / "20240408132435_recmd_output.csv").write_text("x")
        (tmp_path / "20240408132435_PECMD_OUTPUT.csv").write_text("x")
        (tmp_path / "20240408132435_MFTECmd_Output.csv").write_text("x")
        (tmp_path / "20240408132435_AmcacheParser_Output.csv").write_text("x")

        result = discover_ez_tools_csvs(tmp_path)

        assert len(result.evtxecmd_csvs) == 1
        assert len(result.recmd_csvs) == 1
        assert len(result.pecmd_csvs) == 1
        assert len(result.mftecmd_csvs) == 1
        assert len(result.amcacheparser_csvs) == 1
        assert result.total_count == 5

    def test_unclassified_files_are_counted_not_listed(self, tmp_path: Path) -> None:
        (tmp_path / "notes.csv").write_text("x")
        (tmp_path / "random_export.csv").write_text("x")

        result = discover_ez_tools_csvs(tmp_path)

        assert result.unclassified_count == 2
        assert result.total_count == 0

    def test_recursive_discovery(self, tmp_path: Path) -> None:
        nested = tmp_path / "EVTX"
        nested.mkdir()
        (nested / "20240408132435_EvtxECmd_Output.csv").write_text("x")

        result = discover_ez_tools_csvs(tmp_path)

        assert len(result.evtxecmd_csvs) == 1


class TestEzToolsCsvParserEvtxEcmd:
    """Tests for parsing real-schema EvtxECmd CSV output."""

    def test_parses_confirmed_real_schema_correctly(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "20240408132435_EvtxECmd_Output.csv"
        _write_evtxecmd_csv(
            csv_path,
            [
                (
                    "101,101,2024-02-14T03:41:58.4101450+00:00,4688,0,"
                    "Microsoft-Windows-Security-Auditing,Security,4,8,"
                    "DESKTOP-887GK2L,0,S-1-5-18,A new process has been created,"
                    "CyberJunkie,,ProcessID: 10672,,,,,,"
                    "C:\\Users\\CyberJunkie\\Downloads\\evil.exe,False,"
                    "Security.evtx,Audit Success,0"
                ),
            ],
        )

        parser = EzToolsCsvParser(csv_path)
        records = parser.parse_common()

        assert len(records) == 1
        record = records[0]
        assert isinstance(record, ArtifactRecord)
        assert record.artifact_type == ArtifactType.EVTX
        assert record.record_id == "101"
        assert record.timestamp is not None
        assert record.timestamp.year == 2024
        assert record.timestamp.month == 2
        assert "4688" in record.summary
        assert record.metadata["source_tool"] == "EvtxECmd"
        assert record.metadata["provider_name"] == "Microsoft-Windows-Security-Auditing"
        assert record.metadata["payload_data_1"] == "ProcessID: 10672"
        assert parser.get_common_failures() == []

    def test_multiple_rows(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "20240408132435_EvtxECmd_Output.csv"
        row_template = (
            "{rn},{rn},2024-02-14T03:41:58.4101450+00:00,4688,0,Provider,"
            "Security,4,8,HOST,0,S-1-5-18,desc,user,,,,,,,,exe,False,"
            "Security.evtx,Audit Success,0"
        )
        _write_evtxecmd_csv(csv_path, [row_template.format(rn=n) for n in (1, 2, 3)])

        parser = EzToolsCsvParser(csv_path)
        records = parser.parse_common()

        assert len(records) == 3
        assert [r.record_id for r in records] == ["1", "2", "3"]

    def test_missing_timestamp_produces_none_not_failure(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "20240408132435_EvtxECmd_Output.csv"
        _write_evtxecmd_csv(
            csv_path,
            [
                (
                    "1,1,,4688,0,Provider,Security,4,8,HOST,0,S-1-5-18,desc,"
                    "user,,,,,,,,exe,False,Security.evtx,Audit Success,0"
                ),
            ],
        )

        parser = EzToolsCsvParser(csv_path)
        records = parser.parse_common()

        assert len(records) == 1
        assert records[0].timestamp is None
        assert parser.get_common_failures() == []

    def test_raises_on_missing_file(self, tmp_path: Path) -> None:
        parser = EzToolsCsvParser(tmp_path / "20240408132435_EvtxECmd_Output.csv")
        with pytest.raises(EzToolsFileError, match="not found"):
            parser.parse_common()

    def test_raises_on_unrecognized_filename(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "some_random_export.csv"
        csv_path.write_text(_EVTXECMD_HEADER + "\n")

        parser = EzToolsCsvParser(csv_path)
        with pytest.raises(EzToolsFileError, match="Could not identify"):
            parser.parse_common()

    def test_raises_unsupported_tool_error_for_recognized_but_unimplemented(
        self, tmp_path: Path
    ) -> None:
        csv_path = tmp_path / "20240408132435_RECmd_Output.csv"
        csv_path.write_text("SomeColumn\nvalue\n")

        parser = EzToolsCsvParser(csv_path)
        with pytest.raises(UnsupportedEzToolError, match="not implemented yet"):
            parser.parse_common()