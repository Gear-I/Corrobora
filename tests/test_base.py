"""Tests for :mod:`corrobora.parsers.base` and its implementation across
all four concrete parsers.

Confirms every parser correctly implements the shared
``BaseArtifactParser`` interface, and that ``parse_common()`` produces
correctly normalized ``ArtifactRecord`` objects. MFT is tested against
real, spec-correct binary data (its parser has no third-party
dependency and can generate valid synthetic input); the other three
are tested with mocked underlying data, consistent with how their own
native-API tests are written.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from corrobora.parsers.Base import (
    ArtifactRecord,
    ArtifactType,
    BaseArtifactParser,
    ParseFailure,
)
from corrobora.parsers.evtx import EventRecord, EvtxParser
from corrobora.parsers.mft import MftParser
from corrobora.parsers.prefetch import PrefetchParser, PrefetchRecord
from corrobora.parsers.registry import (
    RegistryHiveParser,
    RegistryKey,
    RegistryValue,
)


class TestBaseArtifactParserContract:
    """Tests for the abstract interface itself."""

    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            BaseArtifactParser("some_file")  # type: ignore[abstract]

    def test_all_four_parsers_are_subclasses(self) -> None:
        for cls in (EvtxParser, RegistryHiveParser, PrefetchParser, MftParser):
            assert issubclass(cls, BaseArtifactParser)

    def test_all_four_parsers_declare_distinct_artifact_types(self) -> None:
        types = {
            EvtxParser.artifact_type,
            RegistryHiveParser.artifact_type,
            PrefetchParser.artifact_type,
            MftParser.artifact_type,
        }
        assert types == {
            ArtifactType.EVTX,
            ArtifactType.REGISTRY,
            ArtifactType.PREFETCH,
            ArtifactType.MFT,
        }

    def test_require_existing_file_raises_on_missing(self, tmp_path: Path) -> None:
        parser = MftParser(tmp_path / "does_not_exist")
        with pytest.raises(Exception):  # noqa: B017 -- ArtifactFileError, checked below
            parser._require_existing_file()  # pylint: disable=protected-access

    def test_require_existing_file_raises_on_directory(self, tmp_path: Path) -> None:
        parser = MftParser(tmp_path)
        with pytest.raises(Exception):  # noqa: B017
            parser._require_existing_file()  # pylint: disable=protected-access


class TestMftParseCommon:
    """Tests for MftParser.parse_common() against real synthetic binary data."""

    def test_parse_common_returns_artifact_records(self, tmp_path: Path) -> None:
        from mft_fixtures import build_mft_record  # type: ignore[import-not-found]

        mft_file = tmp_path / "MFT"
        record = build_mft_record(filename="normal.exe")
        mft_file.write_bytes(record)

        parser: BaseArtifactParser = MftParser(mft_file)
        common_records = parser.parse_common()

        assert len(common_records) == 1
        assert isinstance(common_records[0], ArtifactRecord)
        assert common_records[0].artifact_type == ArtifactType.MFT
        assert "normal.exe" in common_records[0].summary
        assert common_records[0].metadata["likely_timestomped"] is False

    def test_parse_common_flags_timestomping_in_summary(self, tmp_path: Path) -> None:
        from mft_fixtures import build_mft_record  # type: ignore[import-not-found]

        mft_file = tmp_path / "MFT"
        backdated = datetime(2010, 1, 1, tzinfo=UTC)
        real_creation = datetime(2024, 6, 1, tzinfo=UTC)
        record = build_mft_record(
            si_creation=backdated,
            si_modification=backdated,
            si_mft_modification=backdated,
            si_access=backdated,
            fn_creation=real_creation,
            fn_modification=real_creation,
            fn_mft_modification=real_creation,
            fn_access=real_creation,
            filename="evil.exe",
        )
        mft_file.write_bytes(record)

        parser = MftParser(mft_file)
        common_records = parser.parse_common()

        assert "[LIKELY TIMESTOMPED]" in common_records[0].summary
        assert common_records[0].metadata["likely_timestomped"] is True

    def test_get_common_failures_reflects_native_failures(self, tmp_path: Path) -> None:
        mft_file = tmp_path / "MFT"
        baad = bytearray(1024)
        baad[0:4] = b"BAAD"
        mft_file.write_bytes(bytes(baad))

        parser = MftParser(mft_file)
        parser.parse_common()
        failures = parser.get_common_failures()

        assert len(failures) == 1
        assert isinstance(failures[0], ParseFailure)
        assert failures[0].identifier == "0"


class TestEvtxParseCommon:
    """Tests for EvtxParser.parse_common() using its own native EventRecord model."""

    def test_parse_common_maps_fields_correctly(self) -> None:
        parser = EvtxParser("dummy.evtx")
        record = EventRecord(
            record_number=5,
            event_id=4688,
            timestamp=datetime(2024, 1, 1, tzinfo=UTC),
            provider_name="Microsoft-Windows-Security-Auditing",
            computer_name="HOST01",
            channel="Security",
            level=0,
            message="a process was created",
            raw_xml="<Event/>",
        )
        common = parser._to_common_record(record)  # pylint: disable=protected-access

        assert common.artifact_type == ArtifactType.EVTX
        assert common.record_id == "5"
        assert common.timestamp == record.timestamp
        assert "4688" in common.summary
        assert common.metadata["provider_name"] == "Microsoft-Windows-Security-Auditing"
        assert common.raw is record


class TestRegistryParseCommon:
    """Tests for RegistryHiveParser.parse_common() field mapping."""

    def test_key_to_common_record(self) -> None:
        parser = RegistryHiveParser("dummy_hive")
        key = RegistryKey(
            path="Software\\Test",
            name="Test",
            last_written=datetime(2024, 1, 1, tzinfo=UTC),
            subkey_count=2,
            value_count=3,
        )
        common = parser._key_to_common_record(key)  # pylint: disable=protected-access

        assert common.artifact_type == ArtifactType.REGISTRY
        assert common.record_id == "KEY:Software\\Test"
        assert common.timestamp == key.last_written

    def test_value_to_common_record(self) -> None:
        parser = RegistryHiveParser("dummy_hive")
        value = RegistryValue(
            key_path="Software\\Test",
            name="Updater",
            value_type=1,
            value_type_str="RegSZ",
            data="C:\\evil.exe",
            raw_data="00",
            raw_data_bytes=b"\x00",
        )
        common = parser._value_to_common_record(value)  # pylint: disable=protected-access

        assert common.artifact_type == ArtifactType.REGISTRY
        assert common.record_id == "VALUE:Software\\Test\\Updater"
        assert common.timestamp is None
        assert common.metadata["data"] == "C:\\evil.exe"


class TestPrefetchParseCommon:
    """Tests for PrefetchParser.parse_common() field mapping."""

    def test_parse_common_wraps_single_record(self) -> None:
        parser = PrefetchParser("dummy.pf")
        record = PrefetchRecord(
            source_path="CALC.EXE-3EA9C6F2.pf",
            executable_name="CALC.EXE",
            prefetch_hash="3EA9C6F2",
            filename_hash_matches=True,
            format_version=30,
            run_count=5,
            last_run_times=(datetime(2024, 3, 15, tzinfo=UTC),),
            referenced_filenames=(),
            volumes=(),
        )

        from unittest import mock

        with mock.patch.object(PrefetchParser, "parse", return_value=record):
            common_records = parser.parse_common()

        assert len(common_records) == 1
        common = common_records[0]
        assert common.artifact_type == ArtifactType.PREFETCH
        assert common.record_id == "3EA9C6F2"
        assert common.timestamp == record.last_run_times[0]
        assert "CALC.EXE" in common.summary