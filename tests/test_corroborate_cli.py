"""Tests for :mod:`corrobora.correlation.cli`.

Parsers are replaced with fakes so the tests exercise case discovery,
file selection, failure handling, evidence collection, and output
without needing real artifact files.
"""

# pylint: disable=missing-function-docstring,too-few-public-methods,redefined-outer-name

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from corrobora.correlation import cli
from corrobora.extractors.evtx import SECURITY_AUDITING_PROVIDER
from corrobora.parsers.Base import ArtifactType
from corrobora.parsers.case_ingest import DiscoveredArtifacts
from corrobora.parsers.evtx import EventRecord
from corrobora.parsers.prefetch import PrefetchRecord
from corrobora.parsers.registry import RegistryFileError, RegistryValue

BASE = datetime(2026, 9, 27, 14, 31, 42, tzinfo=UTC)
_PS_PATH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


def _prefetch(path: str) -> PrefetchRecord:
    return PrefetchRecord(
        source_path=path,
        executable_name="POWERSHELL.EXE",
        prefetch_hash="12345678",
        filename_hash_matches=True,
        format_version=30,
        run_count=4,
        last_run_times=(BASE,),
        referenced_filenames=(),
        volumes=(),
    )


def _event() -> EventRecord:
    return EventRecord(
        record_number=1234,
        event_id=4688,
        timestamp=BASE + timedelta(seconds=5),
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


def _reg_value(key_path: str, name: str, value_type: int, data) -> RegistryValue:
    raw = data if isinstance(data, bytes) else b""
    return RegistryValue(
        key_path=key_path,
        name=name,
        value_type=value_type,
        value_type_str="",
        data=data,
        raw_data=raw.hex(),
        raw_data_bytes=raw,
    )


def _bam_bytes() -> bytes:
    delta = BASE + timedelta(seconds=9) - datetime(1601, 1, 1, tzinfo=UTC)
    ticks = (delta.days * 86_400 + delta.seconds) * 10_000_000
    return ticks.to_bytes(8, "little") + b"\x00" * 16


class FakePrefetchParser:
    """Parses any path except ones containing 'CORRUPT'."""

    def __init__(self, path):
        self.path = str(path)

    def parse(self):
        if "CORRUPT" in self.path:
            raise ValueError("bad signature")
        return _prefetch(self.path)


class FakeEvtxParser:
    """Records which files were parsed; yields one 4688 event each."""

    parsed: list[str] = []

    def __init__(self, path):
        self.path = str(path)

    def parse(self):
        FakeEvtxParser.parsed.append(Path(self.path).name)
        return [_event()]


class FakeRegistryParser:
    """A SYSTEM hive with Select -> ControlSet001, BAM only (no DAM)."""

    roots: list[str] = []

    def __init__(self, path):
        self.path = str(path)

    def parse(self, root_path=None):
        FakeRegistryParser.roots.append(root_path)
        if root_path == "Select":
            return [], [
                _reg_value(r"ROOT\Select", "Current", 4, 1),
                _reg_value(r"ROOT\Select", "Default", 4, 1),
                _reg_value(r"ROOT\Select", "LastKnownGood", 4, 1),
                _reg_value(r"ROOT\Select", "Failed", 4, 0),
            ]
        if root_path == r"ControlSet001\Services\bam":
            key = rf"ROOT\ControlSet001\Services\bam\State\UserSettings\{_SID}"
            name = r"\Device\HarddiskVolume3" + _PS_PATH[2:]
            return [], [_reg_value(key, name, 3, _bam_bytes())]
        raise RegistryFileError(f"key not found: {root_path}")


@pytest.fixture(autouse=True)
def fake_parsers(monkeypatch):
    FakeEvtxParser.parsed = []
    FakeRegistryParser.roots = []
    monkeypatch.setattr(cli, "PrefetchParser", FakePrefetchParser)
    monkeypatch.setattr(cli, "EvtxParser", FakeEvtxParser)
    monkeypatch.setattr(cli, "RegistryHiveParser", FakeRegistryParser)


def _artifacts(prefetch=(), evtx=(), registry=(), mft=()) -> DiscoveredArtifacts:
    return DiscoveredArtifacts(
        evtx_paths=tuple(evtx),
        registry_paths=tuple(registry),
        prefetch_paths=tuple(prefetch),
        mft_paths=tuple(mft),
        unclassified_count=0,
    )


class TestCollectEvidence:
    """File selection, failure handling, and examined-source accounting."""

    def test_all_three_sources_examined(self):
        result = cli.collect_evidence(
            _artifacts(["POWERSHELL.EXE-12345678.pf"], ["Security.evtx"], ["SYSTEM"])
        )
        assert result.examined == {ArtifactType.PREFETCH, ArtifactType.EVTX, ArtifactType.REGISTRY}
        assert {r.artifact_type for r in result.records} == result.examined

    def test_default_evtx_selection(self):
        evtx = ["Security.evtx", "Microsoft-Windows-Sysmon%4Operational.evtx", "System.evtx"]
        result = cli.collect_evidence(_artifacts(evtx=evtx))
        assert FakeEvtxParser.parsed == evtx[:2]
        assert result.sources[ArtifactType.EVTX].skipped == ["System.evtx"]

    def test_all_evtx_flag(self):
        evtx = ["Security.evtx", "System.evtx"]
        cli.collect_evidence(_artifacts(evtx=evtx), all_evtx=True)
        assert FakeEvtxParser.parsed == evtx

    def test_only_system_hives_examined(self):
        result = cli.collect_evidence(_artifacts(registry=["SOFTWARE", "NTUSER.DAT"]))
        assert ArtifactType.REGISTRY not in result.examined
        assert result.sources[ArtifactType.REGISTRY].skipped == ["SOFTWARE", "NTUSER.DAT"]

    def test_system_hive_walks_only_selected_bam_and_dam(self):
        cli.collect_evidence(_artifacts(registry=["SYSTEM"]))
        assert FakeRegistryParser.roots == [
            "Select",
            r"ControlSet001\Services\bam",
            r"ControlSet001\Services\dam",
        ]

    def test_failed_file_recorded_and_others_continue(self):
        result = cli.collect_evidence(
            _artifacts(["CORRUPT-00000000.pf", "POWERSHELL.EXE-12345678.pf"])
        )
        info = result.sources[ArtifactType.PREFETCH]
        assert info.parsed == ["POWERSHELL.EXE-12345678.pf"]
        assert info.failed == [("CORRUPT-00000000.pf", "bad signature")]
        assert ArtifactType.PREFETCH in result.examined

    def test_source_with_only_failures_not_examined(self):
        result = cli.collect_evidence(_artifacts(["CORRUPT-00000000.pf"]))
        assert ArtifactType.PREFETCH not in result.examined


def _case(tmp_path: Path, names: list[str]) -> Path:
    for name in names:
        (tmp_path / name).write_bytes(b"")
    return tmp_path


class TestCollectionSummary:
    """How the list of examined files is shown."""

    def _collection(self) -> cli.CollectionResult:
        result = cli.CollectionResult()
        info = result.sources[ArtifactType.PREFETCH]
        info.parsed = [f"APP{index}.EXE-00000000.pf" for index in range(8)]
        info.failed = [(f"BAD{index}.pf", "bad signature") for index in range(7)]
        return result

    def test_parsed_files_truncated_by_default(self):
        text = cli.render_collection_summary("case", timedelta(seconds=30), self._collection(), 0)
        assert text.count("parsed: APP") == 5
        assert "... and 3 more (use --list-files to show all)" in text

    def test_failed_files_always_listed(self):
        text = cli.render_collection_summary("case", timedelta(seconds=30), self._collection(), 0)
        assert text.count("failed: BAD") == 7

    def test_list_all_files(self):
        text = cli.render_collection_summary(
            "case", timedelta(seconds=30), self._collection(), 0, list_all_files=True
        )
        assert text.count("parsed: APP") == 8
        assert "more (use --list-files" not in text


class TestMain:
    """Command-line behaviour end to end, with real case discovery."""

    def test_subject_report_corroborated(self, tmp_path, capsys):
        case = _case(tmp_path, ["POWERSHELL.EXE-12345678.pf", "Security.evtx", "SYSTEM"])
        code = cli._main(  # pylint: disable=protected-access
            [str(case), "--window", "300", "--subject", r"C:\Windows\POWERSHELL.EXE"]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "Prefetch: examined -- 1 file(s) parsed, 0 failed" in out
        assert "Subject: powershell.exe" in out
        assert "Result: CORROBORATED" in out

    def test_subject_report_partial_without_system_hive(self, tmp_path, capsys):
        case = _case(tmp_path, ["POWERSHELL.EXE-12345678.pf", "Security.evtx", "SOFTWARE"])
        cli._main([str(case), "--window", "300", "--subject", "powershell.exe"])  # pylint: disable=protected-access
        out = capsys.readouterr().out
        assert "Registry: NOT examined" in out
        assert "non-SYSTEM hive(s) not examined" in out
        # Registry was not examined, so it is not expected: Prefetch and
        # EVTX alone fully corroborate.
        assert "Result: CORROBORATED" in out

    def test_list_evidence(self, tmp_path, capsys):
        case = _case(tmp_path, ["POWERSHELL.EXE-12345678.pf", "Security.evtx", "SYSTEM"])
        cli._main(  # pylint: disable=protected-access
            [str(case), "--window", "30", "--subject", "powershell.exe", "--list-evidence"]
        )
        out = capsys.readouterr().out
        assert "All execution evidence for powershell.exe (1 Prefetch, 1 EVTX, 1 Registry)" in out
        assert "2026-09-27 14:31:42.000  Prefetch  start" in out
        assert "2026-09-27 14:31:51.000  Registry  exit   BAM ControlSet001" in out

    def test_list_evidence_requires_subject(self, tmp_path, capsys):
        with pytest.raises(SystemExit) as exc:
            cli._main([str(tmp_path), "--window", "30", "--list-evidence"])  # pylint: disable=protected-access
        assert exc.value.code == 2
        assert "--list-evidence requires --subject" in capsys.readouterr().err

    def test_unknown_subject(self, tmp_path, capsys):
        case = _case(tmp_path, ["POWERSHELL.EXE-12345678.pf"])
        cli._main([str(case), "--window", "300", "--subject", "cmd.exe"])  # pylint: disable=protected-access
        assert "No execution evidence for cmd.exe" in capsys.readouterr().out

    def test_summary_without_subject(self, tmp_path, capsys):
        case = _case(tmp_path, ["POWERSHELL.EXE-12345678.pf", "Security.evtx", "SYSTEM"])
        cli._main([str(case), "--window", "300"])  # pylint: disable=protected-access
        out = capsys.readouterr().out
        assert "powershell.exe" in out
        assert "CORROBORATED" in out
        assert "Prefetch, EVTX, Registry" in out
        assert "do not establish deletion or anti-forensic activity" in out

    def test_missing_case_returns_1(self, tmp_path):
        missing = str(tmp_path / "nope")
        assert cli._main([missing, "--window", "300"]) == 1  # pylint: disable=protected-access

    @pytest.mark.parametrize("window", ["0", "-5", "abc"])
    def test_invalid_window_rejected(self, tmp_path, window):
        with pytest.raises(SystemExit) as exc:
            cli._main([str(tmp_path), "--window", window])  # pylint: disable=protected-access
        assert exc.value.code == 2

    def test_window_required(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            cli._main([str(tmp_path)])  # pylint: disable=protected-access
        assert exc.value.code == 2


class TestReproducibleOutput:
    """--relative-paths and --output give byte-identical output across locations."""

    _NAMES = ["POWERSHELL.EXE-12345678.pf", "Security.evtx", "SYSTEM"]

    def _run(self, case: Path, out_file: Path, *extra: str) -> bytes:
        cli._main(  # pylint: disable=protected-access
            [
                str(case),
                "--window",
                "30",
                "--subject",
                "powershell.exe",
                "--list-evidence",
                "--relative-paths",
                "--output",
                str(out_file),
                *extra,
            ]
        )
        return out_file.read_bytes()

    def test_same_bytes_from_different_locations(self, tmp_path):
        first = tmp_path / "one" / "demo-case"
        second = tmp_path / "somewhere" / "else" / "demo-case"
        for folder in (first, second):
            folder.mkdir(parents=True)
            _case(folder, self._NAMES)
        out_a = self._run(first, tmp_path / "a.txt")
        out_b = self._run(second, tmp_path / "b.txt")
        assert out_a == out_b

    def test_paths_are_relative_with_forward_slashes(self, tmp_path):
        case = tmp_path / "demo-case"
        (case / "Windows" / "Prefetch").mkdir(parents=True)
        (case / "Windows" / "Prefetch" / "POWERSHELL.EXE-12345678.pf").write_bytes(b"")
        (case / "Security.evtx").write_bytes(b"")
        text = self._run(case, tmp_path / "out.txt").decode("utf-8")
        assert "Case: demo-case\n" in text
        assert "parsed: Windows/Prefetch/POWERSHELL.EXE-12345678.pf" in text
        assert str(tmp_path) not in text
        assert "\\" not in text.split("Evidence")[0].split("Sources")[1]

    def test_output_uses_lf_line_endings(self, tmp_path):
        case = tmp_path / "demo-case"
        case.mkdir()
        _case(case, self._NAMES)
        data = self._run(case, tmp_path / "out.txt")
        assert b"\r\n" not in data
        assert data.endswith(b"\n")

    def test_files_processed_in_display_order(self, tmp_path):
        case = tmp_path / "demo-case"
        case.mkdir()
        _case(case, ["B.EXE-00000002.pf", "A.EXE-00000001.pf", "C.EXE-00000003.pf"])
        text = self._run(case, tmp_path / "out.txt").decode("utf-8")
        listed = [line.split("parsed: ")[1] for line in text.splitlines() if "parsed: " in line]
        assert listed == sorted(listed)

    def test_output_without_relative_paths_keeps_absolute(self, tmp_path):
        case = tmp_path / "demo-case"
        case.mkdir()
        _case(case, self._NAMES)
        out_file = tmp_path / "out.txt"
        cli._main(  # pylint: disable=protected-access
            [str(case), "--window", "30", "--output", str(out_file)]
        )
        assert str(case) in out_file.read_text(encoding="utf-8")
