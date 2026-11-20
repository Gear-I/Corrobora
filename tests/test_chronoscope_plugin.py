"""Tests for :mod:`corrobora.chronoscope_plugin`, run through Chronoscope itself.

The evidence is the synthetic reference case from
``scripts/build_reference_case.py``: real-format Prefetch v26 files and a
SYSTEM hive with BAM, ingested by Chronoscope from the case's zip.
"""

# pylint: disable=missing-function-docstring,redefined-outer-name,too-many-locals

from __future__ import annotations

import importlib.util
import json
import struct
import sys
from datetime import timedelta
from pathlib import Path

import pytest

pytest.importorskip("chronoscope")

# pylint: disable=wrong-import-position
from chronoscope.case import Case
from chronoscope.ingest import ingest
from chronoscope.parsers import ParseContext, discover

from corrobora.chronoscope_plugin import PrefetchTimelineParser, RegistryTimelineParser

_ROOT = Path(__file__).resolve().parent.parent


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, _ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


build = _load_script("build_reference_case")


@pytest.fixture
def case(tmp_path: Path):
    timeline = Case.create(tmp_path / "timeline", "TEST", "Examiner", "tester")
    yield timeline
    timeline.close()


def _events(timeline: Case, artifact: str) -> list:
    return [e for e in timeline.iter_events() if e.artifact == artifact]


def _iso(moment) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _hive(root, written=build.T0) -> bytes:
    return build.build_hive(root, written, "SYSTEM")


def _ctx(path: Path) -> ParseContext:
    return ParseContext(path.parent, path.name, "T")


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_plugins_are_registered_with_chronoscope():
    registry = discover()
    assert registry.origins["prefetch"] == "corrobora.chronoscope_plugin:PrefetchTimelineParser"
    assert registry.origins["registry"] == "corrobora.chronoscope_plugin:RegistryTimelineParser"
    assert "prefetch" not in registry.unavailable
    assert "registry" not in registry.unavailable


# --------------------------------------------------------------------------
# The reference case, end to end
# --------------------------------------------------------------------------


def test_reference_case_zip(case, tmp_path):
    archive = tmp_path / "case.zip"
    archive.write_bytes(build.build_zip(build.case_files()))

    result = ingest(case, archive, label="WS01")

    assert not result.errors
    # 12 run times and one volume per file for the 7 Prefetch files.
    assert result.per_parser["prefetch"] == 19
    # 8 keys plus 4 BAM entries.
    assert result.per_parser["registry"] == 12

    runs = {
        (e.message.split(" ")[0], e.timestamp_desc, e.datetime)
        for e in _events(case, "prefetch")
        if "Run Time" in e.timestamp_desc
    }
    delay = timedelta(milliseconds=30)
    for program in build.PROGRAMS:
        starts = sorted(program.starts, reverse=True)
        assert (program.name, "Last Run Time", _iso(starts[0] + delay)) in runs
        for start in starts[1:]:
            assert (program.name, "Previous Run Time", _iso(start + delay)) in runs

    [last_ps] = [
        e
        for e in _events(case, "prefetch")
        if e.timestamp_desc == "Last Run Time" and e.message.startswith("POWERSHELL.EXE")
    ]
    assert last_ps.message == "POWERSHELL.EXE run (count 12)"
    assert last_ps.path == f"case.zip/{build.CASE_NAME}/POWERSHELL.EXE-1A2B3C4D.pf"
    attrs = json.loads(last_ps.attributes)
    assert attrs["run_index"] == 0
    assert attrs["timestamp_semantics"] == "prefetch_last_run"
    assert attrs["filename_hash_matches"] is True
    assert attrs["executable_path"].endswith(
        r"\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE"
    )

    volumes = [e for e in _events(case, "prefetch") if e.timestamp_desc == "Volume Creation Time"]
    assert {e.datetime for e in volumes} == {"2026-01-05T08:00:00.000000Z"}

    bam = {
        e.message: e
        for e in _events(case, "registry")
        if e.timestamp_desc == "Last Execution (BAM)"
    }
    assert len(bam) == 4
    ps = bam[f"{build.DEVICE}{build._PS[2:]} (user {build.SID})"]  # pylint: disable=protected-access
    exited = build.PROGRAMS[0].bam_exit
    assert ps.datetime == _iso(exited)
    attrs = json.loads(ps.attributes)
    assert attrs["executable"] == "powershell.exe"
    assert attrs["timestamp_semantics"] == "registry_bam_last_execution"
    assert attrs["control_set"] == "ControlSet001"
    assert attrs["user_sid"] == build.SID
    assert attrs["key_path"] == rf"ControlSet001\Services\bam\State\UserSettings\{build.SID}"

    keys = {
        e.message: e for e in _events(case, "registry") if e.timestamp_desc == "Key Last Written"
    }
    assert set(keys) == {
        "(root key)",
        "ControlSet001",
        r"ControlSet001\Services",
        r"ControlSet001\Services\bam",
        r"ControlSet001\Services\bam\State",
        r"ControlSet001\Services\bam\State\UserSettings",
        rf"ControlSet001\Services\bam\State\UserSettings\{build.SID}",
        "Select",
    }
    select = json.loads(keys["Select"].attributes)
    assert select["values"] == {"Current": 1, "Default": 1, "Failed": 0, "LastKnownGood": 1}
    assert keys["Select"].datetime == _iso(build._at(15))  # pylint: disable=protected-access


def test_reingest_adds_nothing(case, tmp_path):
    archive = tmp_path / "case.zip"
    archive.write_bytes(build.build_zip(build.case_files()))
    first = ingest(case, archive, label="WS01")
    second = ingest(case, archive, label="WS01")
    assert first.inserted > 0
    assert second.inserted == 0


# --------------------------------------------------------------------------
# Prefetch details
# --------------------------------------------------------------------------


def _prefetch(**overrides) -> bytes:
    args = {
        "executable": "CMD.EXE",
        "prefetch_hash": 0x3C4D5E6F,
        "run_times": [build.T0],
        "run_count": 1,
        "referenced_files": [build.VOLUME + r"\WINDOWS\SYSTEM32\CMD.EXE"],
        "volume_device_path": build.VOLUME,
        "volume_serial": 0x5A4B3C2D,
        "volume_created": build.T0 - timedelta(days=30),
    }
    args.update(overrides)
    return build.build_prefetch(**args)


def test_prefetch_name_hash_mismatch_is_in_the_message(tmp_path):
    pf = tmp_path / "CMD.EXE-DEADBEEF.pf"
    pf.write_bytes(_prefetch())
    events = list(PrefetchTimelineParser().parse(pf, _ctx(pf)))
    [run] = [e for e in events if e.timestamp_desc == "Last Run Time"]
    assert run.message == ("CMD.EXE run (count 1); file name hash does not match the embedded hash")
    assert run.attributes["filename_hash_matches"] is False


def test_prefetch_detection(tmp_path):
    parser = PrefetchTimelineParser()
    data = _prefetch()
    assert parser.can_parse_head("CMD.EXE-3C4D5E6F.pf", data[:64])
    assert parser.can_parse_head("X.pf", b"MAM\x04" + bytes(60))  # Windows 10 compressed
    assert not parser.can_parse_head("notes.txt", data[:64])
    assert not parser.can_parse_head("X.pf", b"not prefetch")
    wrong = tmp_path / "fake.pf"
    wrong.write_bytes(b"hello world")
    assert not parser.can_parse(wrong)


# --------------------------------------------------------------------------
# Registry details
# --------------------------------------------------------------------------


def _key(name, values=(), subkeys=()):
    return build.RegistryKey(name, list(values), list(subkeys))


def test_registry_values_are_rendered_and_capped(tmp_path):
    many = [(f"V{i:03d}", build.REG_DWORD, struct.pack("<I", i)) for i in range(70)]
    run = _key(
        "Run",
        [
            ("Updater", 1, build.utf16("C:\\Users\\Public\\updater.exe\0")),
            ("Blob", build.REG_BINARY, bytes(range(100))),
            ("Long", 1, build.utf16("x" * 600 + "\0")),
            ("Multi", 7, build.utf16("one\0two\0\0")),
            ("", 1, build.utf16("default value\0")),
        ],
    )
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(_hive(_key("ROOT", [], [run, _key("Many", many)])))

    events = {e.message: e for e in RegistryTimelineParser().parse(hive, _ctx(hive))}

    values = events["Run"].attributes["values"]
    assert values["Updater"] == "C:\\Users\\Public\\updater.exe"
    assert values["Blob"] == bytes(range(64)).hex() + "... (100 bytes)"
    assert values["Long"] == "x" * 512 + "... (600 chars)"
    assert values["Multi"] == ["one", "two"]
    assert values["(default)"] == "default value"
    capped = events["Many"].attributes
    assert len(capped["values"]) == 64
    assert capped["values_truncated"] is True
    assert capped["value_count"] == 70


def test_dirty_hive_warns(tmp_path):
    data = bytearray(_hive(_key("ROOT")))
    struct.pack_into("<I", data, 8, 2)  # secondary sequence number behind the primary
    hive = tmp_path / "SOFTWARE"
    hive.write_bytes(bytes(data))
    ctx = _ctx(hive)
    events = list(RegistryTimelineParser().parse(hive, ctx))
    assert len(events) == 1
    assert any("unflushed changes" in warning for warning in ctx.warnings)


def test_registry_detection_skips_transaction_logs(tmp_path):
    parser = RegistryTimelineParser()
    data = _hive(_key("ROOT"))
    assert parser.can_parse_head("SYSTEM", data[:64])
    assert not parser.can_parse_head("SYSTEM.LOG1", data[:64])
    assert not parser.can_parse_head("SYSTEM", b"not a hive")
    log = tmp_path / "NTUSER.DAT.LOG2"
    log.write_bytes(data)
    assert not parser.can_parse(log)
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(data)
    assert parser.can_parse(hive)
