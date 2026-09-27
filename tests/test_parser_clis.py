"""Tests for the ``corrobora-registry`` and ``corrobora-prefetch`` entry points.

Only argument handling is tested here; the parsers themselves are covered
by their own tests. Parser classes and run helpers are replaced with fakes
that record what they were called with.
"""

# pylint: disable=missing-function-docstring,protected-access,too-few-public-methods

from __future__ import annotations

from pathlib import Path

import pytest

from corrobora.parsers import prefetch, registry


class TestRegistryCli:
    """``corrobora-registry <hive> [root_path]``."""

    def test_help_exits_zero_and_prints_usage(self, capsys):
        with pytest.raises(SystemExit) as exc:
            registry._main(["--help"])
        assert exc.value.code == 0
        assert "usage: corrobora-registry [-h] hive [root_path]" in capsys.readouterr().out

    def test_missing_hive_exits_two(self, capsys):
        with pytest.raises(SystemExit) as exc:
            registry._main([])
        assert exc.value.code == 2
        assert "the following arguments are required: hive" in capsys.readouterr().err

    @pytest.mark.parametrize(
        ("argv", "expected"),
        [
            (["NTUSER.DAT"], ("NTUSER.DAT", None)),
            (["NTUSER.DAT", r"Software\Microsoft"], ("NTUSER.DAT", r"Software\Microsoft")),
        ],
    )
    def test_arguments_reach_the_parser(self, monkeypatch, argv, expected):
        calls = []

        class FakeParser:
            """Records the hive path and root path it was given."""

            parse_failures: list = []

            def __init__(self, hive_path):
                self.hive_path = hive_path

            def parse(self, root_path=None):
                calls.append((self.hive_path, root_path))
                return [], []

        monkeypatch.setattr(registry, "RegistryHiveParser", FakeParser)
        registry._main(argv)
        assert calls == [expected]

    def test_missing_file_still_exits_one(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            registry._main([str(tmp_path / "missing-hive")])
        assert exc.value.code == 1


class TestPrefetchCli:
    """``corrobora-prefetch <file.pf-or-folder>``."""

    def test_help_exits_zero_and_prints_usage(self, capsys):
        with pytest.raises(SystemExit) as exc:
            prefetch._main(["--help"])
        assert exc.value.code == 0
        assert "usage: corrobora-prefetch [-h] target" in capsys.readouterr().out

    def test_missing_target_exits_two(self, capsys):
        with pytest.raises(SystemExit) as exc:
            prefetch._main([])
        assert exc.value.code == 2
        assert "the following arguments are required: target" in capsys.readouterr().err

    def test_folder_goes_to_folder_run(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(prefetch, "_run_folder", lambda path: calls.append(("folder", path)))
        monkeypatch.setattr(
            prefetch, "_run_single_file", lambda path: calls.append(("file", path))
        )
        prefetch._main([str(tmp_path)])
        assert calls == [("folder", tmp_path)]

    def test_file_goes_to_single_file_run(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(prefetch, "_run_folder", lambda path: calls.append(("folder", path)))
        monkeypatch.setattr(
            prefetch, "_run_single_file", lambda path: calls.append(("file", path))
        )
        target = tmp_path / "CALC.EXE-3EA9C6F2.pf"
        prefetch._main([str(target)])
        assert calls == [("file", Path(target))]
