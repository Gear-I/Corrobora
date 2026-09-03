"""Unit tests for :mod:`case_ingest`.

Uses real (empty-content) files on disk within pytest's ``tmp_path``
fixture -- classification is filename/extension-based and doesn't
require valid artifact file contents, so these tests exercise real
filesystem discovery without needing genuine forensic data.
"""

# pylint: disable=missing-function-docstring
# Test function names are self-descriptive; per-test docstrings would
# just restate the name.

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from corrobora.parsers.case_ingest import (
    DiscoveredArtifacts,
    InvalidCasePathError,
    discover_artifacts,
    load_case,
)


def _touch(path: Path) -> None:
    """Create an empty file, including any missing parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")


class TestDiscoverArtifacts:
    """Tests for folder-based artifact discovery."""

    def test_raises_on_missing_folder(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist"
        with pytest.raises(InvalidCasePathError, match="not found"):
            discover_artifacts(missing)

    def test_raises_on_file_not_directory(self, tmp_path: Path) -> None:
        a_file = tmp_path / "not_a_dir.txt"
        _touch(a_file)
        with pytest.raises(InvalidCasePathError, match="not a directory"):
            discover_artifacts(a_file)

    def test_classifies_evtx_files(self, tmp_path: Path) -> None:
        _touch(tmp_path / "Security.evtx")
        _touch(tmp_path / "sub" / "System.EVTX")  # case-insensitive

        result = discover_artifacts(tmp_path)

        assert len(result.evtx_paths) == 2

    def test_classifies_registry_hives_by_exact_name(self, tmp_path: Path) -> None:
        _touch(tmp_path / "SYSTEM")
        _touch(tmp_path / "software")  # case-insensitive
        _touch(tmp_path / "NTUSER.DAT")
        _touch(tmp_path / "not_a_hive_named_similarly")

        result = discover_artifacts(tmp_path)

        assert len(result.registry_paths) == 3

    def test_classifies_prefetch_files(self, tmp_path: Path) -> None:
        _touch(tmp_path / "CALC.EXE-3EA9C6F2.pf")
        _touch(tmp_path / "notes.txt")

        result = discover_artifacts(tmp_path)

        assert len(result.prefetch_paths) == 1
        assert result.unclassified_count == 1

    def test_classifies_mft_by_various_naming_conventions(self, tmp_path: Path) -> None:
        _touch(tmp_path / "$MFT")
        _touch(tmp_path / "vol2" / "MFT")
        _touch(tmp_path / "vol3" / "C_MFT")  # KAPE-style naming

        result = discover_artifacts(tmp_path)

        assert len(result.mft_paths) == 3

    def test_unclassified_files_are_counted_not_listed(self, tmp_path: Path) -> None:
        _touch(tmp_path / "random_file.docx")
        _touch(tmp_path / "another.log")

        result = discover_artifacts(tmp_path)

        assert result.unclassified_count == 2
        assert result.total_count == 0

    def test_recursive_discovery_across_nested_directories(self, tmp_path: Path) -> None:
        _touch(tmp_path / "a" / "b" / "c" / "Deep.evtx")

        result = discover_artifacts(tmp_path)

        assert len(result.evtx_paths) == 1

    def test_empty_folder_produces_empty_result(self, tmp_path: Path) -> None:
        result = discover_artifacts(tmp_path)

        assert result == DiscoveredArtifacts(
            evtx_paths=(), registry_paths=(), prefetch_paths=(), mft_paths=(),
            unclassified_count=0,
        )
        assert result.total_count == 0


class TestLoadCaseFromZip:
    """Tests for zip-archive-based case loading."""

    def test_discovers_artifacts_inside_a_zip(self, tmp_path: Path) -> None:
        source_dir = tmp_path / "source"
        _touch(source_dir / "Security.evtx")
        _touch(source_dir / "SYSTEM")
        _touch(source_dir / "app.pf")
        _touch(source_dir / "C_MFT")

        zip_path = tmp_path / "case.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for f in source_dir.rglob("*"):
                if f.is_file():
                    zf.write(f, f.relative_to(source_dir))

        result = load_case(zip_path)

        assert result.total_count == 4

    def test_rejects_zip_slip_path_traversal(self, tmp_path: Path) -> None:
        zip_path = tmp_path / "evil.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("normal.evtx", b"fake")
            zf.writestr("../../../escape.txt", b"malicious")

        with pytest.raises(InvalidCasePathError, match="path traversal"):
            load_case(zip_path)

    def test_raises_on_missing_path(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidCasePathError, match="not found"):
            load_case(tmp_path / "nope.zip")

    def test_raises_on_non_zip_non_directory_file(self, tmp_path: Path) -> None:
        text_file = tmp_path / "notes.txt"
        _touch(text_file)
        with pytest.raises(InvalidCasePathError, match="directory or a .zip"):
            load_case(text_file)

    def test_raises_on_corrupt_zip(self, tmp_path: Path) -> None:
        fake_zip = tmp_path / "corrupt.zip"
        fake_zip.write_bytes(b"this is not a real zip file")
        with pytest.raises(InvalidCasePathError, match="Could not open"):
            load_case(fake_zip)

    def test_load_case_on_directory_delegates_to_discover_artifacts(
        self, tmp_path: Path
    ) -> None:
        _touch(tmp_path / "Security.evtx")
        result = load_case(tmp_path)
        assert len(result.evtx_paths) == 1
