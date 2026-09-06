"""Unit tests for corrobora.parsers.disk_image.

Only the pure, framework-independent logic is covered here (image-type
detection from a file extension). Building a real, valid disk image
(partition table, boot sector, and a working NTFS filesystem) to test
the actual pytsk3/pyewf/pyvhdi/pyvmdk extraction code against is a
much larger undertaking than this project's other synthetic test data
(e.g. generate_sample_mft_bytes()'s bare MFT records) and is out of
scope for this pass -- that extraction path is verified manually
against a real disk image instead. tests/test_case_ingest.py's
TestLoadCaseFromDiskImage covers the *wiring* (that load_case()
correctly routes image extensions here) using deliberately invalid
image content, which doesn't require a real image either.

Requires the optional 'images' extra; skips entirely if it isn't
installed.
"""

# pylint: disable=missing-function-docstring
# Test function names are self-descriptive; per-test docstrings would
# just restate the name.

from __future__ import annotations

import pytest

disk_image = pytest.importorskip("corrobora.parsers.disk_image")

from corrobora.parsers.case_ingest import (  # noqa: E402 pylint: disable=wrong-import-position
    _IMAGE_SUFFIXES,
)


class TestDetectImageKind:
    """Tests for _detect_image_kind()'s extension-based classification."""

    @pytest.mark.parametrize("suffix", [".e01", ".E01", ".ex01", ".Ex01"])
    def test_ewf_extensions(self, suffix: str) -> None:
        assert disk_image._detect_image_kind(  # pylint: disable=protected-access
            f"case{suffix}"
        ) == "ewf"

    @pytest.mark.parametrize("suffix", [".vhd", ".VHD", ".vhdx", ".VHDX"])
    def test_vhdi_extensions(self, suffix: str) -> None:
        assert disk_image._detect_image_kind(  # pylint: disable=protected-access
            f"case{suffix}"
        ) == "vhdi"

    @pytest.mark.parametrize("suffix", [".vmdk", ".VMDK"])
    def test_vmdk_extensions(self, suffix: str) -> None:
        assert disk_image._detect_image_kind(  # pylint: disable=protected-access
            f"case{suffix}"
        ) == "vmdk"

    @pytest.mark.parametrize("suffix", [".raw", ".img", ".dd", ".txt", ""])
    def test_everything_else_is_raw(self, suffix: str) -> None:
        assert disk_image._detect_image_kind(  # pylint: disable=protected-access
            f"case{suffix}"
        ) == "raw"


def test_image_suffixes_kept_in_sync_with_case_ingest() -> None:
    # case_ingest.py deliberately duplicates this set rather than
    # importing disk_image.py (to avoid pulling in its C-extension
    # dependencies for ordinary folder/zip usage) -- this test is the
    # guard against the two silently drifting apart.
    assert disk_image.IMAGE_SUFFIXES == _IMAGE_SUFFIXES
