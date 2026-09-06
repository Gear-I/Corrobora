"""Corrobora Disk Image Support -- single-file module.

Extracts Corrobora's four known Windows artifact types (EVTX,
registry hives, Prefetch, ``$MFT``) directly out of a raw forensic
disk image -- E01/EWF, VHD/VHDX, VMDK, or a raw/dd image -- without
mounting it. Once extraction is done, the result is handed to
``case_ingest.discover_artifacts()`` exactly like a folder of
already-extracted files, so every downstream consumer (the
correlation engine, the GUI, ``corrobora-case --analyze``) needs no
changes at all to work with a disk image as an evidence source.

This module owns all of the heavier, niche C-extension dependencies
this capability needs (``pytsk3``, ``libewf-python``,
``libvhdi-python``, ``libvmdk-python`` -- install with
``pip install corrobora[images]``), so ``case_ingest.py`` itself stays
dependency-free for users who only need folder/zip triage;
``case_ingest.load_case()`` only imports this module lazily, when it
actually recognizes an image file extension, converting an
``ImportError`` (the ``images`` extra isn't installed) into a clear
``InvalidCasePathError`` rather than a raw traceback.

Unlike folder/zip discovery, this does not walk every file on the
volume -- a full disk can be huge -- it goes straight to the specific
well-known paths Windows keeps these artifacts at:

- ``$MFT`` at the volume root.
- ``Windows\\System32\\winevt\\Logs\\*.evtx``
- ``Windows\\Prefetch\\*.pf``
- ``Windows\\System32\\config\\{SYSTEM,SOFTWARE,SAM,SECURITY,DEFAULT}``
- ``Users\\*\\NTUSER.DAT``
- ``Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat``

Known limitations (explicitly out of scope for now, not silently
unsupported): encrypted/password-protected E01 images, legacy
``Documents and Settings\\*`` (Windows XP-style) user profiles, and
non-NTFS filesystems (FAT, exFAT).

Command-line usage:
    python disk_image.py <path-to-image>
"""

from __future__ import annotations

import argparse
import logging
import tempfile
from pathlib import Path

import pyewf
import pytsk3
import pyvhdi
import pyvmdk

from .case_ingest import (
    DiscoveredArtifacts,
    InvalidCasePathError,
    classify_file,
    discover_artifacts,
)

logger = logging.getLogger(__name__)

_EWF_SUFFIXES = frozenset({".e01", ".ex01"})
_VHDI_SUFFIXES = frozenset({".vhd", ".vhdx"})
_VMDK_SUFFIXES = frozenset({".vmdk"})

# Anything not matching a recognized container suffix (including no
# suffix at all, and common raw/dd conventions like .raw/.img/.dd) is
# treated as a raw image -- pytsk3 opens those natively, no library
# needed to unwrap a container format first.
IMAGE_SUFFIXES = _EWF_SUFFIXES | _VHDI_SUFFIXES | _VMDK_SUFFIXES | frozenset(
    {".raw", ".img", ".dd"}
)

_EVTX_LOGS_DIR = "/Windows/System32/winevt/Logs"
_PREFETCH_DIR = "/Windows/Prefetch"
_CONFIG_DIR = "/Windows/System32/config"
_USERS_DIR = "/Users"
_MFT_PATH = "/$MFT"

# NTFS's standard sector size. Partition offsets from pytsk3's
# Volume_Info are reported in sectors, not bytes.
_SECTOR_SIZE = 512


def _detect_image_kind(path: str | Path) -> str:
    """Classify a disk image file by its container format.

    Args:
        path: Path to the image file (for EWF, the first segment,
            e.g. ``case.E01``).

    Returns:
        One of ``"ewf"``, ``"vhdi"``, ``"vmdk"``, or ``"raw"``.
    """
    suffix = Path(path).suffix.lower()
    if suffix in _EWF_SUFFIXES:
        return "ewf"
    if suffix in _VHDI_SUFFIXES:
        return "vhdi"
    if suffix in _VMDK_SUFFIXES:
        return "vmdk"
    return "raw"


class _LibyalImgInfo(pytsk3.Img_Info):
    """Bridges an EWF/VHDI/VMDK handle to pytsk3's expected Img_Info interface.

    pytsk3.Img_Info subclasses must override ``read``/``get_size``/
    ``close`` -- pytsk3 dispatches to them internally while walking a
    filesystem, so they can't just be assigned as instance attributes
    on a base ``Img_Info``, real subclassing is required. pyewf,
    pyvhdi, and pyvmdk handles already expose equivalent
    read/seek/get_media_size/close methods under those names, so this
    just delegates. This is the standard, documented pattern for
    using pytsk3 against a non-raw container format.
    """

    def __init__(self, handle: pyewf.handle | pyvhdi.file | pyvmdk.handle) -> None:
        """Initialize the bridge.

        Args:
            handle: An already-opened pyewf/pyvhdi/pyvmdk handle.
        """
        self._handle = handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self) -> None:
        """Close the underlying handle."""
        self._handle.close()

    def read(self, offset: int, size: int) -> bytes:
        """Read ``size`` bytes at ``offset`` from the underlying handle.

        Args:
            offset: Byte offset to seek to before reading.
            size: Number of bytes to read.

        Returns:
            The bytes read.
        """
        self._handle.seek(offset)
        return self._handle.read(size)

    def get_size(self) -> int:
        """Return the underlying handle's total media size in bytes."""
        return self._handle.get_media_size()


def _open_libyal_handle(kind: str, path: Path) -> pyewf.handle | pyvhdi.file | pyvmdk.handle:
    """Open an EWF/VHDI/VMDK container and return its libyal handle.

    Args:
        kind: One of ``"ewf"``, ``"vhdi"``, ``"vmdk"`` (never
            ``"raw"`` -- raw images don't go through this function).
        path: Path to the image file.

    Returns:
        The opened, ready-to-read libyal handle.

    Raises:
        InvalidCasePathError: If the container can't be opened (bad
            file, unsupported/encrypted format, missing segments).
    """
    try:
        if kind == "ewf":
            handle = pyewf.handle()
            handle.open(pyewf.glob(str(path)))
            return handle
        if kind == "vhdi":
            handle = pyvhdi.file()
            handle.open(str(path))
            return handle
        handle = pyvmdk.handle()
        handle.open(str(path))
        handle.open_extent_data_files()
        return handle
    except OSError as exc:
        raise InvalidCasePathError(f"Could not open disk image '{path}': {exc}") from exc


def _open_image(path: Path) -> pytsk3.Img_Info:
    """Open a disk image of any recognized format as a pytsk3 image handle.

    Args:
        path: Path to the image file.

    Returns:
        A ``pytsk3.Img_Info`` (or compatible bridge) object.

    Raises:
        InvalidCasePathError: If the image can't be opened.
    """
    kind = _detect_image_kind(path)
    if kind == "raw":
        try:
            return pytsk3.Img_Info(str(path))
        except OSError as exc:
            raise InvalidCasePathError(f"Could not open disk image '{path}': {exc}") from exc

    return _LibyalImgInfo(_open_libyal_handle(kind, path))


def _is_ntfs(fs_info: pytsk3.FS_Info) -> bool:
    """Check whether a filesystem pytsk3 opened is NTFS.

    Note:
        ``no-member`` is intentionally suppressed: ``fs_info.info`` is
        a SWIG-wrapped ``TSK_FS_INFO`` C struct pylint can't fully
        introspect, but ``.ftype`` is a real, confirmed attribute
        (verified directly against the installed pytsk3 at
        implementation time), not a typo.
    """
    return fs_info.info.ftype in (  # pylint: disable=no-member
        pytsk3.TSK_FS_TYPE_NTFS,
        pytsk3.TSK_FS_TYPE_NTFS_DETECT,
    )


def _find_ntfs_filesystems(img_info: pytsk3.Img_Info) -> list[pytsk3.FS_Info]:
    """Find every NTFS filesystem within a disk image.

    Tries the image as a partitioned disk first (MBR/GPT); falls back
    to treating the whole image as a single volume if no partition
    table is found (a raw single-volume capture).

    Args:
        img_info: A ``pytsk3.Img_Info``-compatible object.

    Returns:
        Every NTFS ``pytsk3.FS_Info`` found, in partition order.
        Empty if none were found.
    """
    filesystems = []
    try:
        volume_info = pytsk3.Volume_Info(img_info)
    except OSError:
        volume_info = None

    if volume_info is not None:
        for partition in volume_info:
            try:
                fs_info = pytsk3.FS_Info(img_info, offset=partition.start * _SECTOR_SIZE)
            except OSError:
                continue  # Unallocated space, EFI/recovery partition, etc.
            if _is_ntfs(fs_info):
                filesystems.append(fs_info)
        return filesystems

    try:
        fs_info = pytsk3.FS_Info(img_info)
    except OSError:
        return []
    if _is_ntfs(fs_info):
        filesystems.append(fs_info)
    return filesystems


def _list_directory(fs_info: pytsk3.FS_Info, path: str) -> list[tuple[str, bool]]:
    """List the immediate entries of a directory, best-effort.

    Args:
        fs_info: The filesystem to look in.
        path: The TSK-style (forward-slash) directory path.

    Returns:
        ``(name, is_directory)`` pairs, excluding ``.``/``..``. Empty
        (not an error) if the directory doesn't exist -- a real
        image's layout can reasonably differ from the expected one.
    """
    try:
        directory = fs_info.open_dir(path=path)
    except OSError:
        return []

    results = []
    for entry in directory:
        if entry.info.name is None or entry.info.name.name in (b".", b".."):
            continue
        name = entry.info.name.name.decode("utf-8", errors="replace")
        is_directory = entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR
        results.append((name, is_directory))
    return results


def _extract_file(fs_info: pytsk3.FS_Info, path: str, destination: Path) -> bool:
    """Extract a single named file from a filesystem to a local path.

    Args:
        fs_info: The filesystem to read from.
        path: The TSK-style path to the file (e.g. ``"/$MFT"``).
        destination: Local path to write the file's contents to.

    Returns:
        ``True`` if the file was found and extracted, ``False``
        otherwise. Read failures are logged and treated the same as
        not-found, matching this codebase's resilience philosophy:
        one damaged artifact shouldn't abort the whole image scan.
    """
    try:
        tsk_file = fs_info.open(path)
        size = tsk_file.info.meta.size
        data = tsk_file.read_random(0, size)
    except OSError as exc:
        logger.warning("Skipping unreadable image file '%s': %s", path, exc)
        return False
    destination.write_bytes(data)
    return True


def _extract_from_filesystem(fs_info: pytsk3.FS_Info, staging_dir: Path) -> None:
    """Extract every well-known artifact type from one NTFS filesystem.

    Args:
        fs_info: The NTFS filesystem to extract from.
        staging_dir: Local directory to extract matched files into.
    """
    _extract_file(fs_info, _MFT_PATH, staging_dir / "$MFT")

    for directory_path in (_EVTX_LOGS_DIR, _PREFETCH_DIR, _CONFIG_DIR):
        for name, is_directory in _list_directory(fs_info, directory_path):
            if is_directory or classify_file(Path(name)) is None:
                continue
            _extract_file(fs_info, f"{directory_path}/{name}", staging_dir / name)

    for user_name, is_user_directory in _list_directory(fs_info, _USERS_DIR):
        if not is_user_directory:
            continue
        for name, _is_dir in _list_directory(fs_info, f"{_USERS_DIR}/{user_name}"):
            if name.lower() == "ntuser.dat":
                _extract_file(
                    fs_info,
                    f"{_USERS_DIR}/{user_name}/{name}",
                    staging_dir / f"{user_name}_NTUSER.DAT",
                )
        usrclass_dir = f"{_USERS_DIR}/{user_name}/AppData/Local/Microsoft/Windows"
        for name, _is_dir in _list_directory(fs_info, usrclass_dir):
            if name.lower() == "usrclass.dat":
                _extract_file(
                    fs_info, f"{usrclass_dir}/{name}", staging_dir / f"{user_name}_UsrClass.dat"
                )


def load_disk_image(path: str | Path) -> DiscoveredArtifacts:
    """Extract known Windows artifacts from a disk image and classify them.

    Args:
        path: Path to the disk image (E01/EWF, VHD/VHDX, VMDK, or
            raw/dd).

    Returns:
        The classified artifact paths extracted from the image.

    Raises:
        InvalidCasePathError: If the image can't be opened, or if it
            has no recognizable partition table or NTFS filesystem.
    """
    image_path = Path(path)
    if not image_path.exists():
        raise InvalidCasePathError(f"Disk image not found: {image_path}")

    img_info = _open_image(image_path)
    filesystems = _find_ntfs_filesystems(img_info)
    if not filesystems:
        raise InvalidCasePathError(f"No NTFS filesystem found in disk image: {image_path}")

    staging_root = Path(tempfile.mkdtemp(prefix="corrobora_image_"))
    logger.info(
        "Extracting artifacts from '%s' (%d NTFS volume(s)) to '%s'",
        image_path,
        len(filesystems),
        staging_root,
    )
    for index, fs_info in enumerate(filesystems):
        volume_dir = staging_root / f"vol_{index}"
        volume_dir.mkdir(parents=True, exist_ok=True)
        _extract_from_filesystem(fs_info, volume_dir)

    return discover_artifacts(staging_root)


# --------------------------------------------------------------------------
# Command-line entry point
# --------------------------------------------------------------------------


def _main() -> None:
    """Run disk image extraction as a script.

    Usage:
        python disk_image.py <path-to-image>
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="disk_image.py",
        description="Extract Corrobora-recognized artifacts from a disk image.",
    )
    parser.add_argument("image", help="Path to an E01/EWF, VHD/VHDX, VMDK, or raw/dd image.")
    args = parser.parse_args()

    try:
        artifacts = load_disk_image(args.image)
    except InvalidCasePathError as exc:
        logger.error("Disk image extraction failed: %s", exc)
        raise SystemExit(1) from exc

    logger.info(
        "Discovered %d recognized artifact file(s): %d EVTX, %d registry, "
        "%d Prefetch, %d MFT (%d file(s) unclassified).",
        artifacts.total_count,
        len(artifacts.evtx_paths),
        len(artifacts.registry_paths),
        len(artifacts.prefetch_paths),
        len(artifacts.mft_paths),
        artifacts.unclassified_count,
    )


if __name__ == "__main__":
    _main()
