"""Corrobora Case Ingest -- single-file module.

Accepts a folder (e.g. a KAPE-style triage collection) or a ``.zip``
archive of one, recursively discovers the artifact files Corrobora
knows how to parse within it (EVTX, registry hives, Prefetch, MFT),
and hands them straight to the correlation engine's
``build_context()`` -- so an analyst can point Corrobora at "a case"
rather than manually locating and selecting four different kinds of
file.

This module has no third-party dependencies: archive extraction uses
only the standard library's ``zipfile``.

Artifact classification is filename/extension-based, matching the
conventions used by common collection tools (KAPE, ``wevtutil``
exports, etc.):

- EVTX: any file ending in ``.evtx``.
- Prefetch: any file ending in ``.pf``.
- MFT: a file named exactly ``$MFT`` or ``MFT``, or ending in
  ``_MFT`` (case-insensitive) -- the latter matches KAPE's
  drive-letter-prefixed naming convention (e.g. ``C_MFT``).
- Registry hive: a file whose name (case-insensitive, ignoring
  extension for ``NTUSER``/``UsrClass``) matches one of the well-known
  hive names: ``SYSTEM``, ``SOFTWARE``, ``SAM``, ``SECURITY``,
  ``DEFAULT``, ``NTUSER.DAT``, ``UsrClass.dat``.

This is a heuristic, not a guarantee -- a collection with unusually
named files won't be picked up automatically. Treat auto-discovered
results as a starting point; review them before treating an analysis
as complete.

Example:
    >>> from case_ingest import load_case
    >>> from correlation_engine import build_context, CorrelationEngine
    >>> artifacts = load_case("C:/triage/case001.zip")
    >>> context = build_context(
    ...     evtx_paths=list(artifacts.evtx_paths),
    ...     registry_paths=list(artifacts.registry_paths),
    ...     prefetch_paths=list(artifacts.prefetch_paths),
    ...     mft_paths=list(artifacts.mft_paths),
    ... )
    >>> findings = CorrelationEngine().run(context)

Command-line usage:
    python case_ingest.py <path-to-folder-or-zip> [--analyze]
"""

from __future__ import annotations

import argparse
import logging
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_EVTX_SUFFIX = ".evtx"
_PREFETCH_SUFFIX = ".pf"

_MFT_EXACT_NAMES = frozenset({"$mft", "mft"})
_MFT_SUFFIX = "_mft"

_KNOWN_HIVE_NAMES = frozenset(
    {"system", "software", "sam", "security", "default", "ntuser.dat", "usrclass.dat"}
)


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class CaseIngestError(Exception):
    """Base exception for all errors raised by the case ingest subsystem."""


class InvalidCasePathError(CaseIngestError):
    """Raised when the given case path doesn't exist or isn't usable.

    Examples include a path that doesn't exist, a zip archive that
    can't be opened, or a zip archive that fails safety validation
    (see :func:`_safe_extract_zip`).
    """


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DiscoveredArtifacts:
    """The artifact files found within a case folder, grouped by type.

    Attributes:
        evtx_paths: Paths to discovered ``.evtx`` files.
        registry_paths: Paths to discovered registry hive files.
        prefetch_paths: Paths to discovered ``.pf`` files.
        mft_paths: Paths to discovered raw ``$MFT`` files.
        unclassified_count: The number of files scanned that did not
            match any known artifact pattern. Provided so a caller
            can gauge how much of the collection wasn't recognized,
            without needing the full (potentially large) list of
            every non-matching file.
    """

    evtx_paths: tuple[str, ...]
    registry_paths: tuple[str, ...]
    prefetch_paths: tuple[str, ...]
    mft_paths: tuple[str, ...]
    unclassified_count: int

    @property
    def total_count(self) -> int:
        """The total number of recognized artifact files discovered."""
        return (
            len(self.evtx_paths)
            + len(self.registry_paths)
            + len(self.prefetch_paths)
            + len(self.mft_paths)
        )


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


def _classify_file(path: Path) -> str | None:
    """Classify a single file by its likely artifact type.

    Args:
        path: The file to classify.

    Returns:
        One of ``"evtx"``, ``"registry"``, ``"prefetch"``, ``"mft"``,
        or ``None`` if the file doesn't match any known pattern.
    """
    name_lower = path.name.lower()
    suffix_lower = path.suffix.lower()

    if suffix_lower == _EVTX_SUFFIX:
        return "evtx"
    if suffix_lower == _PREFETCH_SUFFIX:
        return "prefetch"
    if name_lower in _MFT_EXACT_NAMES or name_lower.endswith(_MFT_SUFFIX):
        return "mft"
    if name_lower in _KNOWN_HIVE_NAMES:
        return "registry"
    return None


def discover_artifacts(folder: str | Path) -> DiscoveredArtifacts:
    """Recursively scan a folder and classify Corrobora-recognized artifacts.

    Files that can't be classified are silently skipped (counted in
    :attr:`DiscoveredArtifacts.unclassified_count`), not treated as
    errors -- a real collection folder typically contains many files
    Corrobora has no parser for.

    Args:
        folder: Path to the folder to scan.

    Returns:
        The classified artifact paths found.

    Raises:
        InvalidCasePathError: If ``folder`` does not exist or is not
            a directory.
    """
    folder_path = Path(folder)
    if not folder_path.exists():
        raise InvalidCasePathError(f"Case folder not found: {folder_path}")
    if not folder_path.is_dir():
        raise InvalidCasePathError(f"Case path is not a directory: {folder_path}")

    evtx: list[str] = []
    registry: list[str] = []
    prefetch: list[str] = []
    mft: list[str] = []
    unclassified = 0

    for entry in folder_path.rglob("*"):
        try:
            if not entry.is_file():
                continue
        except OSError as exc:
            logger.warning("Skipping unreadable path '%s': %s", entry, exc)
            continue

        category = _classify_file(entry)
        if category == "evtx":
            evtx.append(str(entry))
        elif category == "registry":
            registry.append(str(entry))
        elif category == "prefetch":
            prefetch.append(str(entry))
        elif category == "mft":
            mft.append(str(entry))
        else:
            unclassified += 1

    logger.info(
        "Case scan of '%s': %d EVTX, %d registry, %d Prefetch, %d MFT, "
        "%d unclassified file(s).",
        folder_path,
        len(evtx),
        len(registry),
        len(prefetch),
        len(mft),
        unclassified,
    )

    return DiscoveredArtifacts(
        evtx_paths=tuple(sorted(evtx)),
        registry_paths=tuple(sorted(registry)),
        prefetch_paths=tuple(sorted(prefetch)),
        mft_paths=tuple(sorted(mft)),
        unclassified_count=unclassified,
    )


# --------------------------------------------------------------------------
# Zip archive handling
# --------------------------------------------------------------------------


def _safe_extract_zip(zip_path: Path, destination: Path) -> None:
    """Extract a zip archive, rejecting entries that would escape the destination.

    This guards against "zip slip": a maliciously crafted archive
    containing entries like ``../../etc/passwd`` or an absolute path,
    which would otherwise let extraction write files outside the
    intended destination directory.

    Args:
        zip_path: Path to the ``.zip`` file to extract.
        destination: Directory to extract into. Must already exist.

    Raises:
        InvalidCasePathError: If the archive can't be opened, or if
            any entry in it would extract outside ``destination``.
    """
    destination = destination.resolve()
    try:
        archive = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise InvalidCasePathError(f"Could not open zip archive '{zip_path}': {exc}") from exc

    with archive:
        for member in archive.namelist():
            member_path = (destination / member).resolve()
            if not str(member_path).startswith(str(destination)):
                raise InvalidCasePathError(
                    f"Refusing to extract unsafe archive entry (path traversal "
                    f"attempt) from '{zip_path}': {member!r}"
                )
        archive.extractall(destination)


def load_case(path: str | Path) -> DiscoveredArtifacts:
    """Discover artifacts from a case folder or a ``.zip`` archive of one.

    If ``path`` points to a ``.zip`` file, it is safely extracted to
    a fresh temporary directory first (which is left on disk for the
    duration of the process so extracted files remain readable by
    downstream parsers -- it is not automatically cleaned up, since
    the caller may still need the paths afterward).

    Args:
        path: Path to a case folder, or a ``.zip`` archive of one.

    Returns:
        The classified artifact paths found.

    Raises:
        InvalidCasePathError: If ``path`` does not exist, is neither
            a directory nor a ``.zip`` file, or (for a zip) fails to
            open or extract safely.
    """
    case_path = Path(path)
    if not case_path.exists():
        raise InvalidCasePathError(f"Case path not found: {case_path}")

    if case_path.is_dir():
        return discover_artifacts(case_path)

    if case_path.is_file() and case_path.suffix.lower() == ".zip":
        temp_dir = Path(tempfile.mkdtemp(prefix="corrobora_case_"))
        logger.info("Extracting '%s' to temporary directory '%s'", case_path, temp_dir)
        _safe_extract_zip(case_path, temp_dir)
        return discover_artifacts(temp_dir)

    raise InvalidCasePathError(
        f"Case path must be a directory or a .zip file, got: {case_path}"
    )


# --------------------------------------------------------------------------
# Command-line entry point
# --------------------------------------------------------------------------


def _main() -> None:
    """Run case ingest as a script.

    Usage:
        python case_ingest.py <path-to-folder-or-zip> [--analyze]
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="case_ingest.py",
        description="Discover Corrobora-recognized artifacts in a case folder or zip archive.",
    )
    parser.add_argument("target", help="Path to a case folder or a .zip archive of one.")
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Also run the correlation engine against the discovered artifacts.",
    )
    args = parser.parse_args()

    try:
        artifacts = load_case(args.target)
    except InvalidCasePathError as exc:
        logger.error("Case ingest failed: %s", exc)
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

    if not args.analyze:
        return

    # Imported here rather than at module level so `case_ingest.py` can be
    # used purely for discovery (e.g. by the GUI) without requiring the
    # correlation engine's own dependency chain unless --analyze is used.
    from .correlation_engine import (  # pylint: disable=import-outside-toplevel
        CorrelationEngine,
        Severity,
        build_context,
    )

    context = build_context(
        evtx_paths=list(artifacts.evtx_paths),
        registry_paths=list(artifacts.registry_paths),
        prefetch_paths=list(artifacts.prefetch_paths),
        mft_paths=list(artifacts.mft_paths),
    )
    findings = CorrelationEngine().run(context)

    if not findings:
        logger.info("No findings.")
        return

    for finding in findings:
        logger.info(
            "[%s] %s: %s", finding.severity.value.upper(), finding.rule_name, finding.description
        )

    counts: dict[Severity, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(f"{sev.value}={count}" for sev, count in counts.items())
    logger.info("Summary: %d total finding(s) (%s).", len(findings), summary)


if __name__ == "__main__":
    _main()
