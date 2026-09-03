"""Corrobora EZ Tools orchestrator -- OPTIONAL add-on module.

Runs Eric Zimmerman's EZ Tools executables directly (via
``subprocess``) against raw artifacts, then feeds the resulting CSV
output straight into :mod:`corrobora.parsers.ez_tools_import` for
normalization -- a single-command convenience over the standard
"run EZ Tools separately, then import the CSV" workflow.

This is intentionally a separate module from ``ez_tools_import.py``,
not a required part of Corrobora's core install. Importing this
module has no new dependency (still pure Python standard library),
but *using* it does: it invokes external, Windows/.NET executables
that Corrobora does not bundle, install, or manage the version of.

Why this is optional, not the default workflow:
    Standard DFIR practice runs EZ Tools (typically via KAPE's
    ``!EZParser`` module) as part of a documented collection step,
    producing CSV output that is then carried to an analysis
    workstation -- a clean boundary between "evidence was touched
    here, at this time, by this tool" and later analysis. Having
    Corrobora itself invoke EZ Tools on demand blurs that boundary
    and adds real failure surface (a specific .NET runtime version,
    specific EZ Tools executables, specific CLI flags that can change
    between releases). Prefer ``ez_tools_import.py`` -- reading
    output someone already produced -- as the primary integration
    path; use this orchestrator only when the single-command
    convenience is worth that tradeoff for your workflow.

Verified vs. documented-but-unverified CLI flags:
    EvtxECmd's CLI flags used here (``-f``/``-d``, ``--csv``,
    ``--csvf``) are confirmed against EvtxECmd's actual published
    command-line reference. PECmd and MFTECmd are documented
    community-wide as following the same ``-f``/``-d``/``--csv``/
    ``--csvf`` convention used across Eric Zimmerman's tools, but
    that has not been independently re-verified here the way
    EvtxECmd's was -- run the target executable with ``--help``
    yourself before relying on this for those tools. RECmd requires
    an additional ``--bn <batch-file>`` argument to produce useful
    output at all (it needs a batch definition of which keys/values
    to extract) and is exposed here as such, not with a false
    assumption of a simple default.

Example:
    >>> from corrobora.parsers.ez_tools_orchestrator import EzToolsRunner
    >>> runner = EzToolsRunner(tools_dir="C:/Tools/EZTools")
    >>> result = runner.run_evtxecmd(
    ...     input_path="C:/Evidence/Security.evtx",
    ...     output_dir="C:/Case/Processed",
    ... )
    >>> records = result.parse()  # normalized ArtifactRecord list

Command-line usage:
    corrobora-ez-run --tool evtxecmd --tools-dir "C:\\Tools\\EZTools" \\
        --input "C:\\Evidence\\Security.evtx" --output "C:\\Case\\Processed"
"""

from __future__ import annotations

import argparse
import logging
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .Base import ArtifactRecord
from .ez_tool_importer import EzToolsCsvParser, EzToolsImportError

logger = logging.getLogger(__name__)

# Executable filenames as distributed by Eric Zimmerman's tools installer
# (Get-ZimmermanTools.ps1) / Chocolatey packages.
_TOOL_EXECUTABLES: dict[str, str] = {
    "evtxecmd": "EvtxECmd.exe",
    "pecmd": "PECmd.exe",
    "mftecmd": "MFTECmd.exe",
    "recmd": "RECmd.exe",
}

_DEFAULT_TIMEOUT_SECONDS = 300


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class EzToolsOrchestratorError(EzToolsImportError):  # pylint: disable=too-few-public-methods
    """Base exception for all errors raised by the EZ Tools orchestrator.

    Inherits from :class:`ez_tools_import.EzToolsImportError` so
    orchestration failures can be caught alongside plain CSV-import
    failures with a single ``except`` clause.
    """


class ExecutableNotFoundError(EzToolsOrchestratorError):  # pylint: disable=too-few-public-methods
    """Raised when the requested EZ Tool's executable cannot be found.

    Examples include a missing or misspelled ``tools_dir``, or an EZ
    Tools installation that doesn't include the requested tool.
    """


class ToolExecutionError(EzToolsOrchestratorError):  # pylint: disable=too-few-public-methods
    """Raised when an EZ Tool executable runs but fails or times out.

    Captures the tool's stdout/stderr in the exception message where
    available, since that is usually the most useful diagnostic
    information for a failed external-tool invocation.
    """


class UnsupportedPlatformError(EzToolsOrchestratorError):  # pylint: disable=too-few-public-methods
    """Raised when attempting to run EZ Tools on a non-Windows platform.

    EZ Tools are Windows/.NET executables. This is only raised for
    an explicit, opt-in strict check (see
    :meth:`EzToolsRunner.__init__`'s ``require_windows`` parameter);
    by default, a warning is logged instead and execution is
    attempted anyway, since a correctly configured cross-platform
    .NET runtime may make it work regardless.
    """


# --------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EzToolRunResult:
    """The result of successfully running one EZ Tool.

    Attributes:
        tool_key: Which tool was run (e.g. ``"evtxecmd"``).
        output_csv_path: Path to the CSV output file produced.
        stdout: The tool's captured standard output.
        stderr: The tool's captured standard error.
    """

    tool_key: str
    output_csv_path: Path
    stdout: str
    stderr: str

    def parse(self) -> list[ArtifactRecord]:
        """Parse this run's output CSV into normalized records.

        Convenience wrapper around
        :class:`ez_tools_import.EzToolsCsvParser` so a caller doesn't
        need to separately import and construct one.

        Returns:
            A list of normalized :class:`base.ArtifactRecord` objects.

        Raises:
            EzToolsFileError: If the CSV cannot be opened.
            UnsupportedEzToolError: If this tool's CSV schema isn't
                normalized yet (currently only EvtxECmd is).
        """
        parser = EzToolsCsvParser(self.output_csv_path)
        return parser.parse_common()


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------


class EzToolsRunner:
    """Runs EZ Tools executables directly and locates their CSV output.

    Attributes:
        tools_dir: Directory containing the EZ Tools executables
            (e.g. the extraction target of Eric Zimmerman's
            ``Get-ZimmermanTools.ps1`` installer).
        timeout_seconds: Maximum time to allow a single tool
            invocation to run before raising :class:`ToolExecutionError`.

    Example:
        >>> runner = EzToolsRunner(tools_dir="C:/Tools/EZTools")
        >>> result = runner.run_evtxecmd("Security.evtx", "C:/Case/Processed")
        >>> records = result.parse()
    """

    def __init__(
        self,
        tools_dir: str | Path,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
        require_windows: bool = False,
    ) -> None:
        """Initialize the runner.

        Args:
            tools_dir: Directory containing the EZ Tools executables.
            timeout_seconds: Maximum time to allow a single tool
                invocation to run. Defaults to 300 seconds.
            require_windows: If ``True``, raise
                :class:`UnsupportedPlatformError` immediately when
                not running on Windows, instead of logging a warning
                and attempting execution anyway. Defaults to
                ``False``.

        Raises:
            UnsupportedPlatformError: If ``require_windows`` is
                ``True`` and the current platform is not Windows.
        """
        self.tools_dir = Path(tools_dir)
        self.timeout_seconds = timeout_seconds
        self._check_platform(require_windows)

    @staticmethod
    def _check_platform(require_windows: bool) -> None:
        """Warn (or raise) if not running on Windows.

        Args:
            require_windows: Whether to raise instead of warn.

        Raises:
            UnsupportedPlatformError: If ``require_windows`` is
                ``True`` and the current platform is not Windows.
        """
        if platform.system() == "Windows":
            return
        message = (
            f"EZ Tools are Windows/.NET executables; current platform is "
            f"'{platform.system()}'. Execution may fail unless a compatible "
            f".NET runtime is configured."
        )
        if require_windows:
            raise UnsupportedPlatformError(message)
        logger.warning(message)

    def run_evtxecmd(
        self, input_path: str | Path, output_dir: str | Path, *, is_directory: bool = False
    ) -> EzToolRunResult:
        """Run EvtxECmd against a ``.evtx`` file or folder of them.

        Args:
            input_path: Path to a ``.evtx`` file, or a folder of them
                if ``is_directory`` is ``True``.
            output_dir: Directory to write the CSV output into.
            is_directory: Whether ``input_path`` is a folder rather
                than a single file.

        Returns:
            The :class:`EzToolRunResult`, ready to
            :meth:`~EzToolRunResult.parse`.

        Raises:
            ExecutableNotFoundError: If ``EvtxECmd.exe`` isn't found
                in :attr:`tools_dir`.
            ToolExecutionError: If the tool runs but fails or times out.
        """
        output_filename = "corrobora_evtxecmd_output.csv"
        input_flag = "-d" if is_directory else "-f"
        args = [
            input_flag,
            str(input_path),
            "--csv",
            str(output_dir),
            "--csvf",
            output_filename,
        ]
        return self._run_tool("evtxecmd", args, Path(output_dir) / output_filename)

    def run_pecmd(
        self, input_path: str | Path, output_dir: str | Path, *, is_directory: bool = False
    ) -> EzToolRunResult:
        """Run PECmd against a ``.pf`` file or folder of them.

        Note:
            PECmd's ``-f``/``-d``/``--csv``/``--csvf`` flags follow
            the documented convention shared across EZ Tools, but
            have not been independently re-verified the way
            EvtxECmd's were -- confirm with ``PECmd.exe --help``
            before relying on this in a real workflow.

        Args:
            input_path: Path to a ``.pf`` file, or a folder of them
                if ``is_directory`` is ``True``.
            output_dir: Directory to write the CSV output into.
            is_directory: Whether ``input_path`` is a folder rather
                than a single file.

        Returns:
            The :class:`EzToolRunResult`. Calling
            :meth:`~EzToolRunResult.parse` on it will currently raise
            ``UnsupportedEzToolError`` -- PECmd's CSV schema isn't
            normalized in ``ez_tools_import.py`` yet.

        Raises:
            ExecutableNotFoundError: If ``PECmd.exe`` isn't found in
                :attr:`tools_dir`.
            ToolExecutionError: If the tool runs but fails or times out.
        """
        output_filename = "corrobora_pecmd_output.csv"
        input_flag = "-d" if is_directory else "-f"
        args = [
            input_flag,
            str(input_path),
            "--csv",
            str(output_dir),
            "--csvf",
            output_filename,
        ]
        return self._run_tool("pecmd", args, Path(output_dir) / output_filename)

    def run_mftecmd(self, input_path: str | Path, output_dir: str | Path) -> EzToolRunResult:
        """Run MFTECmd against a raw ``$MFT`` file.

        Note:
            MFTECmd's flags follow the documented EZ Tools
            convention but have not been independently re-verified
            the way EvtxECmd's were -- confirm with
            ``MFTECmd.exe --help`` before relying on this.

        Args:
            input_path: Path to the raw ``$MFT`` file.
            output_dir: Directory to write the CSV output into.

        Returns:
            The :class:`EzToolRunResult`. Calling
            :meth:`~EzToolRunResult.parse` on it will currently raise
            ``UnsupportedEzToolError`` -- MFTECmd's CSV schema isn't
            normalized in ``ez_tools_import.py`` yet.

        Raises:
            ExecutableNotFoundError: If ``MFTECmd.exe`` isn't found
                in :attr:`tools_dir`.
            ToolExecutionError: If the tool runs but fails or times out.
        """
        output_filename = "corrobora_mftecmd_output.csv"
        args = ["-f", str(input_path), "--csv", str(output_dir), "--csvf", output_filename]
        return self._run_tool("mftecmd", args, Path(output_dir) / output_filename)

    def run_recmd(
        self, input_path: str | Path, output_dir: str | Path, batch_file: str | Path
    ) -> EzToolRunResult:
        """Run RECmd against a registry hive using a batch definition file.

        Note:
            Unlike the other tools, RECmd requires a batch (``.reb``)
            file defining which keys/values to extract to produce
            useful output at all -- there is no simple default. EZ
            Tools ships example batch files (``BatchExamples/``)
            alongside RECmd itself.

        Args:
            input_path: Path to the registry hive file.
            output_dir: Directory to write the CSV output into.
            batch_file: Path to the RECmd batch (``.reb``) definition
                file to use.

        Returns:
            The :class:`EzToolRunResult`. Calling
            :meth:`~EzToolRunResult.parse` on it will currently raise
            ``UnsupportedEzToolError`` -- RECmd's CSV schema isn't
            normalized in ``ez_tools_import.py`` yet.

        Raises:
            ExecutableNotFoundError: If ``RECmd.exe`` isn't found in
                :attr:`tools_dir`.
            ToolExecutionError: If the tool runs but fails or times out.
        """
        output_filename = "corrobora_recmd_output.csv"
        args = [
            "-f",
            str(input_path),
            "--bn",
            str(batch_file),
            "--csv",
            str(output_dir),
            "--csvf",
            output_filename,
        ]
        return self._run_tool("recmd", args, Path(output_dir) / output_filename)

    def _run_tool(
        self, tool_key: str, args: list[str], expected_output_csv: Path
    ) -> EzToolRunResult:
        """Locate, invoke, and validate the output of one EZ Tool.

        Args:
            tool_key: The tool's internal key (e.g. ``"evtxecmd"``),
                used to look up its executable filename.
            args: Command-line arguments to pass to the executable.
            expected_output_csv: The output CSV path this invocation
                should produce.

        Returns:
            The populated :class:`EzToolRunResult`.

        Raises:
            ExecutableNotFoundError: If the tool's executable isn't
                found in :attr:`tools_dir`.
            ToolExecutionError: If the tool runs but exits non-zero,
                times out, or doesn't produce the expected output file.
        """
        executable_path = self.tools_dir / _TOOL_EXECUTABLES[tool_key]
        if not executable_path.is_file():
            raise ExecutableNotFoundError(
                f"'{_TOOL_EXECUTABLES[tool_key]}' not found in tools_dir "
                f"'{self.tools_dir}'. Expected it at: {executable_path}"
            )

        expected_output_csv.parent.mkdir(parents=True, exist_ok=True)
        command = [str(executable_path), *args]
        logger.info("Running: %s", " ".join(command))

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolExecutionError(
                f"{_TOOL_EXECUTABLES[tool_key]} timed out after "
                f"{self.timeout_seconds}s: {exc}"
            ) from exc
        except OSError as exc:
            raise ToolExecutionError(
                f"Failed to launch {_TOOL_EXECUTABLES[tool_key]}: {exc}"
            ) from exc

        if completed.returncode != 0:
            raise ToolExecutionError(
                f"{_TOOL_EXECUTABLES[tool_key]} exited with code "
                f"{completed.returncode}.\nstdout: {completed.stdout}\n"
                f"stderr: {completed.stderr}"
            )
        if not expected_output_csv.is_file():
            raise ToolExecutionError(
                f"{_TOOL_EXECUTABLES[tool_key]} completed (exit code 0) but "
                f"the expected output file was not found: {expected_output_csv}\n"
                f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
            )

        logger.info("Completed: %s -> %s", _TOOL_EXECUTABLES[tool_key], expected_output_csv)
        return EzToolRunResult(
            tool_key=tool_key,
            output_csv_path=expected_output_csv,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


# --------------------------------------------------------------------------
# Command-line entry point
# --------------------------------------------------------------------------


def _main() -> None:
    """Run the EZ Tools orchestrator as a script.

    Usage:
        corrobora-ez-run --tool evtxecmd --tools-dir DIR --input PATH
            --output DIR [--batch-file PATH] [--directory]
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="ez_tools_orchestrator.py",
        description="Run an EZ Tools executable directly and parse its CSV output. "
        "OPTIONAL convenience layer -- see module docstring for why "
        "ez_tools_import.py (reading already-produced CSVs) is the "
        "recommended primary workflow.",
    )
    parser.add_argument(
        "--tool", required=True, choices=sorted(_TOOL_EXECUTABLES), help="Which EZ Tool to run."
    )
    parser.add_argument(
        "--tools-dir", required=True, help="Directory containing the EZ Tools executables."
    )
    parser.add_argument("--input", required=True, help="Path to the input artifact/folder.")
    parser.add_argument("--output", required=True, help="Directory to write CSV output into.")
    parser.add_argument(
        "--batch-file", default=None, help="RECmd batch (.reb) file (required for --tool recmd)."
    )
    parser.add_argument(
        "--directory",
        action="store_true",
        help="Treat --input as a folder rather than a single file (evtxecmd/pecmd only).",
    )
    args = parser.parse_args()

    if args.tool == "recmd" and not args.batch_file:
        parser.error("--tool recmd requires --batch-file")

    runner = EzToolsRunner(tools_dir=args.tools_dir)

    try:
        if args.tool == "evtxecmd":
            result = runner.run_evtxecmd(args.input, args.output, is_directory=args.directory)
        elif args.tool == "pecmd":
            result = runner.run_pecmd(args.input, args.output, is_directory=args.directory)
        elif args.tool == "mftecmd":
            result = runner.run_mftecmd(args.input, args.output)
        else:
            result = runner.run_recmd(args.input, args.output, args.batch_file)
    except EzToolsOrchestratorError as exc:
        logger.error("Run failed: %s", exc)
        raise SystemExit(1) from exc

    logger.info("Output CSV: %s", result.output_csv_path)

    try:
        records = result.parse()
    except EzToolsImportError as exc:
        logger.warning(
            "Tool ran successfully, but automatic parsing isn't available yet "
            "for %s: %s. The output CSV is still available at %s for manual use.",
            args.tool,
            exc,
            result.output_csv_path,
        )
        return

    logger.info("Parsed %d normalized record(s).", len(records))


if __name__ == "__main__":
    _main()
