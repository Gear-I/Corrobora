"""Unit tests for :mod:`corrobora.parsers.ez_tools_orchestrator`.

Uses mocked ``subprocess.run`` calls throughout -- real EZ Tools
executables are Windows/.NET binaries and cannot run in this test
environment. These tests verify the orchestration logic (argument
construction, exit-code/timeout/missing-output handling, executable
discovery) rather than EZ Tools' own behavior.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import mock

import pytest

from corrobora.parsers.ez_tool_orchestrator import (
    EzToolRunResult,
    EzToolsRunner,
    ExecutableNotFoundError,
    ToolExecutionError,
    UnsupportedPlatformError,
)


def _mock_completed_process(returncode: int = 0, stdout: str = "", stderr: str = "") -> mock.Mock:
    """Build a mock subprocess.CompletedProcess-like result."""
    result = mock.Mock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


class TestEzToolsRunnerPlatformCheck:
    """Tests for the Windows-platform warning/enforcement behavior."""

    def test_defaults_to_warning_on_non_windows(self, tmp_path: Path, caplog) -> None:
        with mock.patch("platform.system", return_value="Linux"):
            EzToolsRunner(tools_dir=tmp_path)
        assert any("Windows/.NET executables" in msg for msg in caplog.messages)

    def test_raises_when_require_windows_and_not_windows(self, tmp_path: Path) -> None:
        with mock.patch("platform.system", return_value="Linux"):
            with pytest.raises(UnsupportedPlatformError):
                EzToolsRunner(tools_dir=tmp_path, require_windows=True)

    def test_no_warning_on_windows(self, tmp_path: Path, caplog) -> None:
        with mock.patch("platform.system", return_value="Windows"):
            EzToolsRunner(tools_dir=tmp_path)
        assert not any("Windows/.NET executables" in msg for msg in caplog.messages)


class TestEzToolsRunnerExecutableDiscovery:
    """Tests for locating the EZ Tool executable within tools_dir."""

    def test_raises_when_executable_missing(self, tmp_path: Path) -> None:
        runner = EzToolsRunner(tools_dir=tmp_path)
        with pytest.raises(ExecutableNotFoundError, match="EvtxECmd.exe"):
            runner.run_evtxecmd("Security.evtx", tmp_path / "out")


class TestRunEvtxEcmd:
    """Tests for EvtxECmd invocation and result handling."""

    def _make_runner_with_fake_exe(self, tmp_path: Path) -> EzToolsRunner:
        (tmp_path / "EvtxECmd.exe").write_bytes(b"fake exe")
        return EzToolsRunner(tools_dir=tmp_path)

    def test_successful_run_returns_result(self, tmp_path: Path) -> None:
        runner = self._make_runner_with_fake_exe(tmp_path)
        output_dir = tmp_path / "out"

        def fake_run(command, **_kwargs):
            # Simulate the tool producing its expected output file.
            csv_index = command.index("--csv")
            csvf_index = command.index("--csvf")
            out_dir = Path(command[csv_index + 1])
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / command[csvf_index + 1]).write_text("RecordNumber\n1\n")
            return _mock_completed_process(returncode=0, stdout="done")

        with mock.patch("subprocess.run", side_effect=fake_run):
            result = runner.run_evtxecmd("Security.evtx", output_dir)

        assert isinstance(result, EzToolRunResult)
        assert result.tool_key == "evtxecmd"
        assert result.output_csv_path.exists()
        assert result.stdout == "done"

    def test_builds_directory_flag_when_is_directory(self, tmp_path: Path) -> None:
        runner = self._make_runner_with_fake_exe(tmp_path)
        output_dir = tmp_path / "out"
        captured_command = {}

        def fake_run(command, **_kwargs):
            captured_command["value"] = command
            out_dir = Path(command[command.index("--csv") + 1])
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / command[command.index("--csvf") + 1]).write_text("x")
            return _mock_completed_process(returncode=0)

        with mock.patch("subprocess.run", side_effect=fake_run):
            runner.run_evtxecmd("C:/Logs", output_dir, is_directory=True)

        assert "-d" in captured_command["value"]
        assert "-f" not in captured_command["value"]

    def test_nonzero_exit_code_raises(self, tmp_path: Path) -> None:
        runner = self._make_runner_with_fake_exe(tmp_path)
        with mock.patch(
            "subprocess.run",
            return_value=_mock_completed_process(returncode=1, stderr="bad input"),
        ):
            with pytest.raises(ToolExecutionError, match="exited with code 1"):
                runner.run_evtxecmd("Security.evtx", tmp_path / "out")

    def test_missing_output_file_raises(self, tmp_path: Path) -> None:
        runner = self._make_runner_with_fake_exe(tmp_path)
        # Tool reports success but never actually writes the expected CSV.
        with mock.patch(
            "subprocess.run", return_value=_mock_completed_process(returncode=0)
        ):
            with pytest.raises(ToolExecutionError, match="output file was not found"):
                runner.run_evtxecmd("Security.evtx", tmp_path / "out")

    def test_timeout_raises_tool_execution_error(self, tmp_path: Path) -> None:
        runner = self._make_runner_with_fake_exe(tmp_path)
        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="EvtxECmd.exe", timeout=300),
        ):
            with pytest.raises(ToolExecutionError, match="timed out"):
                runner.run_evtxecmd("Security.evtx", tmp_path / "out")

    def test_os_error_raises_tool_execution_error(self, tmp_path: Path) -> None:
        runner = self._make_runner_with_fake_exe(tmp_path)
        with mock.patch("subprocess.run", side_effect=OSError("no .NET runtime")):
            with pytest.raises(ToolExecutionError, match="Failed to launch"):
                runner.run_evtxecmd("Security.evtx", tmp_path / "out")


class TestRunRecmdRequiresBatchFile:
    """Tests confirming RECmd's batch-file requirement is reflected in its args."""

    def test_batch_file_included_in_command(self, tmp_path: Path) -> None:
        (tmp_path / "RECmd.exe").write_bytes(b"fake exe")
        runner = EzToolsRunner(tools_dir=tmp_path)
        captured_command = {}

        def fake_run(command, **_kwargs):
            captured_command["value"] = command
            out_dir = Path(command[command.index("--csv") + 1])
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / command[command.index("--csvf") + 1]).write_text("x")
            return _mock_completed_process(returncode=0)

        with mock.patch("subprocess.run", side_effect=fake_run):
            runner.run_recmd("SYSTEM", tmp_path / "out", batch_file="C:/batch.reb")

        assert "--bn" in captured_command["value"]
        bn_index = captured_command["value"].index("--bn")
        assert captured_command["value"][bn_index + 1] == "C:/batch.reb"


class TestEzToolRunResultParse:
    """Tests for EzToolRunResult.parse() delegating to EzToolsCsvParser."""

    def test_parse_delegates_correctly_for_evtxecmd(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "20240408132435_EvtxECmd_Output.csv"
        csv_path.write_text(
            "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,"
            "ProcessId,ThreadId,Computer,ChunkNumber,UserId,MapDescription,UserName,"
            "RemoteHost,PayloadData1,PayloadData2,PayloadData3,PayloadData4,"
            "PayloadData5,PayloadData6,ExecutableInfo,HiddenRecord,SourceFile,"
            "Keywords,ExtraDataOffset\n"
            "1,1,2024-01-01T00:00:00.0000000+00:00,4688,0,Provider,Security,4,8,"
            "HOST,0,S-1-5-18,desc,user,,,,,,,,exe,False,Security.evtx,Audit,0\n"
        )
        result = EzToolRunResult(
            tool_key="evtxecmd", output_csv_path=csv_path, stdout="", stderr=""
        )

        records = result.parse()

        assert len(records) == 1
        assert records[0].record_id == "1"