"""The reference case is reproducible on every OS and Python version CI runs.

CI runs this on Windows, macOS, and Linux with Python 3.11-3.13, so these
tests are what back the claim in docs/reproducible-testing.md that anyone
gets byte-identical results.
"""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from corrobora.correlation import cli
from corrobora.parsers.case_ingest import load_case

_ROOT = Path(__file__).resolve().parent.parent
_MANIFEST = _ROOT / "tests" / "reference" / "case-1" / "manifest.json"


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, _ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    # Registered before running, since dataclasses look their module up by name.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


build = _load_script("build_reference_case")
verify = _load_script("verify_reference_case")


def _manifest() -> dict:
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


def _build(tmp_path: Path) -> Path:
    target = tmp_path / _manifest()["case_file"]
    target.write_bytes(build.build_zip(build.case_files()))
    return target


def test_generator_output_matches_published_hash(tmp_path):
    data = _build(tmp_path).read_bytes()
    assert hashlib.sha256(data).hexdigest() == _manifest()["case_sha256"]


def test_every_case_file_parses_cleanly(tmp_path):
    # Parser error text differs between operating systems, so the case must
    # contain nothing that fails to parse.
    collection = cli.collect_evidence(load_case(_build(tmp_path)))
    for source, info in collection.sources.items():
        assert not info.failed, (source, info.failed)
        assert info.parsed, source


def test_reference_outputs_are_byte_identical(tmp_path, capsys):
    exit_code = verify.main([str(_build(tmp_path)), "--manifest", str(_MANIFEST)])
    out = capsys.readouterr().out
    assert exit_code == 0, out
    assert "PASS: all" in out


def test_expected_outputs_match_manifest_hashes():
    manifest = _manifest()
    for run in manifest["runs"]:
        data = (_MANIFEST.parent / run["expected_output"]).read_bytes()
        assert b"\r" not in data, run["expected_output"]
        assert hashlib.sha256(data).hexdigest() == run["expected_output_sha256"], run["name"]
