"""Verify Corrobora against the reference case.

Runs every command recorded in the reference manifest against the
reference case and checks that each output is byte-for-byte identical to
its expected output. Anyone, on Windows, macOS, or Linux, should get PASS
for the same Corrobora version and the same reference case.

Usage:
    python scripts/build_reference_case.py build
    python scripts/verify_reference_case.py build/corrobora-reference-case-1.zip

The case can be built locally (it is synthetic and deterministic, so the
build matches the published SHA-256) or downloaded from the release named
in the manifest. Maintainers regenerate the expected outputs (after an
intended change to Corrobora's output) with ``--update``, then review the
diff before committing.

Uses only the standard library, plus Corrobora itself (installed with
``pip install -e .``), run with the same Python interpreter as this script.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import subprocess
import sys
import tempfile
from importlib import metadata
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_MANIFEST = _REPO_ROOT / "tests" / "reference" / "case-1" / "manifest.json"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_corrobora(case: Path, args: list[str]) -> bytes:
    """Run corrobora-corroborate with ``args`` and return its --output file's bytes."""
    with tempfile.TemporaryDirectory() as scratch:
        output = Path(scratch) / "output.txt"
        command = [
            sys.executable,
            "-m",
            "corrobora.correlation.cli",
            str(case),
            *args,
            "--output",
            str(output),
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            raise SystemExit(f"FAIL: corrobora-corroborate exited with code {result.returncode}")
        return output.read_bytes()


def _report_diff(expected: bytes, actual: bytes) -> None:
    sys.stdout.writelines(
        difflib.unified_diff(
            expected.decode("utf-8").splitlines(keepends=True),
            actual.decode("utf-8").splitlines(keepends=True),
            fromfile="expected",
            tofile="actual",
        )
    )


def main(argv: list[str] | None = None) -> int:
    """Verify (or, with --update, regenerate) the reference case's expected outputs."""
    parser = argparse.ArgumentParser(
        prog="verify_reference_case.py",
        description="Check Corrobora's output on the reference case against the expected output.",
    )
    parser.add_argument("case", type=Path, help="The reference case .zip.")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=_DEFAULT_MANIFEST,
        help=f"Reference manifest (default: {_DEFAULT_MANIFEST.relative_to(_REPO_ROOT)}).",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Maintainers: rewrite the expected outputs and their hashes in the manifest.",
    )
    options = parser.parse_args(argv)

    manifest = json.loads(options.manifest.read_text(encoding="utf-8"))
    print(f"Python:    {sys.version.split()[0]} on {sys.platform}")
    print(
        f"Corrobora: {metadata.version('corrobora')} (expected output made with "
        f"{manifest['corrobora_version']})"
    )
    print(f"Case:      {options.case.name}")

    case_hash = _sha256_bytes(options.case.read_bytes())
    if case_hash != manifest["case_sha256"]:
        print(f"FAIL: case SHA-256 is {case_hash}, expected {manifest['case_sha256']}.")
        print("The file is incomplete, modified, or not the published reference case.")
        return 1
    print("Case SHA-256 matches the manifest.")

    failed = []
    for run in manifest["runs"]:
        actual = _run_corrobora(options.case, run["args"])
        expected_path = options.manifest.parent / run["expected_output"]
        if options.update:
            expected_path.write_bytes(actual)
            run["expected_output_sha256"] = _sha256_bytes(actual)
            print(f"  updated  {run['name']}")
            continue
        expected = expected_path.read_bytes()
        if actual == expected:
            print(f"  PASS     {run['name']}  (output SHA-256 {_sha256_bytes(actual)})")
        else:
            print(f"  FAIL     {run['name']}: output differs from {run['expected_output']}:")
            _report_diff(expected, actual)
            failed.append(run["name"])

    if options.update:
        manifest["corrobora_version"] = metadata.version("corrobora")
        options.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print("Updated the expected outputs and the manifest. Review the diff before committing.")
        return 0
    if failed:
        print(f"FAIL: {len(failed)} of {len(manifest['runs'])} run(s) differ.")
        return 1
    print(
        f"PASS: all {len(manifest['runs'])} run(s) are byte-for-byte identical "
        "to the expected output."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
