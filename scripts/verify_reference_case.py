"""Verify Corrobora against a published reference case.

Runs the exact command recorded in a reference manifest against the
reference case and checks that the output is byte-for-byte identical to
the expected output. Anyone, on Windows, macOS, or Linux, should get PASS
for the same Corrobora version and the same reference case.

Usage:
    python scripts/verify_reference_case.py <reference-case.zip>
    python scripts/verify_reference_case.py <reference-case.zip> --manifest <manifest.json>

Maintainers regenerate the expected output (after an intended change to
Corrobora's output) with ``--update``, then review the diff before
committing it.

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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_corrobora(case: Path, args: list[str], output: Path) -> None:
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


def main(argv: list[str] | None = None) -> int:
    """Verify (or, with --update, regenerate) a reference case's expected output."""
    parser = argparse.ArgumentParser(
        prog="verify_reference_case.py",
        description="Check Corrobora's output on a reference case against the expected output.",
    )
    parser.add_argument("case", type=Path, help="The reference case .zip (as downloaded).")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=_DEFAULT_MANIFEST,
        help=f"Reference manifest (default: {_DEFAULT_MANIFEST.relative_to(_REPO_ROOT)}).",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Maintainers: rewrite the expected output and its hash in the manifest.",
    )
    options = parser.parse_args(argv)

    manifest = json.loads(options.manifest.read_text(encoding="utf-8"))
    expected_path = options.manifest.parent / manifest["expected_output"]

    print(f"Python:    {sys.version.split()[0]} on {sys.platform}")
    print(f"Corrobora: {metadata.version('corrobora')} (expected output made with "
          f"{manifest['corrobora_version']})")
    print(f"Case:      {options.case.name}")

    actual_hash = _sha256(options.case)
    if actual_hash != manifest["case_sha256"]:
        print(f"FAIL: case SHA-256 is {actual_hash}, expected {manifest['case_sha256']}.")
        print("The download is incomplete or is not the published reference case.")
        return 1
    print("Case SHA-256 matches the manifest.")

    with tempfile.TemporaryDirectory() as scratch:
        output = Path(scratch) / "output.txt"
        _run_corrobora(options.case, manifest["args"], output)
        actual = output.read_bytes()

    if options.update:
        expected_path.write_bytes(actual)
        manifest["expected_output_sha256"] = hashlib.sha256(actual).hexdigest()
        manifest["corrobora_version"] = metadata.version("corrobora")
        options.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"Updated {expected_path.name} and the manifest. Review the diff before committing.")
        return 0

    expected = expected_path.read_bytes()
    if actual == expected:
        print(f"Output SHA-256: {hashlib.sha256(actual).hexdigest()}")
        print("PASS: output is byte-for-byte identical to the expected output.")
        return 0

    print("FAIL: output differs from the expected output:")
    sys.stdout.writelines(
        difflib.unified_diff(
            expected.decode("utf-8").splitlines(keepends=True),
            actual.decode("utf-8").splitlines(keepends=True),
            fromfile="expected",
            tofile="actual",
        )
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
