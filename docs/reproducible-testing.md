# Reproducible testing

This guide gives a fixed procedure for testing Corrobora that anyone can
repeat, any number of times, on Windows, macOS, or Linux, and get
**byte-for-byte identical output** every time.

It works because every input is fixed:

| Input | Fixed by |
|---|---|
| The evidence | A published **reference case** (a zip of real Windows artifacts from a clean test VM), identified by its SHA-256 |
| The command | The exact arguments recorded in the reference manifest |
| The Corrobora version | The version the expected output was made with, recorded in the manifest |
| Paths and line endings | `--relative-paths` (paths relative to the case, `/` separators) and `--output` (UTF-8, `\n` line endings) |

Corrobora itself is deterministic: no randomness, no network access, no
dependence on the local time zone or locale (all times are UTC), and files
are processed in a fixed order.

> **Status:** the reference case has not been published yet. The
> procedure and tooling below are in place; the download link, SHA-256,
> and expected output will be added to `tests/reference/case-1/` when it
> is.

## 1. Install

You need Python 3.11 or later and Git.

**Windows (PowerShell)**

```powershell
git clone https://github.com/Gear-I/Corrobora.git
cd Corrobora
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

**macOS and Linux**

```bash
git clone https://github.com/Gear-I/Corrobora.git
cd Corrobora
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

On Linux, the PyQt5 dependency needs a few system libraries even though
this procedure doesn't open the GUI. On Debian or Ubuntu:

```bash
sudo apt-get install -y libegl1 libgl1 libxkbcommon0 libfontconfig1 libdbus-1-3
```

To test the exact version the expected output was made with, check out its
tag before installing (for example `git checkout v0.1.0`). The manifest's
`corrobora_version` names it.

## 2. Download the reference case

Download the reference case zip from the link in
`tests/reference/case-1/manifest.json` (`case_url`). **Don't unzip it**:
Corrobora reads the zip directly, and the verification checks the zip's
SHA-256 exactly as published.

## 3. Verify

From the repository folder, with the virtual environment active:

```bash
python scripts/verify_reference_case.py path/to/corrobora-reference-case-1.zip
```

The script:

1. checks the zip's SHA-256 against the manifest, so a corrupted or
   different download fails immediately;
2. runs `corrobora-corroborate` with the exact arguments from the manifest;
3. compares the output, byte for byte, with the expected output.

A successful run ends with:

```text
PASS: output is byte-for-byte identical to the expected output.
```

On a mismatch it prints `FAIL` and a line-by-line diff. The first lines
show your Python version, operating system, and Corrobora version, so
include them when reporting a difference.

## 4. Run it yourself

The verification runs this command, which you can run directly to see and
keep the output:

```bash
corrobora-corroborate path/to/corrobora-reference-case-1.zip --window 30 --subject powershell.exe --list-evidence --relative-paths --output output.txt
```

Check that `output.txt` matches the manifest's `expected_output_sha256`:

| OS | Command |
|---|---|
| Windows (PowerShell) | `Get-FileHash output.txt -Algorithm SHA256` |
| macOS | `shasum -a 256 output.txt` |
| Linux | `sha256sum output.txt` |

Windows prints the hash in upper case; the comparison is case-insensitive.

## What makes output differ

| Cause | Why |
|---|---|
| A different or modified case | Different evidence, different results. The SHA-256 check catches this. |
| A different Corrobora version | Output formats can change between versions (see `CHANGELOG.md`). Check out the manifest's version. |
| Omitting `--relative-paths` | Paths then include where the case was unzipped. |
| Redirecting output (`> output.txt`) instead of `--output` | On Windows, redirection writes `\r\n` line endings. |
| Different arguments | A different window, subject, or options is a different test. |

Files that fail to parse are reported with the parser's own error text,
which can differ between operating systems. The reference case therefore
contains only files that parse cleanly.

## How the reference case is built

The reference case is built once, by a maintainer, on a **clean Windows
VM** with no personal data:

1. Enable process-creation auditing (Security 4688).
2. Launch `powershell.exe` several times at recorded times, each run kept
   open for a fixed period.
3. Collect the Prefetch files, a Security log export containing only
   Event ID 4688, and the `SYSTEM` hive.
4. Zip the collection, record its SHA-256, and publish it as a GitHub
   release asset.
5. Generate the expected output with
   `python scripts/verify_reference_case.py <zip> --update` and commit it
   with the manifest.

The recorded run times are included in the zip (`runs.csv`), so the
timestamps Corrobora reports can be checked against when each process
actually started and exited.
