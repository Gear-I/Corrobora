# Reproducible testing

This guide gives a fixed procedure for testing Corrobora that anyone can
repeat, any number of times, on Windows, macOS, or Linux, and get
**byte-for-byte identical output** every time.

It works because every input is fixed:

| Input | Fixed by |
|---|---|
| The evidence | The **reference case**: a synthetic Windows case, built by a deterministic script and identified by its SHA-256 |
| The commands | The exact arguments recorded in the reference manifest |
| The Corrobora version | The version the expected output was made with, recorded in the manifest |
| Paths and line endings | `--relative-paths` (paths relative to the case, `/` separators) and `--output` (UTF-8, `\n` line endings) |

Corrobora itself is deterministic: no randomness, no network access, no
dependence on the local time zone or locale (all times are UTC), and files
are processed in a fixed order. CI runs the whole procedure on Windows,
macOS, and Linux with Python 3.11, 3.12, and 3.13.

## The reference case

`corrobora-reference-case-1.zip` is **synthetic**: every file is generated
by [`scripts/build_reference_case.py`](../scripts/build_reference_case.py),
and the computer (`DEMO-WS01`), account (`analyst`), SID, programs, and
times are fictional. No real system's data is included, so it is safe to
share and inspect.

The files are minimal but valid instances of the real formats that
Corrobora's parsers read:

| File | Format |
|---|---|
| `*.pf` (7 files) | Prefetch version 26 (Windows 8.1 layout), uncompressed |
| `Security.evtx` | EVTX 3.1, Security log, Event ID 4688 only, with valid checksums |
| `SYSTEM` | Registry hive (regf 1.5) with the `Select` and BAM keys |
| `runs.csv` | Ground-truth start and exit times of the `powershell.exe` runs |

The timings follow what was measured on a real system (see
`TimestampSemantics` in `src/corrobora/models/evidence.py`): 4688 at
process start, Prefetch about 30 ms later, BAM about 2 ms after exit.

Each program is set up to exercise a different outcome at a 30-second
window:

| Program | Evidence | Result |
|---|---|---|
| `powershell.exe` | Prefetch, 4688, and BAM for the last of three runs | Corroborated |
| `certutil.exe` | Prefetch, 4688, BAM | Corroborated |
| `cmd.exe` | Prefetch, 4688; no BAM entry | Partially Corroborated |
| `whoami.exe` | Prefetch, 4688; BAM holds an earlier run's exit (still running at collection) | Partially Corroborated |
| `notepad.exe` | Prefetch, BAM; ran before auditing was enabled | Partially Corroborated |
| `ping.exe` | Prefetch, and a 4688 event 45 s away | Needs Review |
| `mspaint.exe` | Prefetch only | Needs Review |

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

The manifest's `corrobora_version` names the version the expected output
was made with; the manifest and expected outputs in a given commit always
match the code in that commit.

## 2. Build the reference case

From the repository folder, with the virtual environment active:

```bash
python scripts/build_reference_case.py build
```

This writes `build/corrobora-reference-case-1.zip` and prints its SHA-256.
The build is deterministic (sorted, uncompressed zip entries with fixed
timestamps), so it must print the same SHA-256 as `case_sha256` in
[`tests/reference/case-1/manifest.json`](../tests/reference/case-1/manifest.json)
on every machine.

## 3. Verify

```bash
python scripts/verify_reference_case.py build/corrobora-reference-case-1.zip
```

The script:

1. checks the zip's SHA-256 against the manifest;
2. runs `corrobora-corroborate` with each set of arguments in the manifest;
3. compares each output, byte for byte, with its expected output.

A successful run ends with:

```text
PASS: all 2 run(s) are byte-for-byte identical to the expected output.
```

On a mismatch it prints `FAIL` and a line-by-line diff. The first lines
show your Python version, operating system, and Corrobora version, so
include them when reporting a difference.

## 4. Run it yourself

These are the two commands the verification runs, so you can see and keep
the output:

```bash
corrobora-corroborate build/corrobora-reference-case-1.zip --window 30 --relative-paths --list-files --output summary.txt
corrobora-corroborate build/corrobora-reference-case-1.zip --window 30 --relative-paths --subject powershell.exe --subject whoami.exe --subject notepad.exe --subject ping.exe --list-evidence --output reports.txt
```

Each file's SHA-256 should equal the matching `expected_output_sha256` in
the manifest:

| OS | Command |
|---|---|
| Windows (PowerShell) | `Get-FileHash summary.txt -Algorithm SHA256` |
| macOS | `shasum -a 256 summary.txt` |
| Linux | `sha256sum summary.txt` |

Windows prints the hash in upper case; the comparison is case-insensitive.

## What makes output differ

| Cause | Why |
|---|---|
| A different or modified case | Different evidence, different results. The SHA-256 check catches this. |
| A different Corrobora version | Output formats can change between versions (see `CHANGELOG.md`). Use the manifest from the same commit as the code. |
| Omitting `--relative-paths` | Paths then include where the case was built. |
| Redirecting output (`> file.txt`) instead of `--output` | On Windows, redirection writes `\r\n` line endings. |
| Different arguments | A different window, subject, or options is a different test. |

Files that fail to parse are reported with the parser's own error text,
which can differ between operating systems. The reference case therefore
contains only files that parse cleanly (a test checks this).

## For maintainers

After an intended change to Corrobora's output, regenerate the expected
outputs, review the diff, and commit them with the change:

```bash
python scripts/build_reference_case.py build
python scripts/verify_reference_case.py build/corrobora-reference-case-1.zip --update
git diff tests/reference/
```

Changing the scenario in `build_reference_case.py` changes the zip, so
update `case_sha256` in the manifest as well. Expected outputs are stored
with their line endings untouched (see `.gitattributes`).
