![VeriTrace Logo](docs/Logo_Icon/VeriTrace_logo_Icon.png)

# VeriTrace

VeriTrace is a Python-based digital forensics framework for detecting
indicators of anti-forensic activity on Windows systems through
cross-artifact consistency analysis.

Rather than parsing a single artifact type in isolation, VeriTrace
cross-references independent evidence sources -- Windows Event Logs
(EVTX), the Registry, Prefetch, and the NTFS Master File Table (MFT)
-- to surface disagreements between them that a single artifact alone
would never reveal: a program with execution evidence in Prefetch but
no corresponding EVTX log entry, registry persistence with no
supporting execution evidence at all, a Prefetch file whose name
doesn't match its own embedded hash, or a file whose timestamps show
signs of deliberate backdating (timestomping).

## Features

- **EVTX parser** -- structured extraction of Windows Event Log records,
  with per-record failure isolation and optional HTML report export.
- **Registry parser** -- recursive hive walking with full key/value
  extraction and LastWrite timestamp tracking.
- **Prefetch parser** -- execution history extraction, including
  filename/embedded-hash tamper detection.
- **MFT parser** -- a from-scratch NTFS binary parser (no third-party
  dependency) with built-in timestomping detection via
  $STANDARD_INFORMATION vs. $FILE_NAME comparison.
- **Correlation engine** -- a rule-based, fully deterministic (no AI/ML)
  engine that cross-references all four artifact types to surface
  anti-forensic indicators, ranked by severity.
- **Desktop GUI** -- a Tkinter application for running the full
  pipeline interactively, with live progress, sortable/filterable
  results, and HTML export.

## Installation

```bash
pip install -e .
```

This installs VeriTrace's dependencies (`python-evtx`, `python-registry`,
`libscca-python`) and registers the following commands on your `PATH`:

| Command | What it does |
|---|---|
| `veritrace-evtx` | Parse `.evtx` file(s) or a folder of them |
| `veritrace-registry` | Parse a registry hive file |
| `veritrace-prefetch` | Parse `.pf` file(s) or a folder of them |
| `veritrace-mft` | Parse a raw `$MFT` file and detect timestomping |
| `veritrace-correlate` | Run the full cross-artifact correlation engine |
| `veritrace-gui` | Launch the desktop GUI |

For development (running the test suite and linters):

```bash
pip install -e ".[dev]"
```

For progress bars during large EVTX parses:

```bash
pip install -e ".[progress]"
```

## Usage

```bash
# Parse a single EVTX file
veritrace-evtx Security.evtx

# Parse every .evtx file in a folder, with a progress bar
veritrace-evtx "C:\Windows\System32\winevt\Logs" --progress

# Run full cross-artifact correlation
veritrace-correlate --evtx Security.evtx --registry NTUSER.DAT \
    --prefetch "C:\Windows\Prefetch" --mft C_MFT

# Launch the GUI
veritrace-gui
```

## Running tests

```bash
pytest tests/ -v
ruff check src/
mypy src/veritrace/parsers/
pylint src/veritrace/parsers/*.py
```

## Design principles

- **No AI/ML.** Every detection rule is deterministic and explainable
  -- a finding can always be traced back to the exact fields and
  comparison that produced it.
- **Resilient parsing.** A single corrupted or unreadable record,
  file, or artifact never aborts an entire analysis run; failures are
  isolated, logged, and reported alongside successful results.
- **Testable by design.** Detection logic is decoupled from file I/O
  wherever possible, so rules and extractors can be (and are) unit
  tested against synthetic data without requiring real forensic
  images.

## Project status

This project is under active development. See `pyproject.toml` for a
note on the current flat-module package layout and a planned
namespaced-package refactor.

## License

MIT -- see `LICENSE`.