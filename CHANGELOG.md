# Changelog

All notable changes to Corrobora are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/). While the version is 0.x,
commands, output formats, and APIs may change between minor releases.

## [0.1.0] - Unreleased

First public pre-release. Corrobora is **alpha software and is not
validated for evidentiary use**; see "Status and limitations" in the README
for what has and hasn't been tested.

Corrobora was developed under the name VeriTrace as a master's capstone
project and renamed on August 7, 2026.

### Added

- **Artifact parsers** for Windows Event Logs (EVTX), registry hives,
  Prefetch, and the NTFS `$MFT` (a from-scratch binary parser), each with
  per-record failure isolation and a shared normalized interface.
- **Program-execution corroboration**
  (`Corrobora-corroborate <case> --window SECONDS [--subject NAME]`):
  - A normalized `EvidenceRecord` model, with each timestamp's meaning
    recorded as `TimestampSemantics` and whether it marks process start or
    exit as `TimestampAnchor`.
  - Evidence extractors for Prefetch run times, Security 4688 and Sysmon
    Event ID 1 process creation (matched on provider as well as Event ID),
    and Registry BAM/DAM entries.
  - Results of *Corroborated*, *Partially Corroborated*, or *Needs Review*,
    with a plain-language explanation. A missing or disagreeing source is
    never reported as proof of deletion or tampering.
  - A required correlation window with no default. Start-time evidence is
    compared within the window; BAM, which records process exit, is
    matched to the most recent run that started before it.
  - Sources that were not examined are distinguished from sources with no
    evidence.
  - `--list-evidence` lists every record behind a result with millisecond
    timestamps; `--list-files` lists every parsed file.
- **Timestamp measurements** from a controlled test on Windows 11 build
  26200, documented on `TimestampSemantics`: Prefetch 30-32 ms and 4688
  0-1 ms after process start, BAM 2 ms after process exit.
- **Rule-based correlation engine** (`Corrobora-correlate`) with rules for
  Prefetch execution without a matching EVTX event, registry run-key
  persistence without execution evidence, Prefetch filename/hash mismatch,
  EVTX record-number gaps, and MFT timestomping, plus per-application
  corroboration scores.
- **Case ingest** (`Corrobora-case`): discovers artifacts in a folder or
  `.zip`, including KAPE-style triage collections.
- **Disk image support** (optional `images` extra): extracts artifacts
  directly from E01/EWF, VHD/VHDX, VMDK, and raw/dd images.
- **EZ Tools integration**: import CSV output from Eric Zimmerman's EZ
  Tools (`Corrobora-ez-import`) or run the tools directly
  (`Corrobora-ez-run`, optional).
- **Desktop GUI** (`Corrobora-gui`, PyQt5) with HTML report export. Enter
  a correlation window next to **Process** to run program-execution
  corroboration in the GUI: a filterable per-program results panel, with
  the full report and evidence list for the selected program. It reuses
  the artifacts already parsed for the rules, so no file is parsed twice.
- **Continuous integration**: pytest on Windows for Python 3.11-3.13, and
  pylint.

### Changed

- Findings from the older rules no longer imply tampering: absence-based
  findings state that the absence alone does not establish deletion or log
  clearing, and the lowest per-application assessment reads "Limited
  corroboration" instead of "Artifact inconsistency detected."
- Per-application corroboration scores count only artifact types that were
  actually loaded; the GUI shows other types as "Not Examined".

### Fixed

- The Prefetch-vs-EVTX rule no longer flags every Prefetch run when the
  loaded event logs contain no process-creation events (for example,
  because process-creation auditing is off, the Windows default); it
  reports the coverage gap once instead.
- Event ID 1 is only treated as process creation when logged by Sysmon.
- `Corrobora-registry --help` and `Corrobora-prefetch --help` print usage
  instead of treating `--help` as a file path.

[0.1.0]: https://github.com/Gear-I/Corrobora/releases/tag/v0.1.0
