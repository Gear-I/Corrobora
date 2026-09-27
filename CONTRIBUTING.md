# Contributing to Corrobora

Thank you for your interest in contributing to **Corrobora**!

Corrobora is an open-source Windows digital forensics framework that checks whether independent artifacts (Prefetch, EVTX, Registry, MFT) corroborate each other. The goal of the project is to support investigators by improving confidence in digital evidence through transparent, explainable, and repeatable forensic analysis. Missing or disagreeing artifacts are reported as discrepancies for examiner review, not as proof of tampering.

At this stage, Corrobora is being developed as part of a master's capstone project (originally under the name VeriTrace -- see the README's Project History section). Contributions are welcome as the project matures.

---

## Code of Conduct

Please be respectful, constructive, and professional in all interactions.

We welcome contributors from all backgrounds who are interested in digital forensics, DFIR, cybersecurity, software engineering, and open-source development.

---

## Before Contributing

Please:

- Search existing Issues before creating a new one.
- Open an Issue to discuss significant feature requests before beginning implementation.
- Keep pull requests focused on a single change whenever possible.
- Follow the project's coding standards.

---

## Development Environment

Recommended environment:

- Python 3.11+ (see `pyproject.toml`'s `requires-python`; the desktop GUI and disk-image
  support depend on packages with prebuilt wheels for 3.11-3.13)
- Visual Studio Code
- Git
- GitHub

Clone the repository:

```bash
git clone https://github.com/Gear-I/Corrobora.git
cd Corrobora
```

Install in editable mode, with the development extras (test runner and linters):

```bash
pip install -e ".[dev]"
```

Two more optional extras exist for specific capabilities you may not need for every
change: `pip install -e ".[progress]"` (progress bars for large EVTX parses) and
`pip install -e ".[images]"` (disk image ingestion -- E01/EWF, VHD/VHDX, VMDK, raw/dd).
See the README's Installation section for details.

---

## Coding Standards

Corrobora follows the following standards:

- PEP 8
- Type hints
- Google-style docstrings
- Meaningful variable and function names
- Small, modular functions
- Robust exception handling
- Logging instead of print statements

Please avoid unnecessary complexity.

---

## Adding Evidence Sources and Rules

Cross-artifact corroboration is built in layers, so each part only knows what it needs to:

1. **Parsers** (`src/corrobora/parsers/`) read an artifact format into native records. They stay
   generic and make no claims about what a record means.
2. **Extractors** (`src/corrobora/extractors/`) decide which native records are evidence of
   something and turn them into `EvidenceRecord`s (`src/corrobora/models/evidence.py`).
3. **Correlation** (`src/corrobora/correlation/`) compares `EvidenceRecord`s only; it never reads
   an artifact format directly.

To add a new evidence source (for example Amcache or UserAssist), write an extractor that produces
`EvidenceRecord`s and give each one a `TimestampSemantics` value stating what its timestamp
actually records. If the timestamp's meaning isn't a match for an existing value, add a new one
and document what is known and what still needs verifying. A new parser is most useful when it
supplies another source to an existing correlation rule.

### Wording findings

Findings are read by examiners and may end up in reports, so they should describe what was
compared and what was found, not conclusions the evidence can't support:

- Don't describe a missing artifact as deletion, log clearing, or anti-forensic activity.
  Artifacts are routinely absent for ordinary reasons (auditing off by default, log rollover,
  Prefetch eviction, an incomplete collection). Say what was not found and that examiner review
  is required.
- Distinguish "not found" from "not examined". If a source wasn't loaded, don't count it as
  missing.
- Don't present a configurable threshold (such as a correlation time window) as a validated
  forensic value.

---

## Running Tests

Run all unit tests before submitting a pull request.

```bash
pytest
```

Run Pylint exactly as CI does (the project currently holds a 10.00/10 score --
please keep it there, adding a documented `# pylint: disable=...` with a
rationale comment for any genuine false positive rather than a blanket
suppression):

```bash
pylint $(git ls-files '*.py')
```

Pull requests should pass all GitHub Actions workflows.

---

## Branch Naming

Please use descriptive branch names.

Examples:

```
feature/registry-parser
feature/prefetch-parser
feature/html-report

bugfix/event-log-parser

docs/readme-update

test/registry-tests
```

---

## Commit Messages

This project does not use Conventional Commits (`feat:`/`fix:`/`docs:` prefixes) --
write a plain, imperative-mood summary line instead, followed by a blank line and a
body explaining *why* the change was made (not just what changed; the diff already
shows that).

Examples, matching this project's actual history:

```
Add disk image support (E01/EWF, VHD/VHDX, VMDK, raw/dd)

Fix pylint findings and the bugs they caught

Extract correlation rules into a plugin-style rules layer

Restructure Findings into a per-application corroboration view
```

---

## Pull Requests

Please include:

- A clear summary
- Motivation for the change
- Testing performed
- Screenshots (if applicable)
- Related Issue number

Example:

```
## Summary

Implemented the initial Registry parser.

## Changes

- Added Registry parser
- Added error handling
- Added unit tests

## Testing

- pytest
- pylint

Closes #12
```

---

## Reporting Bugs

When reporting bugs, include:

- Operating system
- Python version
- Sample input (if possible)
- Expected behavior
- Actual behavior
- Error messages
- Stack trace

---

## Feature Requests

Feature requests are encouraged.

Please describe:

- The problem
- Why it matters
- Proposed solution
- Example workflow

---

## Project Goals

Version 1 currently supports:

- Windows Event Logs (EVTX)
- Windows Registry
- Windows Prefetch
- NTFS Master File Table (MFT), including timestomping detection
- A modular, rule-based cross-artifact correlation engine (see `src/corrobora/rules/`),
  including per-application cross-artifact corroboration scoring
- Program-execution corroboration across Prefetch, EVTX (Security 4688 / Sysmon 1), and
  Registry BAM/DAM, built on a normalized evidence model (see `src/corrobora/models/`,
  `src/corrobora/extractors/`, and `src/corrobora/correlation/`), with the
  `corrobora-corroborate` command
- Disk image ingestion (E01/EWF, VHD/VHDX, VMDK, raw/dd) as an alternative to an
  already-extracted evidence folder -- see the optional `images` extra
- A PyQt5 desktop GUI
- HTML reporting

JSON reporting has been discussed but is not implemented yet -- it's a reasonable
first contribution if you're looking for one. Future releases may include support for
additional Windows forensic artifacts (e.g. Amcache, UserAssist, SRUM, Jump Lists), ideally as
additional evidence sources for the existing program-execution corroboration.

Open research questions are also good contributions: what each artifact's timestamp records and
how far apart related timestamps can be (see `TimestampSemantics` in
`src/corrobora/models/evidence.py`). Findings tested against real data are especially valuable.

---

## Security

If you discover a security issue within Corrobora itself, please do not publicly disclose it immediately.

Instead, open a private discussion or contact the project maintainer.

---

## License

By contributing to Corrobora, you agree that your contributions will be licensed under the project's MIT License.

---

## Thank You

Thank you for helping improve Corrobora and supporting the digital forensics community.

Every contribution—whether code, documentation, bug reports, or ideas is appreciated.