# Contributing to Corrobora

Thank you for your interest in contributing to **Corrobora**!

Corrobora is an open-source Windows digital forensics framework focused on detecting potential indicators of anti-forensic activity through cross-artifact consistency analysis. The goal of the project is to support investigators by improving confidence in digital evidence through transparent, explainable, and repeatable forensic analysis.

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
- Disk image ingestion (E01/EWF, VHD/VHDX, VMDK, raw/dd) as an alternative to an
  already-extracted evidence folder -- see the optional `images` extra
- A PyQt5 desktop GUI
- HTML reporting

JSON reporting has been discussed but is not implemented yet -- it's a reasonable
first contribution if you're looking for one. Future releases may include support for
additional Windows forensic artifacts (e.g. Amcache, SRUM, Jump Lists).

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