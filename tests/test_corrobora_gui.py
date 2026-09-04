"""Unit tests for corrobora_gui's GUI-framework-independent helper functions.

These are the only parts of ``corrobora_gui.py`` covered by automated
tests -- the PyQt5 widgets themselves are out of scope (fragile and
low-value to test headlessly). ``run_analysis`` and ``findings_to_html``
have no Qt dependency, so they're tested the same way as any other
pure function in this project: hand-built or real synthetic inputs,
no mocking.
"""

# pylint: disable=missing-function-docstring
# Test function names are self-descriptive; per-test docstrings would
# just restate the name.

from __future__ import annotations

from pathlib import Path

from corrobora.parsers.corrobora_gui import (
    findings_to_html,
    generate_sample_mft_bytes,
    run_analysis,
)
from corrobora.rules.base import CorrelationFinding, Severity
from corrobora.rules.rule_registry import RULE_REGISTRY


class TestRunAnalysis:
    """Tests for run_analysis()'s rules-filtering behavior."""

    def test_no_sources_no_rules_arg_produces_no_findings_and_no_error(self) -> None:
        outcome = run_analysis([], [], [], [])

        assert outcome.error is None
        assert not outcome.findings

    def test_empty_rules_list_produces_no_findings_even_against_real_data(
        self, tmp_path: Path
    ) -> None:
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(generate_sample_mft_bytes())

        outcome = run_analysis([], [], [], [str(mft_file)], rules=[])

        assert outcome.error is None
        assert not outcome.findings

    def test_rules_param_is_actually_used_not_ignored(self, tmp_path: Path) -> None:
        # generate_sample_mft_bytes() includes one deliberately
        # timestomped record, so filtering to only "integrity"-category
        # rules should surface the timestomping finding.
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(generate_sample_mft_bytes())
        integrity_rules = [
            rule_cls() for rule_cls in RULE_REGISTRY.values() if rule_cls.category == "integrity"
        ]

        outcome = run_analysis([], [], [], [str(mft_file)], rules=integrity_rules)

        assert outcome.error is None
        assert any(f.rule_name == "mft_timestomping_detected" for f in outcome.findings)

    def test_nonexistent_path_is_skipped_not_raised(self, tmp_path: Path) -> None:
        # build_context's per-file loaders catch and log file-level
        # failures rather than propagating them, so a missing file
        # produces an empty (not errored) outcome -- this confirms
        # run_analysis's new `rules` parameter didn't change that
        # existing resilience behavior.
        missing = tmp_path / "does_not_exist" / "MFT"

        outcome = run_analysis([], [], [], [str(missing)])

        assert outcome.error is None
        assert not outcome.findings


class TestFindingsToHtml:
    """Tests for findings_to_html(), including the new Score column."""

    def _make_finding(self, score: int, rule_name: str = "test_rule") -> CorrelationFinding:
        return CorrelationFinding(
            rule_name=rule_name,
            severity=Severity.HIGH,
            description="a test finding",
            evidence=("evidence line",),
            source_paths=("source.evtx",),
            score=score,
        )

    def test_renders_score_column_header(self) -> None:
        html_doc = findings_to_html([self._make_finding(score=87)])

        assert "<th>Score</th>" in html_doc

    def test_renders_each_finding_score_value(self) -> None:
        findings = [
            self._make_finding(score=87, rule_name="rule_a"),
            self._make_finding(score=12, rule_name="rule_b"),
        ]

        html_doc = findings_to_html(findings)

        assert "<td>87</td>" in html_doc
        assert "<td>12</td>" in html_doc

    def test_empty_findings_renders_placeholder_row(self) -> None:
        html_doc = findings_to_html([])

        assert '<tr><td colspan="6">No findings.</td></tr>' in html_doc

    def test_html_escapes_adversarial_description(self) -> None:
        finding = CorrelationFinding(
            rule_name="test_rule",
            severity=Severity.HIGH,
            description="<script>alert('xss')</script>",
            evidence=(),
            source_paths=(),
            score=50,
        )

        html_doc = findings_to_html([finding])

        assert "<script>" not in html_doc
        assert "&lt;script&gt;" in html_doc
