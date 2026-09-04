"""Registry-persistence-vs-Prefetch corroboration rule."""

from __future__ import annotations

import re

from ..base import CorrelationContext, CorrelationFinding, CorrelationRule, Severity

# Registry key path SEGMENTS (i.e. an exact component between backslashes,
# not a substring anywhere in the path) that identify a run-at-startup
# persistence location. Matched case-insensitively.
#
# This must be an exact segment match, not a substring match: a naive
# substring check for "\Run" also matches inside "\RunAs\" (the standard
# Windows shell "Run as..." context-menu verb, present under nearly every
# file type's Classes key -- completely unrelated to startup persistence),
# producing a large number of false positives on any real registry hive.
_DEFAULT_PERSISTENCE_KEY_SEGMENTS = (
    "run",
    "runonce",
    "runservices",
    "runservicesonce",
)

# Regex to pull an "something.exe" reference out of free-form registry
# value data (e.g. a Run key's command line).
_EXE_REFERENCE_PATTERN = re.compile(r"([^\\/\s\"]+\.exe)", re.IGNORECASE)

# Corroboration-strength score for this rule's findings: absence-based
# (no Prefetch evidence of execution), weaker than a positive
# contradiction -- see the rule's own docstring.
_SCORE = 35


class RegistryPersistenceWithoutExecutionRule(
    CorrelationRule
):  # pylint: disable=too-few-public-methods
    """Flags registry run-key persistence with no supporting Prefetch evidence.

    For each registry value under a known persistence key path (Run,
    RunOnce, etc.) whose data references an executable, this rule
    checks whether any Prefetch record shows that executable having
    ever run. A persistence entry with no execution evidence may
    indicate the entry was recently planted and hasn't fired yet, or
    that the corresponding Prefetch file was deliberately deleted to
    hide execution (Prefetch deletion/disabling is a well-known
    anti-forensic technique).

    Note:
        This rule flags an *absence* of evidence, which is inherently
        weaker than flagging a positive contradiction -- a program
        genuinely may not have run yet. Treat findings as leads for
        further investigation (e.g. checking install timestamps),
        not confirmed tampering.
    """

    rule_name = "persistence_without_execution"
    category = "persistence"

    def __init__(
        self,
        persistence_key_segments: tuple[str, ...] = _DEFAULT_PERSISTENCE_KEY_SEGMENTS,
    ) -> None:
        """Initialize the rule.

        Args:
            persistence_key_segments: Key-path segment names (matched
                case-insensitively as a full path component, e.g.
                ``"Run"`` matches ``...\\Run\\Foo`` but not
                ``...\\RunAs\\Foo``) that identify a run-at-startup
                persistence location.
        """
        self._persistence_key_segments = frozenset(
            s.lower() for s in persistence_key_segments
        )

    def evaluate(self, context: CorrelationContext) -> list[CorrelationFinding]:
        if not context.prefetch_entries:
            # No Prefetch data was provided at all, so "no execution
            # evidence found" would be true of every single persistence
            # entry -- including completely benign ones -- and wouldn't
            # reflect anything about the entries themselves. Firing here
            # would mean "we never checked," not "we checked and found
            # nothing," so this rule stays silent rather than producing
            # findings that carry no real information.
            return []

        executed_names = {
            entry.record.executable_name.lower()
            for entry in context.prefetch_entries
            if entry.record.executable_name and entry.record.run_count
        }

        findings: list[CorrelationFinding] = []
        for entry in context.registry_value_entries:
            if not self._is_persistence_key(entry.value.key_path):
                continue
            exe_name = self._extract_exe_name(entry.value.data)
            if exe_name is None:
                continue
            if exe_name.lower() in executed_names:
                continue
            findings.append(
                CorrelationFinding(
                    rule_name=self.rule_name,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Registry persistence entry '{entry.value.key_path}\\"
                        f"{entry.value.name or '(default)'}' references "
                        f"'{exe_name}', but no Prefetch evidence of it ever "
                        f"executing was found."
                    ),
                    evidence=(
                        f"Registry source: {entry.source_path}",
                        f"Key path: {entry.value.key_path}",
                        f"Value data: {entry.value.data!r}",
                    ),
                    source_paths=(entry.source_path,),
                    score=_SCORE,
                )
            )
        return findings

    def _is_persistence_key(self, key_path: str) -> bool:
        """Check whether a key path contains a known persistence key segment.

        Uses exact per-segment matching (splitting on backslash), not
        substring containment -- so ``"...\\Run\\Foo"`` matches but
        ``"...\\RunAs\\Foo"`` does not, even though the latter
        contains ``"Run"`` as a raw substring.

        Args:
            key_path: The registry key path to check.

        Returns:
            ``True`` if any path segment exactly matches (case-insensitively)
            one of the configured persistence key segment names.
        """
        segments = (s.lower() for s in key_path.split("\\"))
        return any(segment in self._persistence_key_segments for segment in segments)

    @staticmethod
    def _extract_exe_name(value_data: object) -> str | None:
        """Extract an ``something.exe`` reference from registry value data.

        Args:
            value_data: The raw value data (typically a string
                command line for persistence entries).

        Returns:
            The referenced executable's filename (no path), or
            ``None`` if no ``.exe`` reference was found.
        """
        if not isinstance(value_data, str):
            return None
        match = _EXE_REFERENCE_PATTERN.search(value_data)
        return match.group(1) if match else None
