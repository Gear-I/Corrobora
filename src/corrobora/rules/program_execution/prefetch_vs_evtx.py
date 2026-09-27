"""Prefetch-vs-EVTX program execution corroboration rule."""

from __future__ import annotations

from datetime import datetime, timedelta

from corrobora.extractors.evtx import SECURITY_AUDITING_PROVIDER, SYSMON_PROVIDER

from ..base import CorrelationContext, CorrelationFinding, CorrelationRule, EvtxEntry, Severity

# (provider, Event ID) pairs that represent process creation, used to
# look for corroborating evidence of a Prefetch-recorded execution.
# Matched on both: Event IDs are only unique within a provider, and
# Event ID 1 in particular is logged by many unrelated providers (e.g.
# Kernel-General in the System log).
_DEFAULT_PROCESS_CREATION_EVENTS = frozenset(
    {(SECURITY_AUDITING_PROVIDER, 4688), (SYSMON_PROVIDER, 1)}
)

# Corroboration-strength score for this rule's findings: absence-based
# (no matching EVTX event found), which is a weaker signal than a
# positive tamper indicator -- see the rule's own docstring.
_SCORE = 45

# Score for the single coverage finding emitted when the loaded EVTX data
# contains no process-creation events at all: it records a limit of the
# evidence, not anything about any particular execution.
_NO_COVERAGE_SCORE = 10

# How many EVTX source paths to list as evidence on the coverage finding.
_MAX_LISTED_SOURCES = 10


class PrefetchExecutionWithoutEvtxRule(CorrelationRule):  # pylint: disable=too-few-public-methods
    """Flags Prefetch-recorded executions with no corresponding EVTX event.

    For each Prefetch run timestamp, this rule looks for an EVTX
    process-creation event (by default, Security Event ID 4688 or Sysmon
    Event ID 1, each from its own provider) within a configurable time window whose message text
    references the executable's name. If none is found, the
    execution is flagged for examiner review. The most common causes
    are benign: process-creation auditing is disabled by default on
    Windows, the Security log may have rolled over since the run, and
    the executable name may not appear in the event text this rule
    searches. Cleared or altered logs are one possible explanation, but
    this absence alone does not establish it.

    If EVTX data was loaded but contains no process-creation events at
    all, there is nothing to compare against: every run would be
    flagged. The rule instead emits one ``INFO`` finding stating that
    the Prefetch executions could not be checked.

    Note:
        Matching relies on a substring search of the executable name
        within each EVTX record's concatenated ``message`` field,
        since Corrobora's EVTX parser does not structurally parse
        named EventData fields (see ``evtx.py``). This is a
        deliberate, documented limitation: it will not catch cases
        where the process name appears only in an unparsed/binary
        field, and can occasionally over-match on short executable
        names. Treat findings as investigative leads, not proof.
    """

    rule_name = "prefetch_execution_without_evtx"
    category = "program_execution"

    def __init__(
        self,
        time_window: timedelta = timedelta(minutes=5),
        process_creation_events: frozenset[tuple[str, int]] = _DEFAULT_PROCESS_CREATION_EVENTS,
    ) -> None:
        """Initialize the rule.

        Args:
            time_window: How far before/after a Prefetch run
                timestamp to search for a matching EVTX event.
            process_creation_events: The ``(provider name, Event ID)``
                pairs considered process-creation evidence.
        """
        self._time_window = time_window
        self._process_creation_events = process_creation_events

    def evaluate(self, context: CorrelationContext) -> list[CorrelationFinding]:
        if not context.evtx_entries:
            # No EVTX data was provided at all, so "no matching event
            # found" would be true of every single Prefetch execution --
            # this rule stays silent rather than flagging every recorded
            # execution just because nothing was loaded to check against.
            return []

        candidate_events = [
            entry
            for entry in context.evtx_entries
            if (entry.record.provider_name, entry.record.event_id)
            in self._process_creation_events
            and entry.record.timestamp is not None
        ]
        if not candidate_events:
            # EVTX data was loaded but holds no process-creation events
            # (typically because process-creation auditing is off, the
            # Windows default, and Sysmon isn't installed). Every run
            # would trivially lack a match, so report the coverage gap
            # once instead of flagging each execution.
            return self._no_coverage_finding(context)

        findings: list[CorrelationFinding] = []
        for prefetch_entry in context.prefetch_entries:
            record = prefetch_entry.record
            if not record.executable_name:
                continue
            for run_time in record.last_run_times:
                if self._has_matching_event(record.executable_name, run_time, candidate_events):
                    continue
                findings.append(
                    CorrelationFinding(
                        rule_name=self.rule_name,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Prefetch shows '{record.executable_name}' executed at "
                            f"{run_time.isoformat()}, but no matching EVTX "
                            f"process-creation event was found within "
                            f"{self._time_window}. This absence alone does not "
                            f"establish log clearing: process-creation auditing "
                            f"is off by default and logs roll over. Examiner "
                            f"review is required."
                        ),
                        evidence=(
                            f"Prefetch source: {prefetch_entry.source_path}",
                            f"Run timestamp: {run_time.isoformat()}",
                        ),
                        source_paths=(prefetch_entry.source_path,),
                        score=_SCORE,
                    )
                )
        return findings

    def _has_matching_event(
        self,
        executable_name: str,
        run_time: datetime,
        candidate_events: list[EvtxEntry],
    ) -> bool:
        """Check whether any candidate EVTX event corroborates a run timestamp.

        Args:
            executable_name: The Prefetch executable name to search
                for.
            run_time: The Prefetch run timestamp to match against.
            candidate_events: EVTX entries already filtered to
                process-creation event IDs with a known timestamp.

        Returns:
            ``True`` if a matching event was found, ``False``
            otherwise.
        """
        name_lower = executable_name.lower()
        window_start = run_time - self._time_window
        window_end = run_time + self._time_window
        for entry in candidate_events:
            timestamp = entry.record.timestamp
            if timestamp is None or not window_start <= timestamp <= window_end:
                continue
            message = (entry.record.message or "").lower()
            if name_lower in message:
                return True
        return False

    def _no_coverage_finding(self, context: CorrelationContext) -> list[CorrelationFinding]:
        """Build the single coverage-gap finding for EVTX without process creation.

        Args:
            context: The correlation context being evaluated.

        Returns:
            One ``INFO`` finding, or an empty list if there are no
            Prefetch run times that would have been checked.
        """
        run_count = sum(
            len(entry.record.last_run_times)
            for entry in context.prefetch_entries
            if entry.record.executable_name
        )
        if not run_count:
            return []
        evtx_sources = sorted({entry.source_path for entry in context.evtx_entries})
        listed = evtx_sources[:_MAX_LISTED_SOURCES]
        evidence = tuple(f"EVTX source checked: {path}" for path in listed)
        if len(evtx_sources) > len(listed):
            evidence += (f"... and {len(evtx_sources) - len(listed)} more EVTX source(s)",)
        return [
            CorrelationFinding(
                rule_name=self.rule_name,
                severity=Severity.INFO,
                description=(
                    f"{run_count} Prefetch-recorded execution(s) could not be checked "
                    f"against EVTX: the loaded event logs contain no process-creation "
                    f"events (Security 4688 or Sysmon 1). Process-creation auditing is "
                    f"off by default on Windows and Sysmon is not installed by default. "
                    f"This is a limit of the available evidence, not an indication of "
                    f"tampering."
                ),
                evidence=evidence,
                source_paths=tuple(evtx_sources),
                score=_NO_COVERAGE_SCORE,
            )
        ]
