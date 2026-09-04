"""Prefetch-vs-EVTX program execution corroboration rule."""

from __future__ import annotations

from datetime import datetime, timedelta

from ..base import CorrelationContext, CorrelationFinding, CorrelationRule, EvtxEntry, Severity

# EVTX Event IDs that represent process creation, used to look for
# corroborating evidence of a Prefetch-recorded execution.
_DEFAULT_PROCESS_CREATION_EVENT_IDS = frozenset({4688, 1})  # Security 4688, Sysmon 1

# Corroboration-strength score for this rule's findings: absence-based
# (no matching EVTX event found), which is a weaker signal than a
# positive tamper indicator -- see the rule's own docstring.
_SCORE = 45


class PrefetchExecutionWithoutEvtxRule(CorrelationRule):  # pylint: disable=too-few-public-methods
    """Flags Prefetch-recorded executions with no corresponding EVTX event.

    For each Prefetch run timestamp, this rule looks for an EVTX
    process-creation event (by default, Event ID 4688 or Sysmon Event
    ID 1) within a configurable time window whose message text
    references the executable's name. If none is found, the
    execution is flagged: it may indicate the corresponding EVTX
    record was cleared, wiped, or never logged (e.g. auditing was
    disabled), or that a legitimate execution simply predates the
    available Security log data.

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
        process_creation_event_ids: frozenset[int] = _DEFAULT_PROCESS_CREATION_EVENT_IDS,
    ) -> None:
        """Initialize the rule.

        Args:
            time_window: How far before/after a Prefetch run
                timestamp to search for a matching EVTX event.
            process_creation_event_ids: The set of EVTX Event IDs
                considered process-creation evidence.
        """
        self._time_window = time_window
        self._process_creation_event_ids = process_creation_event_ids

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
            if entry.record.event_id in self._process_creation_event_ids
            and entry.record.timestamp is not None
        ]

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
                            f"{self._time_window}."
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
