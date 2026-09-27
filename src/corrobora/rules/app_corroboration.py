"""Per-application cross-artifact corroboration.

This is a different kind of analysis than :mod:`corrobora.rules`'s
``CorrelationRule`` subclasses: instead of flagging a specific
disagreement between artifacts, it answers a broader question for
each application detected in the evidence -- "how many independent
artifact sources actually corroborate this program's presence?"

The "universe" of applications considered is seeded from Prefetch and
MFT, the only two artifact types that name a specific executable as a
clean, structured field (Prefetch's ``executable_name``, MFT's
``filename``); Registry and EVTX are then searched for each
candidate's presence via case-insensitive substring matching, since
those artifacts only carry it inside free-text value data / event
messages, not a dedicated field.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .base import CorrelationContext

# Fixed, ordered set of artifact types every AppCorroboration reports
# presence for -- the four Corrobora actually parses today.
_ARTIFACT_TYPE_LABELS: tuple[str, ...] = ("Prefetch", "Registry", "Event Log", "MFT")

# Reiterates this project's founding principle: an absent artifact is
# investigative signal, not proof of anti-forensic activity. Surfaced
# directly in the GUI (not just documentation) so it's seen at the
# point an examiner is looking at a low score.
DISCLAIMER = (
    "A missing artifact does not automatically indicate anti-forensic "
    "activity -- it may reflect normal artifact retention limits, log "
    "rotation, or an incomplete evidence collection. Corrobora surfaces "
    "the inconsistency; examiner interpretation is required."
)


@dataclass(frozen=True, slots=True)
class ArtifactPresence:
    """Whether one artifact type shows any evidence of an application.

    Attributes:
        artifact_type: The artifact type's display label (one of
            :data:`_ARTIFACT_TYPE_LABELS`).
        found: Whether this artifact type shows the application.
            Always ``False`` when ``examined`` is ``False``.
        detail: A human-readable pointer to the match (a source path,
            registry key, or record reference), or a fixed
            not-found / not-examined message.
        examined: Whether any data of this artifact type was loaded.
            An unexamined type says nothing about the application and
            does not count against its score.
    """

    artifact_type: str
    found: bool
    detail: str
    examined: bool = True


@dataclass(frozen=True, slots=True)
class AppCorroboration:
    """One application's corroboration summary across all artifact types.

    Attributes:
        application: The application's filename, lowercased.
        presence: Exactly one :class:`ArtifactPresence` per entry in
            :data:`_ARTIFACT_TYPE_LABELS`, in that order.
        score: 0-100, the percentage of *examined* artifact types with
            ``found=True``. 0 when fewer than two types were examined,
            since a single source cannot corroborate anything.
        assessment: A short, human-readable summary stating how many
            examined artifact types mention the application.
        found_count: Number of artifact types with ``found=True``.
        examined_count: Number of artifact types with data loaded.
    """

    application: str
    presence: tuple[ArtifactPresence, ...]
    score: int
    assessment: str
    found_count: int
    examined_count: int


def _check_prefetch(application: str, context: CorrelationContext) -> ArtifactPresence:
    """Check Prefetch for an exact (case-insensitive) executable-name match."""
    for entry in context.prefetch_entries:
        name = entry.record.executable_name
        if name and name.lower() == application:
            return ArtifactPresence("Prefetch", True, f"Prefetch source: {entry.source_path}")
    return ArtifactPresence("Prefetch", False, "No Prefetch record for this executable.")


def _check_mft(application: str, context: CorrelationContext) -> ArtifactPresence:
    """Check the MFT for an exact (case-insensitive) filename match."""
    for entry in context.mft_entries:
        name = entry.record.filename
        if name and name.lower() == application:
            return ArtifactPresence(
                "MFT", True, f"MFT record #{entry.record.record_number} ('{name}')"
            )
    return ArtifactPresence("MFT", False, "No MFT record for this filename.")


def _check_registry(application: str, context: CorrelationContext) -> ArtifactPresence:
    """Check the registry for a substring match in any value's data."""
    for entry in context.registry_value_entries:
        if application in str(entry.value.data).lower():
            return ArtifactPresence(
                "Registry", True, f"Registry key: {entry.value.key_path}"
            )
    return ArtifactPresence(
        "Registry", False, "No registry value references this executable."
    )


def _check_evtx(application: str, context: CorrelationContext) -> ArtifactPresence:
    """Check EVTX for a substring match in any record's message."""
    for entry in context.evtx_entries:
        message = entry.record.message
        if message and application in message.lower():
            return ArtifactPresence(
                "Event Log",
                True,
                f"EVTX record #{entry.record.record_number} ({entry.source_path})",
            )
    return ArtifactPresence(
        "Event Log", False, "No EVTX event message references this executable."
    )


def _assess(score: int, found: int, examined: int) -> str:
    """Return a short human-readable summary of an application's corroboration.

    Score thresholds match the two labeled examples in this feature's
    original design mockup: 75% ("3 of 4") reads as supported by
    multiple artifacts, and 25% ("1 of 4") as limited corroboration.
    Every assessment states the counts, so a score computed over fewer
    examined types is never mistaken for one over all four. A low score
    describes how few sources mention the application, not a detected
    problem (see :data:`DISCLAIMER`).

    Args:
        score: The 0-100 corroboration score.
        found: Number of artifact types that mention the application.
        examined: Number of artifact types with data loaded.

    Returns:
        A one-sentence assessment.
    """
    if examined < 2:
        return (
            "Cannot be corroborated -- only one artifact type was examined."
        )
    counts = f"{found} of {examined} examined artifact types"
    if found >= 2 and score >= 75:
        return f"Supported by multiple artifacts ({counts})."
    if found >= 2:
        return f"Partially corroborated ({counts})."
    return f"Limited corroboration -- found in only {counts}."


def _candidate_applications(context: CorrelationContext) -> set[str]:
    """Collect every candidate application name from Prefetch and MFT.

    Args:
        context: The parsed artifacts to scan.

    Returns:
        Lowercased executable filenames.
    """
    candidates: set[str] = set()
    for entry in context.prefetch_entries:
        if entry.record.executable_name:
            candidates.add(entry.record.executable_name.lower())
    for entry in context.mft_entries:
        name = entry.record.filename
        if name and name.lower().endswith(".exe"):
            candidates.add(name.lower())
    return candidates


def build_app_corroboration(context: CorrelationContext) -> list[AppCorroboration]:
    """Cross-reference every candidate application against the examined artifact types.

    Artifact types with no data loaded are reported as not examined and
    excluded from the score, so an analysis without (say) an MFT does
    not count the MFT as missing for every application.

    Args:
        context: The parsed artifacts to analyze.

    Returns:
        One :class:`AppCorroboration` per candidate application found
        in Prefetch or MFT, sorted by application name.
    """
    checks: tuple[tuple[str, bool, Callable[[str, CorrelationContext], ArtifactPresence]], ...] = (
        ("Prefetch", bool(context.prefetch_entries), _check_prefetch),
        ("Registry", bool(context.registry_value_entries), _check_registry),
        ("Event Log", bool(context.evtx_entries), _check_evtx),
        ("MFT", bool(context.mft_entries), _check_mft),
    )
    examined_count = sum(1 for _, examined, _ in checks if examined)

    results: list[AppCorroboration] = []
    for application in sorted(_candidate_applications(context)):
        presence = tuple(
            check(application, context) if examined else _not_examined(label)
            for label, examined, check in checks
        )
        found_count = sum(1 for p in presence if p.found)
        if examined_count < 2:
            score = 0
        else:
            score = round(found_count / examined_count * 100)
        results.append(
            AppCorroboration(
                application=application,
                presence=presence,
                score=score,
                assessment=_assess(score, found_count, examined_count),
                found_count=found_count,
                examined_count=examined_count,
            )
        )
    return results


def _not_examined(label: str) -> ArtifactPresence:
    """Presence entry for an artifact type with no data loaded.

    "Examined" means at least one record of the type was loaded;
    :class:`CorrelationContext` does not record which files were
    provided, so a file that parsed to zero records also counts as not
    examined.
    """
    return ArtifactPresence(
        label, False, f"Not examined -- no {label} data was loaded.", examined=False
    )
