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
        detail: A human-readable pointer to the match (a source path,
            registry key, or record reference), or a fixed
            not-found message.
    """

    artifact_type: str
    found: bool
    detail: str


@dataclass(frozen=True, slots=True)
class AppCorroboration:
    """One application's corroboration summary across all artifact types.

    Attributes:
        application: The application's filename, lowercased.
        presence: Exactly one :class:`ArtifactPresence` per entry in
            :data:`_ARTIFACT_TYPE_LABELS`, in that order.
        score: 0-100, the percentage of artifact types with
            ``found=True``.
        assessment: A short, human-readable summary of ``score``.
    """

    application: str
    presence: tuple[ArtifactPresence, ...]
    score: int
    assessment: str


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


def _assess(score: int) -> str:
    """Return a short human-readable summary for a corroboration score.

    Thresholds match the two labeled examples in this feature's
    original design mockup: a 75% score ("3 of 4 artifacts") reads as
    "Supported by multiple artifacts," and a 25% score ("1 of 4")
    reads as "Artifact inconsistency detected."

    Args:
        score: A 0-100 corroboration score.

    Returns:
        A one-sentence assessment.
    """
    if score >= 75:
        return "Supported by multiple artifacts."
    if score >= 50:
        return "Partially corroborated -- some artifacts missing."
    return "Artifact inconsistency detected."


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
    """Cross-reference every candidate application against all four artifact types.

    Args:
        context: The parsed artifacts to analyze.

    Returns:
        One :class:`AppCorroboration` per candidate application found
        in Prefetch or MFT, sorted by application name.
    """
    results: list[AppCorroboration] = []
    for application in sorted(_candidate_applications(context)):
        presence = (
            _check_prefetch(application, context),
            _check_registry(application, context),
            _check_evtx(application, context),
            _check_mft(application, context),
        )
        found_count = sum(1 for p in presence if p.found)
        score = round(found_count / len(_ARTIFACT_TYPE_LABELS) * 100)
        results.append(
            AppCorroboration(
                application=application,
                presence=presence,
                score=score,
                assessment=_assess(score),
            )
        )
    return results
