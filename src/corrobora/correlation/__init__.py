"""Evidence-based cross-artifact correlation.

Correlation here operates only on
:class:`~corrobora.models.evidence.EvidenceRecord` objects produced by
:mod:`corrobora.extractors`; it never inspects Prefetch, EVTX, or registry
structures directly.

This layer sits alongside the older :mod:`corrobora.rules` package, whose
rules work on each parser's native records and report anti-forensic
indicators. Findings here instead report whether independent sources
*corroborate* one another, and deliberately never infer deletion or
tampering from a missing source.
"""
