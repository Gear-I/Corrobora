"""Corrobora: a cross-artifact validation framework for Windows forensics.

Corrobora detects indicators of anti-forensic activity by
cross-referencing independent Windows evidence sources (EVTX,
Registry, Prefetch, MFT) rather than parsing any single artifact type
in isolation. See ``corrobora.parsers`` for the individual artifact
parsers and the correlation engine.
"""