"""Evidence extractors: interpret native parser records as evidence.

Each module here takes one parser's native, artifact-specific records
(e.g. :class:`~corrobora.parsers.prefetch.PrefetchRecord`) and decides
which of them constitute evidence of something, producing
:class:`~corrobora.models.evidence.EvidenceRecord` objects. Parsers stay
generic and format-focused; the artifact-specific knowledge of what a
record *means* lives here.
"""
