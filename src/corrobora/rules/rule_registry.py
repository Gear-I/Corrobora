"""Explicit static registry of every correlation rule Corrobora ships.

Deliberately a plain dict, not directory-scanning/auto-discovery: no
import-time magic, trivial to unit test, and easy to read as the
single source of truth for "what rules exist." Keyed by each rule's
own ``rule_name`` (already the identifier used in
:attr:`~corrobora.rules.base.CorrelationFinding.rule_name` and in
logs), so there is exactly one place a rule's identifier is defined.

Maps id to *class*, not instance: :class:`~corrobora.parsers.correlation_engine.CorrelationEngine`'s
default needs ready-to-use instances (:data:`DEFAULT_RULES`), but a
future GUI checkbox list needs to instantiate only the subset a user
enables -- a class registry supports both without redesigning this
file, and combined with each rule's
:attr:`~corrobora.rules.base.CorrelationRule.category` attribute, a
future GUI can group checkboxes by category too.
"""

from __future__ import annotations

from .base import CorrelationRule
from .integrity.evtx_record_gap import EvtxRecordNumberGapRule
from .integrity.mft_timestomping import MftTimestompingRule
from .integrity.prefetch_hash_mismatch import PrefetchFilenameHashMismatchRule
from .persistence.registry_vs_prefetch import RegistryPersistenceWithoutExecutionRule
from .program_execution.prefetch_vs_evtx import PrefetchExecutionWithoutEvtxRule

RULE_REGISTRY: dict[str, type[CorrelationRule]] = {
    "prefetch_execution_without_evtx": PrefetchExecutionWithoutEvtxRule,
    "persistence_without_execution": RegistryPersistenceWithoutExecutionRule,
    "prefetch_filename_hash_mismatch": PrefetchFilenameHashMismatchRule,
    "evtx_record_number_gap": EvtxRecordNumberGapRule,
    "mft_timestomping_detected": MftTimestompingRule,
}

DEFAULT_RULES: tuple[CorrelationRule, ...] = tuple(cls() for cls in RULE_REGISTRY.values())
