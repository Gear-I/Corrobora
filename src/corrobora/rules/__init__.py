"""Corrobora's cross-artifact correlation rules layer.

This package holds the shared rule/context data model
(:mod:`corrobora.rules.base`) and every concrete :class:`CorrelationRule`
Corrobora ships, grouped by what each rule actually checks:

- ``program_execution`` -- corroborating "did this program really run"
  across independent artifact types.
- ``persistence`` -- corroborating persistence mechanisms against
  execution evidence.
- ``integrity`` -- single-artifact tamper/anomaly checks.

:mod:`corrobora.rules.rule_registry` is the single source of truth for
which rules exist (a plain ``dict[str, type[CorrelationRule]]``,
deliberately static rather than auto-discovered) and what runs by
default.

Splitting rules out of ``corrobora.parsers.correlation_engine`` (which
now only builds contexts and orchestrates rule execution) is the first
step toward Corrobora's plugin-style architecture: a future artifact
plugin layer and GUI can group and select rules by their
:attr:`~corrobora.rules.base.CorrelationRule.category` without this
package needing to change.
"""

from .base import (
    CorrelationContext,
    CorrelationFinding,
    CorrelationRule,
    EvtxEntry,
    MftEntry,
    PrefetchEntry,
    RegistryValueEntry,
    Severity,
    SEVERITY_ORDER,
)
from .rule_registry import DEFAULT_RULES, RULE_REGISTRY

__all__ = [
    "CorrelationContext",
    "CorrelationFinding",
    "CorrelationRule",
    "DEFAULT_RULES",
    "EvtxEntry",
    "MftEntry",
    "PrefetchEntry",
    "RULE_REGISTRY",
    "RegistryValueEntry",
    "SEVERITY_ORDER",
    "Severity",
]
