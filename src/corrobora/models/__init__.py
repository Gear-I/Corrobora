"""Artifact-agnostic data models shared across Corrobora's layers.

Parsers produce artifact-specific native records (``EventRecord``,
``PrefetchRecord``, ``RegistryValue``, ...). The models in this package
describe what those records *mean* as evidence, so correlation logic can
compare evidence from different artifact types without knowing any
artifact's internal format.
"""
