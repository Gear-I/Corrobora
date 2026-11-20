"""Chronoscope parser plugin: Corrobora's Prefetch and Registry parsers.

`Chronoscope <https://github.com/Gear-I/Chronoscope>`_ builds one
sorted, de-duplicated UTC timeline from many artifact sources and loads
third-party parsers from the ``chronoscope.parsers`` entry-point group.
This module registers two of them (see ``pyproject.toml``), so that
after installing Corrobora alongside Chronoscope::

    chronoscope ingest ./case C:\\triage\\WS01 --label WS01

also puts Prefetch run times, registry key LastWrite times, and BAM/DAM
execution times on the timeline. The parsing is Corrobora's own
(:class:`~corrobora.parsers.prefetch.PrefetchParser`,
:class:`~corrobora.parsers.registry.RegistryHiveParser`, and the
evidence extractors); this module only maps their output to Chronoscope
events. Chronoscope is needed only to load the plugin, never by
Corrobora itself.

Events produced:

- **prefetch**: one event per recorded run time (``Last Run Time`` for
  the most recent, ``Previous Run Time`` for the others), and one
  ``Volume Creation Time`` per volume the file references.
- **registry**: one ``Key Last Written`` event per key, with the key's
  values (rendered, and capped per key) as attributes, plus one
  ``Last Execution (BAM)`` or ``Last Execution (DAM)`` event per
  executable entry in a SYSTEM hive's Background/Desktop Activity
  Moderator keys. What each timestamp records is stated in the event's
  ``timestamp_semantics`` attribute, using Corrobora's
  :class:`~corrobora.models.evidence.TimestampSemantics` values: a BAM
  time marks process *exit*, not start.

Limitations:
    Registry transaction logs (``.LOG1``/``.LOG2``) are not applied, as
    in the rest of Corrobora. A hive whose base block shows unflushed
    changes is parsed as it is on disk, with a warning, so recent keys
    may be missing or show older LastWrite times.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from chronoscope.event import TimelineEvent
from chronoscope.parsers.base import ParseContext, Parser

from corrobora.extractors.prefetch import extract_prefetch_evidence
from corrobora.extractors.registry import extract_registry_evidence
from corrobora.models.evidence import EvidenceRecord
from corrobora.parsers.prefetch import PrefetchParser, PrefetchRecord
from corrobora.parsers.registry import RegistryHiveParser, RegistryKey, RegistryValue

# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

_PREFETCH_SUFFIX = ".pf"
_SCCA_SIGNATURE = b"SCCA"  # at offset 4 of an uncompressed Prefetch file
_MAM_SIGNATURE = b"MAM\x04"  # at offset 0 of a Windows 10+ compressed one
_REGF_SIGNATURE = b"regf"
# Transaction logs start with a regf base block too, but are not hives.
_HIVE_LOG_SUFFIXES = (".log", ".log1", ".log2")
_REGF_SEQUENCES = struct.Struct("<4sII")

# --------------------------------------------------------------------------
# Value rendering limits (keep a hive's events a manageable size)
# --------------------------------------------------------------------------

_MAX_VALUES_PER_KEY = 64
_MAX_TEXT_CHARS = 512
_MAX_BINARY_BYTES = 64


def _is_prefetch_head(head: bytes) -> bool:
    return head[4:8] == _SCCA_SIGNATURE or head[:4] == _MAM_SIGNATURE


def _read_head(path: Path, size: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


# --------------------------------------------------------------------------
# Prefetch
# --------------------------------------------------------------------------


class PrefetchTimelineParser(Parser):
    """Chronoscope parser for Windows Prefetch (``.pf``) files."""

    name = "prefetch"
    description = "Windows Prefetch (.pf): run times and volumes (via Corrobora)"

    def can_parse(self, path: Path) -> bool:
        if path.suffix.lower() != _PREFETCH_SUFFIX:
            return False
        try:
            return _is_prefetch_head(_read_head(path, 8))
        except OSError:
            return False

    def can_parse_head(self, name: str, head: bytes) -> bool:
        return name.lower().endswith(_PREFETCH_SUFFIX) and _is_prefetch_head(head)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        parser = PrefetchParser(path)
        record = parser.parse()
        for failure in parser.get_common_failures():
            ctx.warn(f"{failure.identifier}: {failure.reason}")

        evidence = [e for e in extract_prefetch_evidence(record) if e.timestamp is not None]
        if not evidence:
            ctx.warn("no run times recorded")
        executable = record.executable_name or "unknown executable"
        for item in evidence:
            run_index = item.metadata["run_index"]
            yield TimelineEvent(
                timestamp=item.timestamp,
                timestamp_desc="Last Run Time" if run_index == 0 else "Previous Run Time",
                source="PREFETCH",
                artifact=self.name,
                message=_prefetch_message(executable, record),
                path=ctx.relpath,
                attributes={
                    "executable": record.executable_name,
                    "timestamp_semantics": item.timestamp_semantics.value,
                    **_json_safe(item.metadata),
                },
            )
        yield from self._volume_events(record, executable, ctx)

    def _volume_events(
        self, record: PrefetchRecord, executable: str, ctx: ParseContext
    ) -> Iterator[TimelineEvent]:
        for volume in record.volumes:
            if volume.creation_time is None:
                continue
            yield TimelineEvent(
                timestamp=volume.creation_time,
                timestamp_desc="Volume Creation Time",
                source="PREFETCH",
                artifact=self.name,
                message=(
                    f"Volume {volume.device_path or '?'} "
                    f"(serial {volume.serial_number or '?'}) referenced by {executable}"
                ),
                path=ctx.relpath,
                attributes={
                    "executable": record.executable_name,
                    "device_path": volume.device_path,
                    "serial_number": volume.serial_number,
                },
            )


def _prefetch_message(executable: str, record: PrefetchRecord) -> str:
    count = record.run_count if record.run_count is not None else "?"
    message = f"{executable} run (count {count})"
    if record.filename_hash_matches is False:
        message += "; file name hash does not match the embedded hash"
    return message


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


class RegistryTimelineParser(Parser):
    """Chronoscope parser for registry hives (SYSTEM, SOFTWARE, NTUSER.DAT, ...)."""

    name = "registry"
    description = "Registry hives: key LastWrite times and BAM/DAM execution (via Corrobora)"

    def can_parse(self, path: Path) -> bool:
        if path.name.lower().endswith(_HIVE_LOG_SUFFIXES):
            return False
        try:
            return _read_head(path, 4) == _REGF_SIGNATURE
        except OSError:
            return False

    def can_parse_head(self, name: str, head: bytes) -> bool:
        return head[:4] == _REGF_SIGNATURE and not name.lower().endswith(_HIVE_LOG_SUFFIXES)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[TimelineEvent]:
        _warn_if_dirty(path, ctx)
        parser = RegistryHiveParser(path)
        keys, values = parser.parse()
        for failure in parser.get_common_failures():
            ctx.warn(f"{failure.identifier or 'hive'}: {failure.reason}")

        values_by_key: dict[str, list[RegistryValue]] = {}
        for value in values:
            values_by_key.setdefault(value.key_path, []).append(value)

        for key in keys:
            if key.last_written is not None:
                yield self._key_event(key, values_by_key.get(key.path, []), ctx)
        for value in values:
            for item in extract_registry_evidence(value, str(path)):
                if item.timestamp is not None:
                    yield self._execution_event(item, ctx)

    def _key_event(
        self, key: RegistryKey, values: list[RegistryValue], ctx: ParseContext
    ) -> TimelineEvent:
        key_path = _without_root(key.path)
        attributes: dict[str, Any] = {
            "key_path": key_path,
            "root_key": key.path.split("\\", 1)[0],
            "subkey_count": key.subkey_count,
            "value_count": key.value_count,
            "timestamp_semantics": "registry_key_last_write",
        }
        if values:
            shown = values[:_MAX_VALUES_PER_KEY]
            attributes["values"] = {
                (value.name or "(default)"): _render_value(value) for value in shown
            }
            if len(values) > len(shown):
                attributes["values_truncated"] = True
        return TimelineEvent(
            timestamp=key.last_written,
            timestamp_desc="Key Last Written",
            source="REG",
            artifact=self.name,
            message=key_path or "(root key)",
            path=ctx.relpath,
            attributes=attributes,
        )

    def _execution_event(self, item: EvidenceRecord, ctx: ParseContext) -> TimelineEvent:
        moderator = str(item.metadata["moderator"]).upper()
        metadata = dict(item.metadata)
        metadata["key_path"] = _without_root(str(metadata["key_path"]))
        return TimelineEvent(
            timestamp=item.timestamp,
            timestamp_desc=f"Last Execution ({moderator})",
            source="REG",
            artifact=self.name,
            message=f"{item.subject_raw} (user {metadata['user_sid']})",
            path=ctx.relpath,
            attributes={
                "executable": item.subject,
                "executable_path": item.subject_raw,
                "timestamp_semantics": item.timestamp_semantics.value,
                **_json_safe(metadata),
            },
        )


def _warn_if_dirty(path: Path, ctx: ParseContext) -> None:
    """Warn when the base block's sequence numbers differ (unflushed changes)."""
    head = _read_head(path, _REGF_SEQUENCES.size)
    if len(head) < _REGF_SEQUENCES.size:
        return
    _, primary, secondary = _REGF_SEQUENCES.unpack(head)
    if primary != secondary:
        ctx.warn(
            "hive has unflushed changes (base block sequence numbers differ); its "
            ".LOG1/.LOG2 transaction logs are not applied, so recent keys may be missing "
            "or show older LastWrite times"
        )


def _without_root(key_path: str) -> str:
    """Drop the hive's root key name, which varies between hives and tools."""
    return key_path.split("\\", 1)[1] if "\\" in key_path else ""


def _render_value(value: RegistryValue) -> Any:
    """A registry value's data as a JSON-safe, size-capped value."""
    data = value.data
    if isinstance(data, bool | int | float):
        return data
    if isinstance(data, str):
        return _cap_text(data)
    if isinstance(data, list | tuple):
        # REG_MULTI_SZ: python-registry keeps the empty strings of the terminator.
        items = list(data)
        while items and items[-1] == "":
            items.pop()
        return [_cap_text(str(item)) for item in items[:_MAX_VALUES_PER_KEY]]
    raw = value.raw_data_bytes
    rendered = raw[:_MAX_BINARY_BYTES].hex()
    if len(raw) > _MAX_BINARY_BYTES:
        rendered += f"... ({len(raw)} bytes)"
    return rendered


def _cap_text(text: str) -> str:
    text = text.replace("\x00", "")
    if len(text) > _MAX_TEXT_CHARS:
        return text[:_MAX_TEXT_CHARS] + f"... ({len(text)} chars)"
    return text


def _json_safe(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Corrobora metadata (tuples, nested mappings) as plain JSON types."""

    def convert(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {str(k): convert(v) for k, v in item.items()}
        if isinstance(item, list | tuple):
            return [convert(v) for v in item]
        if item is None or isinstance(item, bool | int | float | str):
            return item
        return str(item)

    return {str(k): convert(v) for k, v in metadata.items()}
