"""EVTX evidence extractor.

Turns a parsed :class:`~corrobora.parsers.evtx.EventRecord` into
:class:`~corrobora.models.evidence.EvidenceRecord` objects describing
program execution, from process-creation events:

- Security Event ID 4688 (``Microsoft-Windows-Security-Auditing``),
  subject taken from ``NewProcessName``.
- Sysmon Event ID 1 (``Microsoft-Windows-Sysmon``), subject taken from
  ``Image``.

An event is matched on *both* its Event ID and its provider. Event IDs
are only unique within a provider: Event ID 1 is used by many providers
unrelated to process creation, so matching on the ID alone would turn
unrelated events into execution evidence.

The EVTX parser's ``message`` field concatenates EventData values
without their names, so the process image cannot be identified reliably
from it. This extractor instead reads the named ``<Data Name="...">``
elements from the record's retained ``raw_xml``. Only records that pass
the Event ID and provider filter are re-parsed.

The evidence timestamp is the record's ``TimeCreated``
(:attr:`~corrobora.models.evidence.TimestampSemantics.EVTX_TIME_CREATED`).
Sysmon's own ``UtcTime`` field is preserved in ``metadata`` but not used
as the timestamp, so every EVTX record's timestamp means the same thing.
"""

from __future__ import annotations

import logging
from xml.etree import ElementTree

from corrobora.models.evidence import (
    EvidenceRecord,
    EvidenceType,
    TimestampSemantics,
    normalize_executable_name,
)
from corrobora.parsers.Base import ArtifactType
from corrobora.parsers.evtx import EventRecord

logger = logging.getLogger(__name__)

_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

SECURITY_AUDITING_PROVIDER = "Microsoft-Windows-Security-Auditing"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"

# (provider, event ID) -> name of the EventData field holding the new
# process's image path.
_PROCESS_CREATION_IMAGE_FIELDS: dict[tuple[str, int], str] = {
    (SECURITY_AUDITING_PROVIDER, 4688): "NewProcessName",
    (SYSMON_PROVIDER, 1): "Image",
}

# (provider, event ID) -> {metadata key: EventData field name}, for the
# fields worth surfacing directly. The full EventData is always kept
# under ``metadata["event_data"]`` as well.
_METADATA_FIELDS: dict[tuple[str, int], dict[str, str]] = {
    (SECURITY_AUDITING_PROVIDER, 4688): {
        "process_id": "NewProcessId",
        "parent_process_id": "ProcessId",
        "parent_image": "ParentProcessName",
        "command_line": "CommandLine",
        "user": "SubjectUserName",
        "user_domain": "SubjectDomainName",
        "logon_id": "SubjectLogonId",
    },
    (SYSMON_PROVIDER, 1): {
        "process_id": "ProcessId",
        "parent_process_id": "ParentProcessId",
        "parent_image": "ParentImage",
        "command_line": "CommandLine",
        "user": "User",
        "logon_id": "LogonId",
        "process_guid": "ProcessGuid",
        "sysmon_utc_time": "UtcTime",
        "hashes": "Hashes",
        "original_file_name": "OriginalFileName",
    },
}


def extract_evtx_evidence(record: EventRecord, source_path: str) -> list[EvidenceRecord]:
    """Extract program-execution evidence from one EVTX event record.

    Args:
        record: A record produced by
            :meth:`~corrobora.parsers.evtx.EvtxParser.parse`.
        source_path: The ``.evtx`` file the record was parsed from.
            ``EventRecord`` does not carry its own source path.

    Returns:
        A single-element list for a process-creation event with a usable
        image path; otherwise an empty list (a different event, a
        different provider, unparseable XML, or no image field).
    """
    if record.event_id is None or record.provider_name is None:
        return []
    key = (record.provider_name, record.event_id)
    image_field = _PROCESS_CREATION_IMAGE_FIELDS.get(key)
    if image_field is None:
        return []

    event_data = _parse_event_data(record)
    image = event_data.get(image_field)
    if not image:
        return []
    subject = normalize_executable_name(image)
    if not subject:
        return []

    metadata: dict[str, object] = {
        "event_id": record.event_id,
        "provider_name": record.provider_name,
        "channel": record.channel,
        "computer_name": record.computer_name,
        "record_number": record.record_number,
    }
    for metadata_key, field_name in _METADATA_FIELDS[key].items():
        metadata[metadata_key] = event_data.get(field_name)
    metadata["event_data"] = event_data

    return [
        EvidenceRecord(
            artifact_type=ArtifactType.EVTX,
            evidence_type=EvidenceType.PROGRAM_EXECUTION,
            subject=subject,
            subject_raw=image,
            timestamp=record.timestamp,
            timestamp_semantics=TimestampSemantics.EVTX_TIME_CREATED,
            source_path=source_path,
            record_ref=f"record[{record.record_number}]",
            metadata=metadata,
        )
    ]


def _parse_event_data(record: EventRecord) -> dict[str, str]:
    """Read the named ``EventData`` fields from a record's raw XML.

    Args:
        record: The event record whose ``raw_xml`` to read.

    Returns:
        A mapping of each ``<Data Name="...">`` element's name to its
        stripped text (an empty string when the element has no text).
        Unnamed ``<Data>`` elements are skipped. An empty mapping if the
        XML cannot be parsed or has no ``EventData``.
    """
    try:
        root = ElementTree.fromstring(record.raw_xml)
    except ElementTree.ParseError as exc:
        logger.debug("Could not parse raw XML of record %d: %s", record.record_number, exc)
        return {}
    event_data = root.find(f"{_EVENT_NS}EventData")
    if event_data is None:
        return {}
    fields: dict[str, str] = {}
    for data in event_data.findall(f"{_EVENT_NS}Data"):
        name = data.get("Name")
        if name:
            fields[name] = (data.text or "").strip()
    return fields
