"""Build Corrobora's synthetic reference case, deterministically.

Writes a small Windows case (Prefetch files, a Security event log, and a
SYSTEM registry hive) in the real binary formats, containing only made-up
data, then zips it. Every byte is derived from the scenario below, so
anyone running this script with the same Python major version gets the
same zip, byte for byte, and can check it against the published SHA-256.

Usage:
    python scripts/build_reference_case.py [OUTPUT_DIR]

Writes ``OUTPUT_DIR/corrobora-reference-case-1.zip`` (default: the
current directory) and prints its SHA-256.

The formats written:

- **Prefetch** version 26 (Windows 8.1 layout), uncompressed, with eight
  run-time slots.
- **EVTX** version 3.1: one chunk; each record carries its own BinXML
  template with literal values (no substitutions). Header and chunk CRC32
  checksums are correct.
- **Registry hive** (regf 1.5): only the keys Corrobora reads, ``Select``
  and ``ControlSet001\\Services\\bam\\State\\UserSettings\\<SID>``.

These are minimal, valid instances of each format, sufficient for the
parsers Corrobora uses (libscca, python-evtx, python-registry). They are
not full reproductions of what Windows writes. The scenario is fictional:
the computer, account, SID, and times are invented.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import io
import struct
import sys
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

CASE_NAME = "corrobora-reference-case-1"

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
# Fixed timestamp for zip entries, so the archive bytes never depend on
# when the script runs.
_ZIP_DATE_TIME = (2026, 9, 27, 0, 0, 0)


def filetime(moment: datetime) -> int:
    """Convert a UTC datetime to a Windows FILETIME (100 ns ticks since 1601)."""
    delta = moment - _FILETIME_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def utf16(text: str) -> bytes:
    """UTF-16LE encoding, as used throughout Windows artifact formats."""
    return text.encode("utf-16-le")


# ==========================================================================
# EVTX
# ==========================================================================

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

_EVTX_FILE_HEADER_SIZE = 0x1000
_EVTX_CHUNK_SIZE = 0x10000
_EVTX_CHUNK_HEADER_SIZE = 0x200


@dataclass(frozen=True)
class XmlElement:
    """A minimal XML element for BinXML encoding: attributes, then text or children."""

    name: str
    attributes: tuple[tuple[str, str], ...] = ()
    text: str | None = None
    children: tuple[XmlElement, ...] = ()


class _BinXmlWriter:  # pylint: disable=too-few-public-methods
    """Encodes XmlElement trees as BinXML at a known chunk offset.

    Element and attribute names are written inline (each name is defined
    where it is first used, as allowed by the format), so no chunk string
    table is needed.
    """

    def __init__(self, chunk_offset: int) -> None:
        self.data = bytearray()
        self._chunk_offset = chunk_offset

    def _position(self) -> int:
        return self._chunk_offset + len(self.data)

    def _write_name(self, name: str) -> None:
        encoded = utf16(name)
        # next string offset, hash (unused by parsers), length, string, NUL
        self.data += struct.pack("<IHH", 0, 0, len(name)) + encoded + b"\x00\x00"

    def _write_value(self, text: str) -> None:
        # value token, type 0x01 (UTF-16 string), length in characters, chars
        self.data += struct.pack("<BBH", 0x05, 0x01, len(text)) + utf16(text)

    def element(self, element: XmlElement) -> None:
        """Append one element (and its subtree)."""
        has_attributes = bool(element.attributes)
        token = 0x41 if has_attributes else 0x01
        start = len(self.data)
        # token, dependency id, data size (patched below), name offset
        self.data += struct.pack("<BHII", token, 0xFFFF, 0, 0)
        name_offset = self._position()
        struct.pack_into("<I", self.data, start + 7, name_offset)
        self._write_name(element.name)
        if has_attributes:
            attr_size_pos = len(self.data)
            self.data += struct.pack("<I", 0)
            attrs_start = len(self.data)
            for index, (attr_name, attr_value) in enumerate(element.attributes):
                more = index < len(element.attributes) - 1
                self.data += struct.pack("<B", 0x46 if more else 0x06)
                self.data += struct.pack("<I", self._position() + 4)
                self._write_name(attr_name)
                self._write_value(attr_value)
            struct.pack_into("<I", self.data, attr_size_pos, len(self.data) - attrs_start)
        if element.text is None and not element.children:
            self.data += b"\x03"  # close empty element
        else:
            self.data += b"\x02"  # close start element
            if element.text is not None:
                self._write_value(element.text)
            for child in element.children:
                self.element(child)
            self.data += b"\x04"  # end element
        struct.pack_into("<I", self.data, start + 3, len(self.data) - start - 7)


def _event_record(chunk_offset: int, record_id: int, written: datetime, event: XmlElement) -> bytes:
    """One EVTX record whose BinXML carries a resident template with literal values."""
    record_header = 0x18
    root_start = chunk_offset + record_header
    # Template instance (10 bytes) follows the 4-byte stream start; the
    # resident template definition follows the instance.
    template_offset = root_start + 4 + 10
    body = _BinXmlWriter(template_offset + 24)
    body.data += bytes([0x0F, 0x01, 0x01, 0x00])  # fragment header
    body.element(event)
    body.data += b"\x00"  # end of stream

    guid = hashlib.md5(f"corrobora-template-{record_id}".encode()).digest()
    template = struct.pack("<I", 0) + guid + struct.pack("<I", len(body.data)) + bytes(body.data)
    template_id = struct.unpack_from("<I", guid)[0]
    binxml = (
        bytes([0x0F, 0x01, 0x01, 0x00])
        + struct.pack("<BBII", 0x0C, 0x01, template_id, template_offset)
        + template
        + struct.pack("<I", 0)  # no substitutions
    )
    size = record_header + len(binxml) + 4
    size += (-size) % 8
    record = bytearray(size)
    struct.pack_into("<IIQQ", record, 0, 0x00002A2A, size, record_id, filetime(written))
    record[record_header : record_header + len(binxml)] = binxml
    struct.pack_into("<I", record, size - 4, size)
    return bytes(record)


def build_evtx(events: list[tuple[datetime, XmlElement]], first_record_id: int = 1) -> bytes:
    """Build a one-chunk EVTX file containing ``events`` (``(written, event)``)."""
    chunk = bytearray(_EVTX_CHUNK_SIZE)
    offset = _EVTX_CHUNK_HEADER_SIZE
    last_record_offset = offset
    last_id = first_record_id + len(events) - 1
    for index, (written, event) in enumerate(events):
        record = _event_record(offset, first_record_id + index, written, event)
        if offset + len(record) > _EVTX_CHUNK_SIZE:
            raise ValueError("reference case events do not fit in one EVTX chunk")
        chunk[offset : offset + len(record)] = record
        last_record_offset = offset
        offset += len(record)

    struct.pack_into(
        "<8sQQQQIII",
        chunk,
        0,
        b"ElfChnk\x00",
        first_record_id,
        last_id,
        first_record_id,
        last_id,
        0x80,
        last_record_offset,
        offset,
    )
    struct.pack_into("<I", chunk, 0x34, binascii.crc32(chunk[0x200:offset]) & 0xFFFFFFFF)
    header_crc = binascii.crc32(bytes(chunk[0:0x78]) + bytes(chunk[0x80:0x200])) & 0xFFFFFFFF
    struct.pack_into("<I", chunk, 0x7C, header_crc)

    header = bytearray(_EVTX_FILE_HEADER_SIZE)
    struct.pack_into(
        "<8sQQQIHHHH", header, 0, b"ElfFile\x00", 0, 0, last_id + 1, 0x80, 1, 3, 0x1000, 1
    )
    struct.pack_into("<I", header, 0x7C, binascii.crc32(bytes(header[0:0x78])) & 0xFFFFFFFF)
    return bytes(header) + bytes(chunk)


def security_4688_event(  # pylint: disable=too-many-arguments
    *,
    record_id: int,
    written: datetime,
    computer: str,
    user: str,
    domain: str,
    sid: str,
    image: str,
    command_line: str,
    parent_image: str,
    new_pid: int,
    parent_pid: int,
) -> XmlElement:
    """A Security 4688 (process creation) event with typical fields."""
    stamp = written.strftime("%Y-%m-%dT%H:%M:%S.") + f"{written.microsecond:06d}0Z"
    system = XmlElement(
        "System",
        children=(
            XmlElement(
                "Provider",
                attributes=(
                    ("Name", "Microsoft-Windows-Security-Auditing"),
                    ("Guid", "{54849625-5478-4994-a5ba-3e3b0328c30d}"),
                ),
            ),
            XmlElement("EventID", text="4688"),
            XmlElement("Version", text="2"),
            XmlElement("Level", text="0"),
            XmlElement("Task", text="13312"),
            XmlElement("Opcode", text="0"),
            XmlElement("Keywords", text="0x8020000000000000"),
            XmlElement("TimeCreated", attributes=(("SystemTime", stamp),)),
            XmlElement("EventRecordID", text=str(record_id)),
            XmlElement("Correlation"),
            XmlElement("Execution", attributes=(("ProcessID", "4"), ("ThreadID", "212"))),
            XmlElement("Channel", text="Security"),
            XmlElement("Computer", text=computer),
            XmlElement("Security"),
        ),
    )
    fields = (
        ("SubjectUserSid", sid),
        ("SubjectUserName", user),
        ("SubjectDomainName", domain),
        ("SubjectLogonId", "0x3e7a1"),
        ("NewProcessId", hex(new_pid)),
        ("NewProcessName", image),
        ("TokenElevationType", "%%1938"),
        ("ProcessId", hex(parent_pid)),
        ("CommandLine", command_line),
        ("TargetUserSid", "S-1-0-0"),
        ("TargetUserName", "-"),
        ("TargetDomainName", "-"),
        ("TargetLogonId", "0x0"),
        ("ParentProcessName", parent_image),
        ("MandatoryLabel", "S-1-16-8192"),
    )
    event_data = XmlElement(
        "EventData",
        children=tuple(
            XmlElement("Data", attributes=(("Name", name),), text=value) for name, value in fields
        ),
    )
    return XmlElement("Event", attributes=(("xmlns", EVENT_NS),), children=(system, event_data))


# ==========================================================================
# Prefetch
# ==========================================================================

_PF_VERSION = 26
_PF_HEADER_SIZE = 84
_PF_FILE_INFO_SIZE = 224
_PF_METRICS_ENTRY_SIZE = 32
_PF_VOLUME_ENTRY_SIZE = 104


def build_prefetch(  # pylint: disable=too-many-arguments,too-many-locals
    *,
    executable: str,
    prefetch_hash: int,
    run_times: list[datetime],
    run_count: int,
    referenced_files: list[str],
    volume_device_path: str,
    volume_serial: int,
    volume_created: datetime,
) -> bytes:
    """Build an uncompressed version 26 Prefetch file.

    Args:
        executable: The executable name as Prefetch stores it (upper case,
            at most 29 characters).
        prefetch_hash: The 32-bit Prefetch hash, also used in the file name.
        run_times: Up to eight run times; stored most recent first.
        run_count: The total run count.
        referenced_files: Device paths of files loaded at startup.
        volume_device_path: The volume's device path.
        volume_serial: The volume serial number.
        volume_created: The volume creation time.
    """
    if len(executable) > 29 or len(run_times) > 8:
        raise ValueError("executable name over 29 characters or more than 8 run times")

    metrics_offset = _PF_HEADER_SIZE + _PF_FILE_INFO_SIZE
    metrics = bytearray()
    traces = bytearray()
    strings = bytearray()
    for index, name in enumerate(referenced_files):
        # start trace chain index, trace chain count, prefetched blocks,
        # filename string offset (bytes), filename length (chars), flags,
        # file reference
        metrics += struct.pack("<IIIIIIQ", index, 1, 1, len(strings), len(name), 0x0200, 0)
        # One trace chain per file: next index (0xFFFFFFFF = end), block
        # load count, then flags.
        traces += struct.pack("<IIBBH", 0xFFFFFFFF, 1, 0x02, 0x01, 0xFFFF)
        strings += utf16(name) + b"\x00\x00"
    trace_offset = metrics_offset + len(metrics)
    strings_offset = trace_offset + len(traces)
    strings_size = len(strings)
    volumes_offset = strings_offset + strings_size
    volumes_offset += (-volumes_offset) % 8

    device = utf16(volume_device_path) + b"\x00\x00"
    volume_entry = bytearray(_PF_VOLUME_ENTRY_SIZE)
    struct.pack_into(
        "<IIQIIIII",
        volume_entry,
        0,
        _PF_VOLUME_ENTRY_SIZE,  # device path follows the entry
        len(volume_device_path),
        filetime(volume_created),
        volume_serial,
        0,  # file references offset
        0,  # file references size
        0,  # directory strings offset
        0,  # number of directory strings
    )
    volumes = bytes(volume_entry) + device
    total_size = volumes_offset + len(volumes)
    total_size += (-total_size) % 8

    data = bytearray(total_size)
    struct.pack_into("<I4sII", data, 0, _PF_VERSION, b"SCCA", 0x11, total_size)
    name_field = utf16(executable)
    data[16 : 16 + len(name_field)] = name_field
    struct.pack_into("<I", data, 76, prefetch_hash)

    info = _PF_HEADER_SIZE
    struct.pack_into(
        "<IIIIIIIII",
        data,
        info,
        metrics_offset,
        len(referenced_files),
        trace_offset,
        len(referenced_files),
        strings_offset,
        strings_size,
        volumes_offset,
        1,
        len(volumes),
    )
    for index, moment in enumerate(sorted(run_times, reverse=True)):
        struct.pack_into("<Q", data, info + 44 + 8 * index, filetime(moment))
    struct.pack_into("<I", data, info + 124, run_count)

    data[metrics_offset : metrics_offset + len(metrics)] = metrics
    data[trace_offset : trace_offset + len(traces)] = traces
    data[strings_offset : strings_offset + strings_size] = strings
    data[volumes_offset : volumes_offset + len(volumes)] = volumes
    return bytes(data)


def prefetch_file_name(executable: str, prefetch_hash: int) -> str:
    """The ``NAME-HHHHHHHH.pf`` file name Windows uses."""
    return f"{executable}-{prefetch_hash:08X}.pf"


# ==========================================================================
# Registry hive
# ==========================================================================

REG_DWORD = 4
REG_BINARY = 3

_REGF_HEADER_SIZE = 0x1000
_HBIN_HEADER_SIZE = 0x20


@dataclass
class RegistryKey:
    """A key to write: its values (name, type, data) and subkeys."""

    name: str
    values: list[tuple[str, int, bytes]]
    subkeys: list[RegistryKey]


class _HiveCells:
    """Allocates registry cells in a single hive bin.

    Offsets are relative to the start of the first hbin, as the format
    requires. Cells are 8-byte aligned and marked allocated (negative size).
    """

    def __init__(self) -> None:
        self.data = bytearray()

    def allocate(self, payload_size: int) -> int:
        """Reserve a cell for ``payload_size`` bytes; return its offset."""
        size = payload_size + 4
        size += (-size) % 8
        offset = _HBIN_HEADER_SIZE + len(self.data)
        self.data += struct.pack("<i", -size) + bytes(size - 4)
        return offset

    def write(self, offset: int, payload: bytes) -> None:
        """Fill the payload of the cell at ``offset``."""
        start = offset - _HBIN_HEADER_SIZE + 4
        self.data[start : start + len(payload)] = payload

    def add(self, payload: bytes) -> int:
        """Allocate and fill a cell in one step."""
        offset = self.allocate(len(payload))
        self.write(offset, payload)
        return offset


def _write_key(  # pylint: disable=too-many-locals
    cells: _HiveCells, key: RegistryKey, parent_offset: int, written: int, is_root: bool
) -> int:
    name = key.name.encode("ascii")
    nk_offset = cells.allocate(0x4C + len(name))

    value_offsets = []
    for value_name, value_type, data in key.values:
        encoded_name = value_name.encode("ascii")
        if len(data) <= 4:
            length, data_field = 0x80000000 | len(data), data.ljust(4, b"\x00")
        else:
            length, data_field = len(data), struct.pack("<I", cells.add(data))
        vk = (
            b"vk"
            + struct.pack("<HI", len(encoded_name), length)
            + data_field
            + struct.pack("<IHH", value_type, 0x0001, 0)
            + encoded_name
        )
        value_offsets.append(cells.add(vk))
    values_list = (
        cells.add(b"".join(struct.pack("<I", o) for o in value_offsets))
        if value_offsets
        else 0xFFFFFFFF
    )

    ordered = sorted(key.subkeys, key=lambda k: k.name.upper())
    child_offsets = [_write_key(cells, sub, nk_offset, written, False) for sub in ordered]
    subkey_list = 0xFFFFFFFF
    if child_offsets:
        entries = b"".join(
            struct.pack("<I", o) + sub.name.encode("ascii")[:4].ljust(4, b"\x00")
            for o, sub in zip(child_offsets, ordered)
        )
        subkey_list = cells.add(b"lf" + struct.pack("<H", len(child_offsets)) + entries)

    flags = 0x0020 | (0x002C if is_root else 0)
    max_value_name = max((len(v[0]) * 2 for v in key.values), default=0)
    max_value_data = max((len(v[2]) for v in key.values), default=0)
    max_subkey_name = max((len(s.name) * 2 for s in key.subkeys), default=0)
    nk = (
        b"nk"
        + struct.pack("<HQI", flags, written, 0)
        + struct.pack(
            "<IIIIIIIIIIIIII",
            parent_offset,
            len(child_offsets),
            0,  # volatile subkeys
            subkey_list,
            0xFFFFFFFF,  # volatile subkey list
            len(value_offsets),
            values_list,
            0xFFFFFFFF,  # security descriptor (not needed by readers here)
            0xFFFFFFFF,  # class name
            max_subkey_name,
            0,  # largest class name
            max_value_name,
            max_value_data,
            0,  # work variable
        )
        + struct.pack("<HH", len(name), 0)
        + name
    )
    cells.write(nk_offset, nk)
    return nk_offset


def build_hive(root: RegistryKey, written: datetime, file_name: str) -> bytes:
    """Build a registry hive (regf 1.5) containing ``root`` and its subtree."""
    stamp = filetime(written)
    cells = _HiveCells()
    root_offset = _write_key(cells, root, 0, stamp, True)

    hbin_size = _HBIN_HEADER_SIZE + len(cells.data) + 8
    hbin_size += (-hbin_size) % 0x1000
    free = hbin_size - _HBIN_HEADER_SIZE - len(cells.data)
    hbin = bytearray(
        b"hbin" + struct.pack("<II", 0, hbin_size) + bytes(8) + struct.pack("<QI", stamp, 0)
    )
    hbin += cells.data + struct.pack("<i", free) + bytes(free - 4)

    header = bytearray(_REGF_HEADER_SIZE)
    struct.pack_into("<4sIIQIIIIIII", header, 0, b"regf", 1, 1, stamp, 1, 5, 0, 1, root_offset,
                     hbin_size, 1)
    name_field = utf16(file_name)[:64]
    header[0x30 : 0x30 + len(name_field)] = name_field
    checksum = 0
    for (dword,) in struct.iter_unpack("<I", bytes(header[:0x1FC])):
        checksum ^= dword
    struct.pack_into("<I", header, 0x1FC, checksum)
    return bytes(header) + bytes(hbin)


def bam_value_data(exited: datetime) -> bytes:
    """BAM value data: FILETIME of the last process exit, then 16 bytes of flags."""
    return struct.pack("<Q", filetime(exited)) + bytes(16)


# ==========================================================================
# The scenario
# ==========================================================================

COMPUTER = "DEMO-WS01"
USER = "analyst"
SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
VOLUME = r"\VOLUME{01dc1f2e3d4c5b6a-5a4b3c2d}"
DEVICE = r"\Device\HarddiskVolume3"
T0 = datetime(2026, 9, 20, 14, 0, 0, tzinfo=UTC)

# Offsets measured on a real system (see TimestampSemantics): 4688 at
# process start, Prefetch about 30 ms later, BAM about 2 ms after exit.
_PREFETCH_DELAY = timedelta(milliseconds=30)
_BAM_DELAY = timedelta(milliseconds=2)


@dataclass(frozen=True)
class Program:  # pylint: disable=too-many-instance-attributes
    """One executable in the scenario and the evidence each source holds."""

    image: str  # full Win32 path
    prefetch_hash: int
    run_count: int
    starts: tuple[datetime, ...]  # process starts, oldest first
    logged_starts: tuple[datetime, ...] = ()  # starts with a Security 4688 event
    bam_exit: datetime | None = None
    parent: str = r"C:\Windows\explorer.exe"
    arguments: str = ""

    @property
    def name(self) -> str:
        """Executable file name, as written in Prefetch (upper case)."""
        return self.image.rsplit("\\", 1)[-1].upper()


def _at(minutes: float) -> datetime:
    return T0 + timedelta(minutes=minutes)


# Auditing (4688) is "enabled" from T0 onward; earlier runs have no event.
_PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_PS_RUNS = (_at(0), _at(3), _at(6))
PROGRAMS: tuple[Program, ...] = (
    # Run three times, each open 61 s: every source agrees.
    Program(
        _PS,
        0x1A2B3C4D,
        12,
        (_at(-2880), _at(-1440), *_PS_RUNS),
        _PS_RUNS,
        _PS_RUNS[-1] + timedelta(seconds=61) + _BAM_DELAY,
        arguments=" -NoProfile",
    ),
    Program(
        r"C:\Windows\System32\certutil.exe",
        0x2B3C4D5E,
        1,
        (_at(9.2),),
        (_at(9.2),),
        _at(9.2) + timedelta(seconds=1.4) + _BAM_DELAY,
        parent=_PS,
        arguments=r" -hashfile C:\Users\analyst\Downloads\tool.zip SHA256",
    ),
    # No BAM entry for this user and program.
    Program(
        r"C:\Windows\System32\cmd.exe", 0x3C4D5E6F, 41, (_at(8),), (_at(8),), arguments=" /c dir"
    ),
    # BAM holds the exit of an earlier run: this run was still going at collection.
    Program(
        r"C:\Windows\System32\whoami.exe",
        0x4D5E6F70,
        2,
        (_at(-300), _at(9.7)),
        (_at(9.7),),
        _at(-300) + timedelta(seconds=0.4) + _BAM_DELAY,
        parent=r"C:\Windows\System32\cmd.exe",
    ),
    # Ran before auditing was enabled: Prefetch and BAM only.
    Program(
        r"C:\Windows\System32\notepad.exe",
        0x5E6F7081,
        7,
        (_at(-45),),
        (),
        _at(-45) + timedelta(minutes=12) + _BAM_DELAY,
    ),
    # The 4688 event is 45 s from the Prefetch run time: outside a 30 s window.
    Program(
        r"C:\Windows\System32\PING.EXE",
        0x6F708192,
        3,
        (_at(11),),
        (_at(11) - timedelta(seconds=45),),
        arguments=" 192.0.2.10",
    ),
    # Prefetch only.
    Program(r"C:\Windows\System32\mspaint.exe", 0x708192A3, 1, (_at(-120),)),
)


def _prefetch_files() -> dict[str, bytes]:
    files = {}
    for program in PROGRAMS:
        runs = [start + _PREFETCH_DELAY for start in program.starts][-8:]
        files[prefetch_file_name(program.name, program.prefetch_hash)] = build_prefetch(
            executable=program.name,
            prefetch_hash=program.prefetch_hash,
            run_times=runs,
            run_count=program.run_count,
            referenced_files=[
                VOLUME + r"\WINDOWS\SYSTEM32\NTDLL.DLL",
                VOLUME + r"\WINDOWS\SYSTEM32\KERNEL32.DLL",
                VOLUME + program.image[2:].upper(),
            ],
            volume_device_path=VOLUME,
            volume_serial=0x5A4B3C2D,
            volume_created=datetime(2026, 1, 5, 8, 0, tzinfo=UTC),
        )
    return files


def _security_log() -> bytes:
    starts = sorted(
        ((start, program) for program in PROGRAMS for start in program.logged_starts),
        key=lambda pair: pair[0],
    )
    first_id = 18200
    events = []
    for index, (start, program) in enumerate(starts):
        event = security_4688_event(
            record_id=first_id + index,
            written=start,
            computer=COMPUTER,
            user=USER,
            domain=COMPUTER,
            sid=SID,
            image=program.image,
            command_line=program.image.rsplit("\\", 1)[-1] + program.arguments,
            parent_image=program.parent,
            new_pid=0x1A00 + 4 * index,
            parent_pid=0x0F10,
        )
        events.append((start, event))
    return build_evtx(events, first_record_id=first_id)


def _dword(value: int) -> bytes:
    return struct.pack("<I", value)


def _system_hive() -> bytes:
    bam_values = [("Version", REG_DWORD, _dword(1)), ("SequenceNumber", REG_DWORD, _dword(17))]
    for program in PROGRAMS:
        if program.bam_exit is not None:
            bam_values.append(
                (DEVICE + program.image[2:], REG_BINARY, bam_value_data(program.bam_exit))
            )
    user_settings = RegistryKey("UserSettings", [], [RegistryKey(SID, bam_values, [])])
    bam = RegistryKey(
        "bam", [("Version", REG_DWORD, _dword(1))], [RegistryKey("State", [], [user_settings])]
    )
    select = RegistryKey(
        "Select",
        [
            ("Current", REG_DWORD, _dword(1)),
            ("Default", REG_DWORD, _dword(1)),
            ("Failed", REG_DWORD, _dword(0)),
            ("LastKnownGood", REG_DWORD, _dword(1)),
        ],
        [],
    )
    root = RegistryKey(
        "ROOT",
        [],
        [RegistryKey("ControlSet001", [], [RegistryKey("Services", [], [bam])]), select],
    )
    return build_hive(root, _at(15), "SYSTEM")


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _runs_csv() -> bytes:
    lines = ["Program,StartUtc,ExitUtc,Notes"]
    for start in _PS_RUNS:
        exit_time = start + timedelta(seconds=61)
        lines.append(f"powershell.exe,{_iso(start)},{_iso(exit_time)},synthetic ground truth")
    return ("\n".join(lines) + "\n").encode("utf-8")


_README = """Corrobora reference case 1 (synthetic)

Every file here was generated by scripts/build_reference_case.py in the
Corrobora repository. The computer (DEMO-WS01), account (analyst), SID,
programs, and times are fictional. No real system's data is included.

The files are minimal but valid instances of the real formats: Prefetch
version 26, EVTX 3.1 (Security, Event ID 4688 only), and a SYSTEM registry
hive containing only the Select and BAM keys.

runs.csv gives the ground-truth start and exit times of the three
powershell.exe runs. See docs/reproducible-testing.md for how to use this
case to verify Corrobora.
"""


def case_files() -> dict[str, bytes]:
    """Every file in the case, by path inside the case folder."""
    files = dict(_prefetch_files())
    files["Security.evtx"] = _security_log()
    files["SYSTEM"] = _system_hive()
    files["runs.csv"] = _runs_csv()
    files["README.txt"] = _README.encode("utf-8")
    return files


def build_zip(files: dict[str, bytes]) -> bytes:
    """A deterministic zip of the case folder.

    Entries are sorted, stored uncompressed (compressed bytes can differ
    between zlib builds), and given fixed timestamps and attributes.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(f"{CASE_NAME}/{name}", date_time=_ZIP_DATE_TIME)
            info.create_system = 0
            info.external_attr = 0
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, files[name])
    return buffer.getvalue()


def main(argv: list[str] | None = None) -> int:
    """Build the reference case zip and print its SHA-256."""
    parser = argparse.ArgumentParser(
        prog="build_reference_case.py",
        description="Build Corrobora's synthetic reference case, deterministically.",
    )
    parser.add_argument(
        "output_dir",
        nargs="?",
        type=Path,
        default=Path("."),
        help="Folder to write the zip into (default: current folder).",
    )
    options = parser.parse_args(argv)
    options.output_dir.mkdir(parents=True, exist_ok=True)
    data = build_zip(case_files())
    target = options.output_dir / f"{CASE_NAME}.zip"
    target.write_bytes(data)
    print(f"Wrote {target} ({len(data)} bytes)")
    print(f"SHA-256: {hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
