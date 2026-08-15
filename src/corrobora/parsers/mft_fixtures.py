"""Synthetic MFT record builders for testing.

Builds real, spec-correct NTFS MFT record bytes (including a valid
fixup/update-sequence-array) so :mod:`mft` can be tested against
byte-accurate input without needing a real ``$MFT`` file.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

_WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def datetime_to_filetime(dt: datetime) -> int:
    """Convert a UTC datetime to a Windows FILETIME integer."""
    delta = dt - _WINDOWS_EPOCH
    return int(delta / timedelta(microseconds=1)) * 10


def _build_resident_attribute(attr_type: int, content: bytes) -> bytes:
    """Build a minimal resident attribute (header + content), 8-byte aligned."""
    content_offset = 24
    total_len = content_offset + len(content)
    padding = (8 - total_len % 8) % 8
    total_len += padding

    attr = bytearray(total_len)
    attr[0:4] = attr_type.to_bytes(4, "little")
    attr[4:8] = total_len.to_bytes(4, "little")
    attr[8] = 0  # resident
    attr[16:20] = len(content).to_bytes(4, "little")
    attr[20:22] = content_offset.to_bytes(2, "little")
    attr[content_offset : content_offset + len(content)] = content
    return bytes(attr)


def _build_si_content(
    creation: datetime | None,
    modification: datetime | None,
    mft_modification: datetime | None,
    access: datetime | None,
) -> bytes:
    """Build $STANDARD_INFORMATION attribute content bytes."""

    def _ft(dt: datetime | None) -> bytes:
        return (0 if dt is None else datetime_to_filetime(dt)).to_bytes(8, "little")

    return _ft(creation) + _ft(modification) + _ft(mft_modification) + _ft(access) + b"\x00" * 24


def _build_fn_content(
    parent_record_number: int,
    creation: datetime | None,
    modification: datetime | None,
    mft_modification: datetime | None,
    access: datetime | None,
    name: str,
    namespace: int = 1,
) -> bytes:
    """Build $FILE_NAME attribute content bytes."""

    def _ft(dt: datetime | None) -> bytes:
        return (0 if dt is None else datetime_to_filetime(dt)).to_bytes(8, "little")

    name_utf16 = name.encode("utf-16-le")
    return b"".join(
        [
            parent_record_number.to_bytes(8, "little"),
            _ft(creation),
            _ft(modification),
            _ft(mft_modification),
            _ft(access),
            (1024).to_bytes(8, "little"),
            (1024).to_bytes(8, "little"),
            (0).to_bytes(4, "little"),
            (0).to_bytes(4, "little"),
            bytes([len(name)]),
            bytes([namespace]),
            name_utf16,
        ]
    )


def build_mft_record(  # pylint: disable=too-many-arguments,too-many-locals
    *,
    si_creation: datetime | None = None,
    si_modification: datetime | None = None,
    si_mft_modification: datetime | None = None,
    si_access: datetime | None = None,
    fn_creation: datetime | None = None,
    fn_modification: datetime | None = None,
    fn_mft_modification: datetime | None = None,
    fn_access: datetime | None = None,
    filename: str = "test.exe",
    parent_record_number: int = 5,
    is_directory: bool = False,
    is_allocated: bool = True,
    include_si: bool = True,
    include_fn: bool = True,
    corrupt_fixup: bool = False,
) -> bytes:
    """Build a full, spec-correct 1024-byte synthetic MFT record.

    Args:
        si_creation: $STANDARD_INFORMATION creation time.
        si_modification: $STANDARD_INFORMATION modification time.
        si_mft_modification: $STANDARD_INFORMATION MFT-modification time.
        si_access: $STANDARD_INFORMATION access time.
        fn_creation: $FILE_NAME creation time.
        fn_modification: $FILE_NAME modification time.
        fn_mft_modification: $FILE_NAME MFT-modification time.
        fn_access: $FILE_NAME access time.
        filename: The file name to embed in $FILE_NAME.
        parent_record_number: Parent directory MFT record number.
        is_directory: Whether to set the directory flag.
        is_allocated: Whether to set the in-use flag.
        include_si: Whether to include a $STANDARD_INFORMATION attribute.
        include_fn: Whether to include a $FILE_NAME attribute.
        corrupt_fixup: If True, deliberately corrupts the fixup so
            fixup verification will fail.

    Returns:
        1024 bytes representing one valid (unless ``corrupt_fixup``)
        MFT record.
    """
    record = bytearray(1024)
    record[0:4] = b"FILE"

    usa_offset = 48
    usa_count = 3  # 1 USN + 2 sectors (1024 / 512)
    record[4:6] = usa_offset.to_bytes(2, "little")
    record[6:8] = usa_count.to_bytes(2, "little")
    record[16:18] = (1).to_bytes(2, "little")  # sequence number
    record[18:20] = (1).to_bytes(2, "little")  # hard link count

    first_attr_offset = 56
    record[20:22] = first_attr_offset.to_bytes(2, "little")

    flags = (0x0001 if is_allocated else 0) | (0x0002 if is_directory else 0)
    record[22:24] = flags.to_bytes(2, "little")

    usn = b"\x01\x00"
    real_sector1 = b"\xAB\xCD"
    real_sector2 = b"\xEF\x01"
    record[usa_offset : usa_offset + 2] = usn
    record[usa_offset + 2 : usa_offset + 4] = real_sector1
    record[usa_offset + 4 : usa_offset + 6] = real_sector2
    record[510:512] = usn
    record[1022:1024] = b"\x00\x00" if corrupt_fixup else usn

    offset = first_attr_offset
    if include_si:
        si_content = _build_si_content(
            si_creation, si_modification, si_mft_modification, si_access
        )
        si_attr = _build_resident_attribute(0x10, si_content)
        record[offset : offset + len(si_attr)] = si_attr
        offset += len(si_attr)

    if include_fn:
        fn_content = _build_fn_content(
            parent_record_number,
            fn_creation,
            fn_modification,
            fn_mft_modification,
            fn_access,
            filename,
        )
        fn_attr = _build_resident_attribute(0x30, fn_content)
        record[offset : offset + len(fn_attr)] = fn_attr
        offset += len(fn_attr)

    record[offset : offset + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    used_size = offset + 4
    record[24:28] = used_size.to_bytes(4, "little")
    record[28:32] = (1024).to_bytes(4, "little")

    return bytes(record)