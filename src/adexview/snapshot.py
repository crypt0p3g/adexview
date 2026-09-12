# Derived from takito1812/adx-query (MIT), Copyright (c) 2025 Víctor García.
# Substantially rewritten in this edition; see LICENSE and NOTICE.md.
"""Binary reader for Sysinternals AD Explorer ``.dat`` snapshots.

The whole file is memory-mapped and decoded with ``struct.unpack_from`` on the
mapping, so reading an object costs a handful of C-level calls instead of one
``read()`` per field. Every length and offset taken from the file is checked
against the object region before it is used, so a truncated or corrupt
snapshot raises :class:`SnapshotFormatError` instead of reading garbage.

The format knowledge comes from analysis of snapshot files and from the
published work in https://github.com/c3c/ADExplorerSnapshot.py (MIT).
"""

from __future__ import annotations

import codecs
import datetime
import mmap
import os
import struct
import uuid
from array import array
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

# ADSI attribute type constants (subset required for the reader)
ADSTYPE_INVALID = 0
ADSTYPE_DN_STRING = 1
ADSTYPE_CASE_EXACT_STRING = 2
ADSTYPE_CASE_IGNORE_STRING = 3
ADSTYPE_PRINTABLE_STRING = 4
ADSTYPE_NUMERIC_STRING = 5
ADSTYPE_BOOLEAN = 6
ADSTYPE_INTEGER = 7
ADSTYPE_OCTET_STRING = 8
ADSTYPE_UTC_TIME = 9
ADSTYPE_LARGE_INTEGER = 10
ADSTYPE_PROV_SPECIFIC = 11
ADSTYPE_OBJECT_CLASS = 12
ADSTYPE_CASEIGNORE_LIST = 13
ADSTYPE_OCTET_LIST = 14
ADSTYPE_PATH = 15
ADSTYPE_POSTALADDRESS = 16
ADSTYPE_TIMESTAMP = 17
ADSTYPE_BACKLINK = 18
ADSTYPE_TYPEDNAME = 19
ADSTYPE_HOLD = 20
ADSTYPE_NETADDRESS = 21
ADSTYPE_REPLICAPOINTER = 22
ADSTYPE_FAXNUMBER = 23
ADSTYPE_EMAIL = 24
ADSTYPE_NT_SECURITY_DESCRIPTOR = 25
ADSTYPE_UNKNOWN = 26
ADSTYPE_DN_WITH_BINARY = 27
ADSTYPE_DN_WITH_STRING = 28

STRING_ADS_TYPES = frozenset((
    ADSTYPE_DN_STRING, ADSTYPE_CASE_EXACT_STRING, ADSTYPE_CASE_IGNORE_STRING,
    ADSTYPE_PRINTABLE_STRING, ADSTYPE_NUMERIC_STRING, ADSTYPE_OBJECT_CLASS,
))

HEADER_SIZE = 0x43E
SIGNATURE_COMPLETE = b"win-ad-ob\x00"
SIGNATURE_IN_PROGRESS = b"win-ad-XX\x00"
# Header field offsets (all little-endian).
_OFF_MARKER = 10
_OFF_FILETIME = 14
_OFF_DESCRIPTION = 22
_OFF_SERVER = 22 + 520
_OFF_NUM_OBJECTS = 22 + 1040
_OFF_NUM_ATTRIBUTES = _OFF_NUM_OBJECTS + 4
_OFF_MAPPING = _OFF_NUM_ATTRIBUTES + 4
# Largest single value the reader will accept. Real snapshots hold values of a
# few megabytes at most (certificates, large security descriptors); anything
# beyond this is treated as corruption rather than allocated.
MAX_VALUE_BYTES = 64 * 1024 * 1024

_U32 = struct.Struct("<I")
_I32 = struct.Struct("<i")
_I64 = struct.Struct("<q")
_U64 = struct.Struct("<Q")
_MAPPING_PAIR = struct.Struct("<Ii")
_SYSTEMTIME = struct.Struct("<8H")
_OBJECT_HEADER = struct.Struct("<II")
_PROPERTY_TYPES = struct.Struct("<iI")
# "utf-16-le" is not one of CPython's fast-path codec names, so bytes.decode()
# would route every string through the Python-level codec wrapper. Calling the
# C decoder directly avoids that for the millions of strings a snapshot holds.
_utf16le_decode = codecs.utf_16_le_decode


class SnapshotFormatError(ValueError):
    """The snapshot is truncated, corrupt, or not an AD Explorer file."""


@dataclass(frozen=True)
class SnapshotHeader:
    signature: str
    captured_at: datetime.datetime
    description: str
    server: str
    num_objects: int
    num_attributes: int
    mapping_offset: int
    file_size: int

    @property
    def complete(self) -> bool:
        return self.signature == SIGNATURE_COMPLETE.rstrip(b"\x00").decode("ascii")


@dataclass(frozen=True)
class PropertyDefinition:
    index: int
    name: str
    ads_type: int
    distinguished_name: str
    schema_id_guid: uuid.UUID
    attribute_security_guid: uuid.UUID


def _windows_filetime_to_datetime(value: int) -> datetime.datetime:
    """Convert a Windows FILETIME (100-ns intervals since 1601) to UTC datetime."""
    if value == 0:
        return datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)
    epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    try:
        return epoch_start + datetime.timedelta(microseconds=value // 10)
    except OverflowError:
        return epoch_start


def _utf16(data) -> str:
    if not data:
        return ""
    return _utf16le_decode(data, "ignore")[0].rstrip("\x00")


def _parse_sid(data: bytes) -> str:
    """Convert a binary SID into the standard string representation."""
    if len(data) < 8:
        return data.hex()
    revision = data[0]
    sub_authority_count = data[1]
    identifier_authority = int.from_bytes(data[2:8], byteorder="big")
    subs = []
    for i in range(sub_authority_count):
        start = 8 + i * 4
        if start + 4 > len(data):
            break
        subs.append(str(_U32.unpack_from(data, start)[0]))
    return "S-{}-{}{}".format(revision, identifier_authority, "".join(f"-{s}" for s in subs))


def _decode_octet_string(prop_name: str, blob: bytes, raw: bool) -> object:
    """Decode binary attributes to human readable types when possible."""
    if raw:
        return blob
    low_name = prop_name.lower()
    if len(blob) == 16 and (low_name.endswith("guid") or low_name == "objectguid"):
        return str(uuid.UUID(bytes_le=blob))
    if low_name == "objectsid":
        return _parse_sid(blob)
    return blob.hex()


def _collapse_values(values: List[object]) -> object:
    if not values:
        return []
    if len(values) == 1:
        return values[0]
    return values


class SnapshotEntry:
    """One directory object; attribute values are decoded lazily and cached."""

    __slots__ = ("reader", "offset", "size", "_mapping", "_by_index", "_cache", "_raw_cache")

    def __init__(self, reader: "SnapshotReader", offset: int):
        self.reader = reader
        self.offset = offset
        buf = reader.buf
        limit = reader.data_end
        if offset < HEADER_SIZE or offset + 8 > limit:
            raise SnapshotFormatError(f"object offset {offset} is outside the object region")
        size, table_size = _OBJECT_HEADER.unpack_from(buf, offset)
        table_end = offset + 8 + table_size * 8
        if size < 8 or offset + size > limit or table_end > offset + size:
            raise SnapshotFormatError(f"object at {offset} has an invalid size/table ({size}, {table_size})")
        self.size = size
        self._mapping: Tuple[Tuple[int, int], ...] = tuple(
            _MAPPING_PAIR.iter_unpack(buf[offset + 8:table_end])
        )
        self._by_index: Optional[Dict[int, int]] = None
        self._cache: Dict[int, List[object]] = {}
        self._raw_cache: Dict[int, List[object]] = {}

    @property
    def mapping(self) -> Sequence[Tuple[int, int]]:
        return self._mapping

    def attribute_offset(self, prop_index: int) -> Optional[int]:
        by_index = self._by_index
        if by_index is None:
            by_index = self._by_index = dict(self._mapping)
        return by_index.get(prop_index)

    def has_attribute(self, attr_name: str) -> bool:
        prop = self.reader.get_property(attr_name)
        return prop is not None and self.attribute_offset(prop.index) is not None

    def get_attribute_values(self, attr_name: str, raw: bool = False) -> List[object]:
        prop = self.reader.get_property(attr_name)
        if prop is None:
            raise KeyError(attr_name)
        cache = self._raw_cache if raw else self._cache
        cached = cache.get(prop.index)
        if cached is not None:
            return cached
        attr_offset = self.attribute_offset(prop.index)
        if attr_offset is None:
            raise KeyError(attr_name)
        values = self._read_values(prop, attr_offset, raw=raw)
        cache[prop.index] = values
        return values

    def iter_attributes(self, raw: bool = False) -> Iterator[Tuple[str, List[object]]]:
        cache = self._raw_cache if raw else self._cache
        properties = self.reader.properties
        for attr_index, attr_offset in self._mapping:
            prop = properties[attr_index]
            values = cache.get(attr_index)
            if values is None:
                values = self._read_values(prop, attr_offset, raw=raw)
                cache[attr_index] = values
            yield prop.name, values

    def raw_items(self, wanted: Optional[frozenset] = None) -> Iterator[Tuple[str, List[object]]]:
        """Yield (name, raw values) for every attribute, or only ``wanted`` indexes."""
        cache = self._raw_cache
        properties = self.reader.properties
        for attr_index, attr_offset in self._mapping:
            if wanted is not None and attr_index not in wanted:
                continue
            values = cache.get(attr_index)
            if values is None:
                values = self._read_values(properties[attr_index], attr_offset, raw=True)
                cache[attr_index] = values
            yield properties[attr_index].name, values

    def to_dict(
        self,
        attributes: Optional[Sequence[str]] = None,
        *,
        decode: bool = True,
        timezone_name: str = "Asia/Tokyo",
    ) -> Dict[str, object]:
        """Materialise the entry.

        Binary values are fetched in their original form and passed through
        the central attribute decoder.  ``decode=False`` is useful to audit
        numeric flags or perform custom analysis without losing source values.
        """
        wanted = self.reader.get_property_indices(attributes) if attributes else None
        result: Dict[str, object] = {
            name: _collapse_values(values) for name, values in self.raw_items(wanted)
        }
        if not decode:
            return result
        from .decoders import decode_record

        return decode_record(result, ads_types=self.reader.ads_types, timezone_name=timezone_name)

    # -- value decoding --------------------------------------------------------

    def _read_values(self, prop: PropertyDefinition, attr_offset: int, raw: bool = False) -> List[object]:
        reader = self.reader
        buf = reader.buf
        limit = reader.data_end
        base = self.offset + attr_offset
        if base < HEADER_SIZE or base + 4 > limit:
            raise SnapshotFormatError(f"value offset {base} for {prop.name} is outside the object region")
        num_values = _U32.unpack_from(buf, base)[0]
        if num_values == 0:
            return []
        if num_values > (limit - base) // 4:
            raise SnapshotFormatError(f"{prop.name} at {base} claims {num_values} values")
        attr_type = prop.ads_type
        pos = base + 4
        values: List[object] = []

        if attr_type in STRING_ADS_TYPES:
            end_offsets = pos + 4 * num_values
            if end_offsets > limit:
                raise SnapshotFormatError(f"{prop.name} at {base} string table is truncated")
            for rel in struct.unpack_from(f"<{num_values}i", buf, pos):
                start = base + rel
                if start < HEADER_SIZE or start > limit:
                    raise SnapshotFormatError(f"{prop.name} at {base} points outside the file")
                values.append(reader.read_wchar(start))
            return values

        if attr_type == ADSTYPE_OCTET_STRING:
            data_pos = base + 4 + 4 * num_values
            if data_pos > limit:
                raise SnapshotFormatError(f"{prop.name} at {base} length table is truncated")
            for length in struct.unpack_from(f"<{num_values}I", buf, base + 4):
                if length > MAX_VALUE_BYTES or data_pos + length > limit:
                    raise SnapshotFormatError(f"{prop.name} at {base} has an invalid value length {length}")
                blob = buf[data_pos:data_pos + length]
                data_pos += length
                values.append(_decode_octet_string(prop.name, blob, raw))
            return values

        if attr_type == ADSTYPE_BOOLEAN:
            if pos + 4 * num_values > limit:
                raise SnapshotFormatError(f"{prop.name} at {base} is truncated")
            return [bool(item) for item in struct.unpack_from(f"<{num_values}I", buf, pos)]

        if attr_type == ADSTYPE_INTEGER:
            if pos + 4 * num_values > limit:
                raise SnapshotFormatError(f"{prop.name} at {base} is truncated")
            return list(struct.unpack_from(f"<{num_values}I", buf, pos))

        if attr_type == ADSTYPE_LARGE_INTEGER:
            if pos + 8 * num_values > limit:
                raise SnapshotFormatError(f"{prop.name} at {base} is truncated")
            return list(struct.unpack_from(f"<{num_values}q", buf, pos))

        if attr_type == ADSTYPE_UTC_TIME:
            if pos + 16 * num_values > limit:
                raise SnapshotFormatError(f"{prop.name} at {base} is truncated")
            for _ in range(num_values):
                year, month, _dow, day, hour, minute, second, _ms = _SYSTEMTIME.unpack_from(buf, pos)
                pos += 16
                try:
                    stamp = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
                    values.append(int(stamp.timestamp()))
                except (ValueError, OverflowError):
                    values.append(0)
            return values

        # Security descriptors and every other structured type are stored as
        # length-prefixed blobs.
        data_pos = base + 4 + 4 * num_values
        if data_pos > limit:
            raise SnapshotFormatError(f"{prop.name} at {base} length table is truncated")
        for length in struct.unpack_from(f"<{num_values}I", buf, base + 4):
            if length > MAX_VALUE_BYTES or data_pos + length > limit:
                raise SnapshotFormatError(f"{prop.name} at {base} has an invalid value length {length}")
            blob = buf[data_pos:data_pos + length]
            data_pos += length
            values.append(blob if raw else blob.hex())
        return values


class SnapshotReader:
    """High-level access to an AD Explorer snapshot."""

    def __init__(
        self,
        path: "os.PathLike[str] | str",
        use_mmap: bool = True,
        parse_object_offsets: bool = True,
    ):
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        self._fh_raw = self.path.open("rb")
        self._mmap: Optional[mmap.mmap] = None
        if use_mmap:
            try:
                self._mmap = mmap.mmap(self._fh_raw.fileno(), 0, access=mmap.ACCESS_READ)
                self.buf = self._mmap
            except ValueError:
                # Empty file: fall back to an in-memory buffer so the header
                # check below produces a clear error.
                self.buf = self._fh_raw.read()
        else:
            # Rarely used: reading the whole file keeps the same bytes-slicing
            # semantics as the mmap object, at the cost of copying on slice.
            self.buf = self._fh_raw.read()
        self.file_size = len(self.buf)
        try:
            self._header = self._parse_header()
            self.data_end = self._header.mapping_offset
            self._properties, self._property_by_name = self._parse_properties()
            self.ads_types: Dict[str, int] = {
                prop.name.casefold(): prop.ads_type for prop in self._properties
            }
            self._property_index_cache: Dict[Tuple[str, ...], frozenset] = {}
            self._object_offsets = self._parse_object_offsets() if parse_object_offsets else array("Q")
        except Exception:
            self.close()
            raise

    def __enter__(self) -> "SnapshotReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __len__(self) -> int:
        return len(self._object_offsets)

    def close(self) -> None:
        if self._mmap is not None:
            self._mmap.close()
            self._mmap = None
        self._fh_raw.close()

    @property
    def header(self) -> SnapshotHeader:
        return self._header

    @property
    def properties(self) -> Sequence[PropertyDefinition]:
        return self._properties

    @property
    def object_offsets(self) -> Sequence[int]:
        return self._object_offsets

    def get_property(self, name: Optional[str]) -> Optional[PropertyDefinition]:
        if name is None:
            return None
        idx = self._property_by_name.get(name.casefold())
        if idx is None:
            return None
        return self._properties[idx]

    def get_property_indices(self, names: Sequence[str]) -> frozenset:
        """Resolve an attribute selection once and reuse it for every object."""
        key = tuple(names)
        cached = self._property_index_cache.get(key)
        if cached is None:
            cached = frozenset(
                index for name in names
                if (index := self._property_by_name.get(name.casefold())) is not None
            )
            if len(self._property_index_cache) >= 256:
                self._property_index_cache.clear()
            self._property_index_cache[key] = cached
        return cached

    def read_wchar(self, start: int) -> str:
        """Read a NUL-terminated UTF-16LE string at an absolute offset."""
        buf = self.buf
        limit = self.data_end
        end = buf.find(b"\x00\x00", start, limit + 1)
        # The terminator must sit on a UTF-16 code-unit boundary.
        while end != -1 and (end - start) & 1:
            end = buf.find(b"\x00\x00", end + 1, limit + 1)
        if end == -1:
            raise SnapshotFormatError(f"unterminated string at {start}")
        if end == start:
            return ""
        return _utf16le_decode(buf[start:end], "ignore")[0]

    def iter_entries(self) -> Iterator[SnapshotEntry]:
        for offset in self._object_offsets:
            yield SnapshotEntry(self, offset)

    def entry_at(self, index: int) -> SnapshotEntry:
        """Return one object by its zero-based snapshot ordinal."""
        if index < 0 or index >= len(self._object_offsets):
            raise IndexError(index)
        return SnapshotEntry(self, self._object_offsets[index])

    def entry_at_offset(self, offset: int) -> SnapshotEntry:
        """Return one object using a byte offset saved by an index."""
        if offset < HEADER_SIZE or offset >= self._header.mapping_offset:
            raise ValueError(f"invalid snapshot object offset: {offset}")
        return SnapshotEntry(self, offset)

    # -- internal parsing helpers -------------------------------------------------

    def _parse_header(self) -> SnapshotHeader:
        buf = self.buf
        if self.file_size < HEADER_SIZE:
            raise SnapshotFormatError("file is smaller than an AD Explorer snapshot header")
        signature = bytes(buf[0:10])
        if signature not in (SIGNATURE_COMPLETE, SIGNATURE_IN_PROGRESS):
            raise SnapshotFormatError("not an AD Explorer snapshot (bad signature)")
        filetime = _U64.unpack_from(buf, _OFF_FILETIME)[0]
        description = _utf16(buf[_OFF_DESCRIPTION:_OFF_DESCRIPTION + 520])
        server = _utf16(buf[_OFF_SERVER:_OFF_SERVER + 520])
        num_objects = _U32.unpack_from(buf, _OFF_NUM_OBJECTS)[0]
        num_attributes = _U32.unpack_from(buf, _OFF_NUM_ATTRIBUTES)[0]
        mapping_offset = _U64.unpack_from(buf, _OFF_MAPPING)[0]
        if mapping_offset < HEADER_SIZE or mapping_offset + 4 > self.file_size:
            raise SnapshotFormatError(f"metadata offset {mapping_offset} is outside the file")
        return SnapshotHeader(
            signature=signature.decode("ascii", errors="ignore").rstrip("\x00"),
            captured_at=_windows_filetime_to_datetime(filetime),
            description=description,
            server=server,
            num_objects=num_objects,
            num_attributes=num_attributes,
            mapping_offset=mapping_offset,
            file_size=self.file_size,
        )

    def _parse_properties(self) -> Tuple[List[PropertyDefinition], Dict[str, int]]:
        buf = self.buf
        size = self.file_size
        pos = self._header.mapping_offset
        num_properties = _U32.unpack_from(buf, pos)[0]
        pos += 4
        properties: List[PropertyDefinition] = []
        by_name: Dict[str, int] = {}

        def take(count: int) -> int:
            nonlocal pos
            if count > size - pos:
                raise SnapshotFormatError("property table is truncated")
            start = pos
            pos += count
            return start

        for idx in range(num_properties):
            name_len = _U32.unpack_from(buf, take(4))[0]
            name = _utf16(buf[take(name_len):pos])
            _syntax_id, ads_type = _PROPERTY_TYPES.unpack_from(buf, take(8))
            dn_len = _U32.unpack_from(buf, take(4))[0]
            distinguished_name = _utf16(buf[take(dn_len):pos])
            schema_guid = uuid.UUID(bytes_le=bytes(buf[take(16):pos]))
            attribute_guid = uuid.UUID(bytes_le=bytes(buf[take(16):pos]))
            take(4)  # display hint
            properties.append(PropertyDefinition(
                index=idx, name=name, ads_type=ads_type,
                distinguished_name=distinguished_name,
                schema_id_guid=schema_guid, attribute_security_guid=attribute_guid,
            ))
            by_name[name.casefold()] = idx
        return properties, by_name

    def _parse_object_offsets(self) -> array:
        offsets = array("Q")
        buf = self.buf
        limit = self.data_end
        pos = HEADER_SIZE
        unpack = _U32.unpack_from
        for _ in range(self._header.num_objects):
            if pos + 8 > limit:
                break
            obj_size = unpack(buf, pos)[0]
            if obj_size < 8 or pos + obj_size > limit:
                raise SnapshotFormatError(f"object at {pos} has an invalid size {obj_size}")
            offsets.append(pos)
            pos += obj_size
        return offsets
