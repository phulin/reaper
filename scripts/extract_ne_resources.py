#!/usr/bin/env python3
"""List or extract resources from a Windows NE executable."""

from __future__ import annotations

import argparse
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path


NE_INT_RESOURCE_TYPES = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    15: "NAMETABLE",
}


@dataclass(frozen=True)
class ResourceEntry:
    type_id: int
    type_name: str
    resource_id: int
    offset: int
    length: int
    flags: int

    def to_json(self) -> dict[str, object]:
        return {
            "type_id": self.type_id,
            "type_id_hex": f"0x{self.type_id:04x}",
            "type_name": self.type_name,
            "resource_id": self.resource_id,
            "resource_id_hex": f"0x{self.resource_id:04x}",
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:08x}",
            "length": self.length,
            "flags": self.flags,
            "flags_hex": f"0x{self.flags:04x}",
        }


def parse_int(value: str) -> int:
    return int(value, 0)


def normalize_type_id(type_id: int) -> int:
    return type_id & 0x7FFF if type_id & 0x8000 else type_id


def decode_int_id(resource_id: int) -> int:
    return resource_id & 0x7FFF if resource_id & 0x8000 else resource_id


def parse_name_table(binary: bytes, cursor: int) -> dict[int, str]:
    names: dict[int, str] = {}
    start = cursor
    while cursor < len(binary):
        size = binary[cursor]
        if size == 0:
            break
        cursor += 1
        names[cursor - start - 1] = binary[cursor : cursor + size].decode(
            "latin1", "replace"
        )
        cursor += size
    return names


def decode_type_name(type_id: int, names: dict[int, str]) -> str:
    if type_id & 0x8000:
        normalized = normalize_type_id(type_id)
        return NE_INT_RESOURCE_TYPES.get(normalized, f"INT_{normalized}")
    return names.get(type_id, f"STR_{type_id}")


def parse_ne_resources(binary: bytes) -> list[ResourceEntry]:
    if len(binary) < 0x40:
        raise ValueError("Input is too small to contain an NE header pointer")

    ne_offset = struct.unpack_from("<I", binary, 0x3C)[0]
    if binary[ne_offset : ne_offset + 2] != b"NE":
        raise ValueError("Input is not an NE executable")

    resource_table_offset = (
        ne_offset + struct.unpack_from("<H", binary, ne_offset + 0x24)[0]
    )
    align_shift = struct.unpack_from("<H", binary, resource_table_offset)[0]

    cursor = resource_table_offset + 2
    raw_entries: list[tuple[int, list[tuple[int, int, int, int]]]] = []
    while True:
        type_id = struct.unpack_from("<H", binary, cursor)[0]
        cursor += 2
        if type_id == 0:
            break

        count = struct.unpack_from("<H", binary, cursor)[0]
        cursor += 2
        cursor += 4

        resources: list[tuple[int, int, int, int]] = []
        for _ in range(count):
            offset = struct.unpack_from("<H", binary, cursor)[0] << align_shift
            length = struct.unpack_from("<H", binary, cursor + 2)[0] << align_shift
            flags = struct.unpack_from("<H", binary, cursor + 4)[0]
            resource_id = struct.unpack_from("<H", binary, cursor + 6)[0]
            cursor += 12
            resources.append((resource_id, offset, length, flags))
        raw_entries.append((type_id, resources))

    names = parse_name_table(binary, cursor)
    entries: list[ResourceEntry] = []
    for type_id, resources in raw_entries:
        type_name = decode_type_name(type_id, names)
        normalized_type_id = normalize_type_id(type_id)
        for resource_id, offset, length, flags in resources:
            entries.append(
                ResourceEntry(
                    type_id=normalized_type_id,
                    type_name=type_name,
                    resource_id=decode_int_id(resource_id),
                    offset=offset,
                    length=length,
                    flags=flags,
                )
            )
    return entries


def sanitize_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "resource"


def matches_filter(
    entry: ResourceEntry,
    type_filters: set[int | str] | None,
    id_filters: set[int] | None,
) -> bool:
    if type_filters is not None:
        type_match = (
            entry.type_id in type_filters or entry.type_name.upper() in type_filters
        )
        if not type_match:
            return False
    if id_filters is not None and entry.resource_id not in id_filters:
        return False
    return True


def resource_bytes(binary: bytes, entry: ResourceEntry, swap_words: bool) -> bytes:
    data = binary[entry.offset : entry.offset + entry.length]
    if not swap_words:
        return data

    swapped = bytearray()
    full_words = len(data) - (len(data) % 2)
    for index in range(0, full_words, 2):
        swapped.extend((data[index + 1], data[index]))
    swapped.extend(data[full_words:])
    return bytes(swapped)


def parse_type_filters(values: list[str]) -> set[int | str] | None:
    if not values:
        return None

    filters: set[int | str] = set()
    for value in values:
        try:
            filters.add(parse_int(value))
        except ValueError:
            filters.add(value.upper())
    return filters


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Path to the NE executable.")
    parser.add_argument(
        "--list",
        action="store_true",
        help="List matching resources as JSON without extracting them.",
    )
    parser.add_argument(
        "--type",
        dest="types",
        action="append",
        default=[],
        help="Resource type name or id to include. May be repeated.",
    )
    parser.add_argument(
        "--id",
        dest="ids",
        action="append",
        type=parse_int,
        default=[],
        help="Resource id to include. May be repeated.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("ne-resources"),
        help="Directory for extracted resource payloads.",
    )
    parser.add_argument(
        "--swap-words",
        action="store_true",
        help="Swap each 16-bit word in the extracted payloads.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    input_path = args.input.resolve()
    binary = input_path.read_bytes()
    resources = parse_ne_resources(binary)
    type_filters = parse_type_filters(args.types)
    id_filters = set(args.ids) if args.ids else None
    matched = [
        entry for entry in resources if matches_filter(entry, type_filters, id_filters)
    ]

    if args.list:
        print(json.dumps([entry.to_json() for entry in matched], indent=2))
        return 0

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[dict[str, object]] = []
    for entry in matched:
        stem = sanitize_filename(
            f"{entry.type_name}_{entry.type_id:04x}_{entry.resource_id:04x}"
        )
        output_path = output_dir / f"{stem}.bin"
        output_path.write_bytes(resource_bytes(binary, entry, args.swap_words))
        metadata = entry.to_json()
        metadata["path"] = str(output_path)
        extracted.append(metadata)

    print(json.dumps({"input_path": str(input_path), "extracted": extracted}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
