"""NE (New Executable) format parser for 16-bit Windows executables."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


@dataclass
class MZHeader:
    """DOS MZ stub header preceding the NE header."""

    e_magic: int
    e_lfanew: int  # offset to NE header (at MZ offset 0x3C)

    @classmethod
    def parse(cls, data: bytes) -> MZHeader:
        if len(data) < 0x40:
            raise ValueError("File too small for MZ header")
        magic = struct.unpack_from("<H", data, 0)[0]
        if magic != 0x5A4D:
            raise ValueError(f"Not an MZ executable (magic=0x{magic:04X})")
        lfanew = struct.unpack_from("<H", data, 0x3C)[0]
        return cls(e_magic=magic, e_lfanew=lfanew)


@dataclass
class NESegmentEntry:
    """One entry in the NE segment table."""

    index: int  # 1-based segment number
    file_offset: int  # absolute byte offset in file (after shift)
    length: int  # length in file (0 means 64K)
    flags: int
    min_alloc: int  # minimum allocation size (0 means 64K)

    @property
    def is_data(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def is_code(self) -> bool:
        return not self.is_data

    @property
    def has_relocs(self) -> bool:
        return bool(self.flags & 0x0100)

    @property
    def alloc_size(self) -> int:
        size = max(self.length or 0x10000, self.min_alloc or 0x10000)
        return size


@dataclass
class NERelocation:
    """One relocation entry within a segment."""

    src_type: int  # 0=LOBYTE, 2=SEG16, 3=FAR32, 5=OFF16
    rel_type: int  # low 2 bits: 0=internal, 1=imp_ord, 2=imp_name, 3=osfixup
    offset: int  # offset within segment
    param1: int
    param2: int

    @property
    def is_additive(self) -> bool:
        return bool(self.rel_type & 0x04)

    @property
    def kind(self) -> int:
        return self.rel_type & 0x03

    # Relocation kinds
    INTERNAL = 0
    IMPORTED_ORDINAL = 1
    IMPORTED_NAME = 2
    OSFIXUP = 3

    # Source types
    SRC_LOBYTE = 0
    SRC_SEG16 = 2
    SRC_FAR32 = 3
    SRC_OFF16 = 5


@dataclass
class NEResourceEntry:
    """One resource entry (NAMEINFO) from the NE resource table."""

    type_id: int  # integer resource type (high bit stripped)
    res_id: int  # integer resource ID (high bit stripped)
    file_offset: int  # absolute byte offset in file
    length: int  # length in bytes
    flags: int

    # Standard NE resource types
    RT_CURSOR = 1
    RT_BITMAP = 2
    RT_ICON = 3
    RT_MENU = 4
    RT_DIALOG = 5
    RT_STRING = 6
    RT_FONTDIR = 7
    RT_FONT = 8
    RT_ACCELERATOR = 9
    RT_RCDATA = 10
    RT_GROUP_CURSOR = 12
    RT_GROUP_ICON = 14


@dataclass
class NEResourceTypeGroup:
    """One TYPEINFO block from the NE resource table."""

    type_id: int  # integer resource type (high bit stripped), or raw offset for named types
    type_name: str = ""  # non-empty for named (string) resource types
    entries: list[NEResourceEntry] = field(default_factory=list)


@dataclass
class NEHeader:
    """Parsed NE header and associated tables."""

    ne_offset: int
    entry_cs: int  # 1-based segment index for CS
    entry_ip: int
    stack_ss: int  # 1-based segment index for SS
    stack_sp: int
    num_segments: int
    num_module_refs: int
    align_shift: int
    auto_data_seg: int  # automatic data segment index (DGROUP)
    program_flags: int
    app_flags: int

    segments: list[NESegmentEntry] = field(default_factory=list)
    module_names: list[str] = field(default_factory=list)
    module_name: str = ""
    resources: list[NEResourceTypeGroup] = field(default_factory=list)
    # Mapping from uppercase type name to integer type_id (0x8000 stripped),
    # built from the NE name table resource (RT_NAMETABLE = 0x800F).
    _name_table: dict[str, int] = field(default_factory=dict)

    def find_resource(
        self, type_id: int, res_id: int
    ) -> NEResourceEntry | None:
        """Find a resource by integer type and ID."""
        for group in self.resources:
            if group.type_id == type_id:
                for entry in group.entries:
                    if entry.res_id == res_id:
                        return entry
                return None
        return None

    def find_resource_by_name(
        self, type_name: str, res_id: int
    ) -> NEResourceEntry | None:
        """Find a resource by string type name and integer ID.

        Resolves the string type name to an integer type ID using the NE
        name table (RT_NAMETABLE, type 0x800F), mirroring Win16
        FindResource behavior.  Falls back to matching against resource
        groups that carry an explicit string name.
        """
        type_name_upper = type_name.upper()

        # Primary path: resolve via the name table (like Wine's
        # NE_FindNameTableId).  The name table maps string type names
        # to integer type IDs.
        resolved_type = self._name_table.get(type_name_upper)
        if resolved_type is not None:
            return self.find_resource(resolved_type, res_id)

        # Fallback: match against groups that have an explicit name
        # stored in the resource table itself (type_id without 0x8000).
        for group in self.resources:
            if group.type_name and group.type_name.upper() == type_name_upper:
                for entry in group.entries:
                    if entry.res_id == res_id:
                        return entry
                return None

        return None

    @classmethod
    def parse(cls, data: bytes) -> NEHeader:
        mz = MZHeader.parse(data)
        ne_off = mz.e_lfanew

        if len(data) < ne_off + 0x40:
            raise ValueError("File too small for NE header")

        sig = data[ne_off : ne_off + 2]
        if sig != b"NE":
            raise ValueError(f"Not an NE executable (sig={sig!r})")

        # Parse NE header fields
        entry_ip = struct.unpack_from("<H", data, ne_off + 0x14)[0]
        entry_cs = struct.unpack_from("<H", data, ne_off + 0x16)[0]
        stack_sp = struct.unpack_from("<H", data, ne_off + 0x18)[0]
        stack_ss = struct.unpack_from("<H", data, ne_off + 0x1A)[0]
        num_segments = struct.unpack_from("<H", data, ne_off + 0x1C)[0]
        num_module_refs = struct.unpack_from("<H", data, ne_off + 0x1E)[0]
        seg_table_off = struct.unpack_from("<H", data, ne_off + 0x22)[0]
        res_table_off = struct.unpack_from("<H", data, ne_off + 0x24)[0]
        res_name_off = struct.unpack_from("<H", data, ne_off + 0x26)[0]
        mod_ref_off = struct.unpack_from("<H", data, ne_off + 0x28)[0]
        imp_name_off = struct.unpack_from("<H", data, ne_off + 0x2A)[0]
        align_shift = struct.unpack_from("<H", data, ne_off + 0x32)[0]
        auto_data_seg = struct.unpack_from("<H", data, ne_off + 0x0E)[0]
        program_flags = data[ne_off + 0x0D]
        app_flags = data[ne_off + 0x0E]

        hdr = cls(
            ne_offset=ne_off,
            entry_cs=entry_cs,
            entry_ip=entry_ip,
            stack_ss=stack_ss,
            stack_sp=stack_sp,
            num_segments=num_segments,
            num_module_refs=num_module_refs,
            align_shift=align_shift,
            auto_data_seg=auto_data_seg,
            program_flags=program_flags,
            app_flags=app_flags,
        )

        # Parse segment table
        abs_seg = ne_off + seg_table_off
        for i in range(num_segments):
            offset, length, flags, min_alloc = struct.unpack_from(
                "<HHHH", data, abs_seg + i * 8
            )
            hdr.segments.append(
                NESegmentEntry(
                    index=i + 1,
                    file_offset=offset << align_shift,
                    length=length,
                    flags=flags,
                    min_alloc=min_alloc,
                )
            )

        # Parse resource table
        if res_table_off != 0:
            abs_rt = ne_off + res_table_off
            rsc_align_shift = struct.unpack_from("<H", data, abs_rt)[0]
            pos = abs_rt + 2
            while True:
                rt_type_id = struct.unpack_from("<H", data, pos)[0]
                if rt_type_id == 0:
                    break
                rt_count = struct.unpack_from("<H", data, pos + 2)[0]
                # Skip rtReserved (4 bytes)
                pos += 8

                # Decode type: high bit set means integer type
                type_name = ""
                if rt_type_id & 0x8000:
                    actual_type = rt_type_id & 0x7FFF
                else:
                    # Name offset relative to resource table start
                    name_addr = abs_rt + rt_type_id
                    name_len = data[name_addr]
                    type_name = data[name_addr + 1 : name_addr + 1 + name_len].decode("ascii", errors="replace")
                    actual_type = rt_type_id  # keep raw offset as type_id

                group = NEResourceTypeGroup(type_id=actual_type, type_name=type_name)

                for _j in range(rt_count):
                    rn_offset, rn_length, rn_flags, rn_id = struct.unpack_from(
                        "<HHHH", data, pos
                    )
                    # Skip rnReserved (4 bytes)
                    pos += 12

                    # Decode resource ID: high bit set means integer ID
                    if rn_id & 0x8000:
                        actual_id = rn_id & 0x7FFF
                    else:
                        actual_id = rn_id  # name offset

                    entry = NEResourceEntry(
                        type_id=actual_type,
                        res_id=actual_id,
                        file_offset=rn_offset << rsc_align_shift,
                        length=rn_length << rsc_align_shift,
                        flags=rn_flags,
                    )
                    group.entries.append(entry)

                hdr.resources.append(group)

        # Parse module reference table -> imported names
        abs_mod = ne_off + mod_ref_off
        abs_imp = ne_off + imp_name_off
        for i in range(num_module_refs):
            name_off = struct.unpack_from("<H", data, abs_mod + i * 2)[0]
            abs_name = abs_imp + name_off
            name_len = data[abs_name]
            name = data[abs_name + 1 : abs_name + 1 + name_len].decode("ascii")
            hdr.module_names.append(name)

        # Parse resident name table for module name
        abs_res = ne_off + res_name_off
        name_len = data[abs_res]
        if name_len > 0:
            hdr.module_name = data[abs_res + 1 : abs_res + 1 + name_len].decode(
                "ascii"
            )

        # Build name table: resolve string type names → integer type IDs
        # from the RT_NAMETABLE resource (type 15 / 0x800F).
        # Each entry: WORD length, WORD type_id, WORD res_id, then
        # null-terminated type name string followed by res name string.
        RT_NAMETABLE = 15
        nametab_entry = hdr.find_resource(RT_NAMETABLE, 1)
        if nametab_entry is not None:
            p = nametab_entry.file_offset
            end = p + nametab_entry.length
            while p + 6 <= end:
                entry_len = struct.unpack_from("<H", data, p)[0]
                if entry_len == 0:
                    break
                nt_type_id = struct.unpack_from("<H", data, p + 2)[0]
                # Extract null-terminated type name at p+6
                name_start = p + 6
                name_end = data.index(b"\x00", name_start, p + entry_len)
                tn = data[name_start:name_end].decode("ascii", errors="replace")
                if tn:
                    # Strip 0x8000 to match our stored group.type_id
                    hdr._name_table[tn.upper()] = nt_type_id & 0x7FFF
                p += entry_len

        return hdr


def parse_segment_relocations(
    data: bytes, seg: NESegmentEntry
) -> list[NERelocation]:
    """Parse the relocation table appended after a segment's data in the file."""
    if not seg.has_relocs:
        return []

    reloc_off = seg.file_offset + seg.length
    if reloc_off + 2 > len(data):
        return []

    num_relocs = struct.unpack_from("<H", data, reloc_off)[0]
    relocs = []
    for i in range(num_relocs):
        entry_off = reloc_off + 2 + i * 8
        if entry_off + 8 > len(data):
            break
        src_type = data[entry_off]
        rel_type = data[entry_off + 1]
        offset = struct.unpack_from("<H", data, entry_off + 2)[0]
        param1 = struct.unpack_from("<H", data, entry_off + 4)[0]
        param2 = struct.unpack_from("<H", data, entry_off + 6)[0]
        relocs.append(NERelocation(src_type, rel_type, offset, param1, param2))

    return relocs
