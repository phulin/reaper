"""SimTower NE executable emulator using Unicorn engine.

Loads the 16-bit NE binary into Unicorn in 16-bit protected mode
(UC_MODE_32 with a GDT of 16-bit descriptors). Each NE segment gets
its own GDT entry with the correct base and limit. Imported Win16 API
functions are stubbed out with `xor ax,ax; retf N` thunks.
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_32, Uc, UcError
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BP,
    UC_X86_REG_BX,
    UC_X86_REG_CR0,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EIP,
    UC_X86_REG_ES,
    UC_X86_REG_GDTR,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)

from simtower.ne_loader import (
    NEHeader,
    NERelocation,
    NESegmentEntry,
    parse_segment_relocations,
)
from simtower.stubs import StubDef, build_stub_lookup

log = logging.getLogger(__name__)

# ── Memory layout ────────────────────────────────────────────────────
# We place segments at linear addresses starting at LOAD_BASE, packed
# tightly. Each segment gets a GDT descriptor pointing to its linear
# base with the correct limit.
#
# GDT is at linear address GDT_ADDR.
# Selectors are allocated starting from FIRST_SELECTOR (0x08) upward,
# each spaced by 8 (the GDT entry size).

MEM_SIZE = 16 * 1024 * 1024  # 16 MiB address space
GDT_ADDR = 0x1000  # linear address of GDT
GDT_LIMIT = 0x1000  # 4 KiB = room for 512 descriptors
LOAD_BASE = 0x10_0000  # 1 MiB: linear base for NE segments
STUB_BASE = 0x80_0000  # 8 MiB: linear base for API stub thunks
FIRST_SELECTOR = 0x08  # first usable GDT selector (skip null)


def _gdt_entry(base: int, limit: int, access: int, flags_hi: int) -> bytes:
    """Build an 8-byte GDT descriptor.

    access:   P(1) DPL(2) S(1) Type(4) — e.g. 0x9A = code/readable, 0x92 = data/writable
    flags_hi: G(1) D/B(1) 0(1) AVL(1)  — upper nibble of byte 6
              For 16-bit segments: D=0. G=0 means limit is in bytes (up to 64K).
              G=1 means limit is in 4K pages.
    """
    entry = bytearray(8)
    # Limit bits 0-15
    entry[0] = limit & 0xFF
    entry[1] = (limit >> 8) & 0xFF
    # Base bits 0-23
    entry[2] = base & 0xFF
    entry[3] = (base >> 8) & 0xFF
    entry[4] = (base >> 16) & 0xFF
    # Access byte
    entry[5] = access
    # Limit bits 16-19 | flags
    entry[6] = ((limit >> 16) & 0x0F) | ((flags_hi & 0x0F) << 4)
    # Base bits 24-31
    entry[7] = (base >> 24) & 0xFF
    return bytes(entry)


class SimTowerEmulator:
    """Load and emulate SIMTOWER.EX_ (NE 16-bit) in Unicorn.

    Uses 16-bit protected mode: UC_MODE_32 with a GDT whose descriptors
    have D=0 (16-bit default operand/address size).
    """

    def __init__(self, exe_path: str | Path):
        self.exe_bytes = Path(exe_path).read_bytes()
        self.ne = NEHeader.parse(self.exe_bytes)

        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.mu.mem_map(0, MEM_SIZE)

        # GDT bookkeeping
        self._gdt = bytearray(GDT_LIMIT)
        self._next_selector = FIRST_SELECTOR  # next free selector index

        # NE segment index (1-based) -> GDT selector
        self.seg_selectors: dict[int, int] = {}
        # NE segment index (1-based) -> linear base address
        self.seg_bases: dict[int, int] = {}
        # GDT selector -> linear base (for all segments we create)
        self.selector_bases: dict[int, int] = {}

        # Stub tracking
        self.stub_addrs: dict[int, StubDef] = {}  # linear addr -> StubDef
        self.stub_locations: dict[
            tuple[str, int], tuple[int, int]
        ] = {}  # (mod, ord) -> (selector, offset)
        self._stub_selector: int = 0  # filled in by _build_stubs

        self._assign_segments()
        self._build_stubs()
        self._install_gdt()
        self._load_segments()
        self._apply_all_relocations()
        self._init_registers()
        self._install_hooks()

    # ── GDT management ───────────────────────────────────────────────

    def _alloc_selector(self, base: int, limit: int, *, code: bool) -> int:
        """Allocate a GDT descriptor and return its selector value.

        All descriptors are 16-bit (D=0, G=0 for limits ≤64K, G=1 otherwise).
        """
        sel = self._next_selector
        self._next_selector += 8

        if sel + 8 > GDT_LIMIT:
            raise RuntimeError("GDT full")

        # Access: Present | DPL=0 | S=1 | type
        # Code: Execute/Read = 0x9A, Data: Read/Write = 0x92
        access = 0x9A if code else 0x92

        # For limits > 0xFFFF, use granularity bit (G=1, limit in 4K pages)
        if limit > 0xFFFF:
            flags_hi = 0x8  # G=1, D=0
            gdt_limit = limit >> 12
        else:
            flags_hi = 0x0  # G=0, D=0
            gdt_limit = limit

        entry = _gdt_entry(base, gdt_limit, access, flags_hi)
        self._gdt[sel : sel + 8] = entry
        self.selector_bases[sel] = base
        return sel

    def _install_gdt(self) -> None:
        """Write the GDT to Unicorn memory and load GDTR."""
        self.mu.mem_write(GDT_ADDR, bytes(self._gdt))
        # GDTR: (unused, base, limit, unused)
        self.mu.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, GDT_LIMIT - 1, 0))

        # Enable protected mode
        cr0 = self.mu.reg_read(UC_X86_REG_CR0)
        self.mu.reg_write(UC_X86_REG_CR0, cr0 | 1)

    # ── Memory layout ────────────────────────────────────────────────

    def _assign_segments(self) -> None:
        """Assign linear addresses and GDT selectors to each NE segment."""
        linear = LOAD_BASE
        for seg in self.ne.segments:
            base = linear
            size = seg.alloc_size
            limit = size - 1 if size > 0 else 0

            is_code = seg.is_code
            sel = self._alloc_selector(base, limit, code=is_code)

            self.seg_selectors[seg.index] = sel
            self.seg_bases[seg.index] = base

            # Advance, 16-byte aligned
            linear += (size + 15) & ~15

        log.info(
            "Assigned %d segments: selectors 0x%02X..0x%02X, linear 0x%06X..0x%06X",
            len(self.ne.segments),
            FIRST_SELECTOR,
            self._next_selector - 8,
            LOAD_BASE,
            linear - 1,
        )

    def _build_stubs(self) -> None:
        """Create stub thunks for each imported API.

        All stubs live in a single 16-bit code segment at STUB_BASE.
        Each thunk is:
            xor ax, ax      ; 31 C0  (2 bytes) — return 0
            retf <N>         ; CA <lo> <hi>      (3 bytes) — Pascal pop
        or for cdecl (N=0):
            xor ax, ax      ; 31 C0
            retf             ; CB               (1 byte)
        """
        lookup = build_stub_lookup()
        offset = 0

        for key, stub in lookup.items():
            addr = STUB_BASE + offset
            self.stub_locations[key] = (0, offset)  # selector filled in below
            self.stub_addrs[addr] = stub

            code = bytearray()
            code += b"\x31\xc0"  # xor ax, ax
            if stub.param_bytes > 0:
                code += b"\xca"
                code += struct.pack("<H", stub.param_bytes)
            else:
                code += b"\xcb"
            self.mu.mem_write(addr, bytes(code))
            offset += len(code)

        # Create a code selector covering the whole stub region
        stub_limit = max(offset - 1, 0)
        self._stub_selector = self._alloc_selector(STUB_BASE, stub_limit, code=True)

        # Patch stub_locations with the real selector
        for key in self.stub_locations:
            _, off = self.stub_locations[key]
            self.stub_locations[key] = (self._stub_selector, off)

        log.info(
            "Built %d API stubs at linear 0x%06X, selector 0x%02X",
            len(lookup),
            STUB_BASE,
            self._stub_selector,
        )

    # ── Segment loading ──────────────────────────────────────────────

    def _load_segments(self) -> None:
        """Load all segment data from the EXE file into Unicorn memory."""
        for seg in self.ne.segments:
            base = self.seg_bases[seg.index]

            if seg.file_offset and seg.length:
                data = self.exe_bytes[seg.file_offset : seg.file_offset + seg.length]
                self.mu.mem_write(base, data)

            # Zero-fill remaining allocation
            remaining = seg.alloc_size - seg.length
            if remaining > 0:
                self.mu.mem_write(base + seg.length, b"\x00" * remaining)

        log.info("Loaded %d segments into memory", len(self.ne.segments))

    # ── Relocations ──────────────────────────────────────────────────

    def _apply_all_relocations(self) -> None:
        """Parse and apply relocations for every segment."""
        total = 0
        for seg in self.ne.segments:
            relocs = parse_segment_relocations(self.exe_bytes, seg)
            for reloc in relocs:
                self._apply_relocation(seg, reloc)
            total += len(relocs)
        log.info(
            "Applied %d relocations across %d segments", total, len(self.ne.segments)
        )

    def _apply_relocation(self, seg: NESegmentEntry, reloc: NERelocation) -> None:
        """Apply a single relocation entry within a segment."""
        seg_base = self.seg_bases[seg.index]

        kind = reloc.kind

        if kind == NERelocation.INTERNAL:
            self._apply_internal_reloc(seg_base, reloc)
        elif kind == NERelocation.IMPORTED_ORDINAL:
            self._apply_import_ordinal_reloc(seg_base, reloc)
        elif kind == NERelocation.OSFIXUP:
            self._apply_osfixup(seg_base, seg, reloc)
        elif kind == NERelocation.IMPORTED_NAME:
            log.warning(
                "IMPORTED_NAME relocation not implemented (offset=0x%04X)", reloc.offset
            )
        else:
            log.warning(
                "Unknown relocation kind %d at offset 0x%04X", kind, reloc.offset
            )

    def _resolve_target(self, reloc: NERelocation) -> tuple[int, int] | None:
        """Resolve a relocation target to (selector, offset)."""
        kind = reloc.kind

        if kind == NERelocation.INTERNAL:
            target_seg_idx = reloc.param1 & 0xFF  # low byte is segment number
            target_offset = reloc.param2
            if target_seg_idx == 0:
                # Moveable segment — param2 is entry ordinal. Skip for now.
                return None
            sel = self.seg_selectors.get(target_seg_idx)
            if sel is None:
                return None
            return (sel, target_offset)

        if kind == NERelocation.IMPORTED_ORDINAL:
            mod_idx = reloc.param1 - 1  # 1-based -> 0-based
            ordinal = reloc.param2
            if mod_idx < 0 or mod_idx >= len(self.ne.module_names):
                return None
            mod_name = self.ne.module_names[mod_idx]
            key = (mod_name, ordinal)
            loc = self.stub_locations.get(key)
            if loc is None:
                raise KeyError(f"No stub for {mod_name} ordinal {ordinal}")
            return loc

        return None

    def _patch_chain(
        self,
        seg_base: int,
        reloc: NERelocation,
        target_sel: int,
        target_off: int,
    ) -> None:
        """Patch a chained relocation (non-additive).

        NE non-additive relocations form a linked list: the WORD at each
        patch site contains the offset of the NEXT site. Ends with 0xFFFF.
        """
        offset = reloc.offset
        visited = set()

        while offset != 0xFFFF and offset not in visited:
            visited.add(offset)
            addr = seg_base + offset

            # Read the next-in-chain pointer before we overwrite
            next_offset = struct.unpack("<H", self.mu.mem_read(addr, 2))[0]

            self._write_fixup(addr, reloc.src_type, target_sel, target_off)
            offset = next_offset

    def _write_fixup(
        self,
        addr: int,
        src_type: int,
        target_sel: int,
        target_off: int,
    ) -> None:
        """Write the actual fixup bytes at the given address."""
        if src_type == NERelocation.SRC_FAR32:
            # 32-bit far pointer: offset (WORD) then selector (WORD)
            self.mu.mem_write(addr, struct.pack("<HH", target_off, target_sel))
        elif src_type == NERelocation.SRC_OFF16:
            self.mu.mem_write(addr, struct.pack("<H", target_off))
        elif src_type == NERelocation.SRC_SEG16:
            self.mu.mem_write(addr, struct.pack("<H", target_sel))
        elif src_type == NERelocation.SRC_LOBYTE:
            self.mu.mem_write(addr, struct.pack("<B", target_off & 0xFF))
        else:
            log.warning("Unknown src_type %d at addr 0x%05X", src_type, addr)

    def _apply_internal_reloc(self, seg_base: int, reloc: NERelocation) -> None:
        target = self._resolve_target(reloc)
        if target is None:
            return
        target_sel, target_off = target

        if reloc.is_additive:
            self._write_fixup(
                seg_base + reloc.offset, reloc.src_type, target_sel, target_off
            )
        else:
            self._patch_chain(seg_base, reloc, target_sel, target_off)

    def _apply_import_ordinal_reloc(self, seg_base: int, reloc: NERelocation) -> None:
        target = self._resolve_target(reloc)
        if target is None:
            return
        target_sel, target_off = target

        if reloc.is_additive:
            self._write_fixup(
                seg_base + reloc.offset, reloc.src_type, target_sel, target_off
            )
        else:
            self._patch_chain(seg_base, reloc, target_sel, target_off)

    def _apply_osfixup(
        self, seg_base: int, seg: NESegmentEntry, reloc: NERelocation
    ) -> None:
        """Handle OS fixup relocations.

        Type 5 (DGROUP): patch in the automatic data segment selector.
        Types 1-4, 6: FP emulation fixups — leave as-is for now.
        """
        fixup_type = reloc.param1

        if fixup_type == 5:
            # DGROUP fixup — write the DGROUP selector
            dgroup_sel = self.seg_selectors.get(self.ne.auto_data_seg, 0)
            if reloc.is_additive:
                self._write_fixup(
                    seg_base + reloc.offset, reloc.src_type, dgroup_sel, 0
                )
            else:
                self._patch_chain(seg_base, reloc, dgroup_sel, 0)
        else:
            # FP emulation fixups (types 1-4, 6) — leave bytes as-is
            pass

    # ── Register init ────────────────────────────────────────────────

    def _init_registers(self) -> None:
        """Set initial register state for the NE entry point."""
        cs_sel = self.seg_selectors[self.ne.entry_cs]
        ss_sel = self.seg_selectors[self.ne.stack_ss]
        dgroup_sel = self.seg_selectors.get(self.ne.auto_data_seg, ss_sel)

        self.mu.reg_write(UC_X86_REG_CS, cs_sel)
        self.mu.reg_write(UC_X86_REG_EIP, self.ne.entry_ip)
        self.mu.reg_write(UC_X86_REG_SS, ss_sel)
        self.mu.reg_write(UC_X86_REG_SP, self.ne.stack_sp or 0xFFFE)
        self.mu.reg_write(UC_X86_REG_DS, dgroup_sel)
        self.mu.reg_write(UC_X86_REG_ES, dgroup_sel)

        # Win16 InitTask register conventions
        self.mu.reg_write(UC_X86_REG_AX, dgroup_sel)
        self.mu.reg_write(UC_X86_REG_BX, self.ne.stack_sp or 0x1000)
        self.mu.reg_write(UC_X86_REG_CX, 0x1000)  # heap size
        self.mu.reg_write(UC_X86_REG_DI, dgroup_sel)  # instance handle
        self.mu.reg_write(UC_X86_REG_SI, 0)  # previous instance
        self.mu.reg_write(UC_X86_REG_BP, 0)
        self.mu.reg_write(UC_X86_REG_DX, 0)

        log.info(
            "Registers: CS=%04X IP=%04X SS=%04X SP=%04X DS=%04X",
            cs_sel,
            self.ne.entry_ip,
            ss_sel,
            self.ne.stack_sp or 0xFFFE,
            dgroup_sel,
        )

    # ── Hooks ────────────────────────────────────────────────────────

    def _install_hooks(self) -> None:
        """Install Unicorn hooks for monitoring and stub handling."""
        stub_end = STUB_BASE + 0x10000
        self.mu.hook_add(
            UC_HOOK_CODE,
            self._on_stub_execute,
            begin=STUB_BASE,
            end=stub_end,
        )

    def _on_stub_execute(self, mu: Uc, address: int, size: int, _user_data) -> None:
        """Called when execution enters the stub region.

        In protected mode, Unicorn reports the linear address
        (CS.base + EIP) to code hooks.
        """
        stub = self.stub_addrs.get(address)
        if stub is not None:
            log.debug(
                "STUB CALL: %s.%s (ordinal %d, param_bytes=%d)",
                stub.module,
                stub.name,
                stub.ordinal,
                stub.param_bytes,
            )

    # ── Execution ────────────────────────────────────────────────────

    def run(self, max_instructions: int = 10_000_000) -> None:
        """Start emulation from the entry point.

        In protected mode, emu_start sets EIP directly (not linear address).
        We pass the segment offset; CS base is applied by the CPU.
        """
        cs_sel = self.mu.reg_read(UC_X86_REG_CS)
        eip = self.mu.reg_read(UC_X86_REG_EIP)
        cs_base = self.selector_bases.get(cs_sel, 0)

        log.info(
            "Starting emulation at %04X:%04X (linear 0x%06X)",
            cs_sel,
            eip,
            cs_base + eip,
        )

        try:
            self.mu.emu_start(eip, 0xFFFF, count=max_instructions)
        except UcError as e:
            cs_sel = self.mu.reg_read(UC_X86_REG_CS)
            eip = self.mu.reg_read(UC_X86_REG_EIP)
            log.error("Unicorn error at %04X:%04X: %s", cs_sel, eip, e)
            raise RuntimeError(f"Emulation error at {cs_sel:04X}:{eip:04X}: {e}") from e

    def dump_regs(self) -> str:
        """Return a formatted string of current register state."""
        regs = {
            "AX": UC_X86_REG_AX,
            "BX": UC_X86_REG_BX,
            "CX": UC_X86_REG_CX,
            "DX": UC_X86_REG_DX,
            "SI": UC_X86_REG_SI,
            "DI": UC_X86_REG_DI,
            "SP": UC_X86_REG_SP,
            "BP": UC_X86_REG_BP,
            "CS": UC_X86_REG_CS,
            "DS": UC_X86_REG_DS,
            "ES": UC_X86_REG_ES,
            "SS": UC_X86_REG_SS,
        }
        parts = []
        for name, reg in regs.items():
            val = self.mu.reg_read(reg)
            parts.append(f"{name}={val:04X}")
        return " ".join(parts)


def main() -> None:
    import sys

    logging.basicConfig(
        level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s"
    )

    exe_path = sys.argv[1] if len(sys.argv) > 1 else "src/simtower/SIMTOWER.EXE"
    emu = SimTowerEmulator(exe_path)
    print(f"Initial registers: {emu.dump_regs()}")

    try:
        emu.run(max_instructions=100_000)
    except RuntimeError as e:
        print(f"Stopped: {e}")

    print(f"Final registers: {emu.dump_regs()}")


if __name__ == "__main__":
    main()
