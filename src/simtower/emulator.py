"""SimTower NE executable emulator using Unicorn engine.

Loads the 16-bit NE binary into Unicorn in 16-bit protected mode
(UC_MODE_32 with a GDT of 16-bit descriptors). Each NE segment gets
its own GDT entry with the correct base and limit. Imported Win16 API
functions are stubbed with `retf N` thunks; a code hook sets return
values (default AX=0) and dispatches to Python handlers for functions
that need real behaviour (GlobalAlloc, GlobalLock, etc.).
"""

from __future__ import annotations

import json
import logging
import struct
from collections import defaultdict
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INTR, UC_MODE_32, Uc, UcError
from unicorn.x86_const import (
    UC_X86_REG_AH,
    UC_X86_REG_AL,
    UC_X86_REG_AX,
    UC_X86_REG_BP,
    UC_X86_REG_BX,
    UC_X86_REG_CR0,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_EIP,
    UC_X86_REG_ES,
    UC_X86_REG_GDTR,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)

from simtower.constants import (
    CALL_TRAP_BASE,
    DS_OFF,
    FACILITY_WIDTHS,
    FAMILY_NAMES,
    FIRST_SELECTOR,
    GDT_ADDR,
    GDT_LIMIT,
    LOAD_BASE,
    MEM_SIZE,
    OBJ_STRIDE,
    PLACE_OBJ_NE_SEG,
    PLACE_OBJ_OFFSET,
    PLACE_STAIRS_NE_SEG,
    PLACE_STAIRS_OFFSET,
    SCHEDULER_NE_SEG,
    SCHEDULER_SEG_OFFSET,
    SIM_REC_SIZE,
    SIM_STATE_NAMES,
    STUB_BASE,
    StubHandler,
    _gdt_entry,
)
from simtower.heap import GlobalHeap
from simtower.ne_loader import (
    NEHeader,
    NERelocation,
    NEResourceEntry,
    NESegmentEntry,
    parse_segment_relocations,
)
from simtower.stub_handlers import STUB_HANDLERS
from simtower.stubs import StubDef, build_stub_lookup

log = logging.getLogger(__name__)

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
        self._next_selector = FIRST_SELECTOR

        # NE segment index (1-based) -> GDT selector
        self.seg_selectors: dict[int, int] = {}
        # NE segment index (1-based) -> linear base address
        self.seg_bases: dict[int, int] = {}
        # GDT selector -> linear base (for all segments we create)
        self.selector_bases: dict[int, int] = {}

        # Stub tracking
        self.stub_addrs: dict[int, StubDef] = {}  # linear addr -> StubDef
        self.stub_locations: dict[tuple[str, int], tuple[int, int]] = {}
        self._stub_selector: int = 0

        # Heap
        self.heap = GlobalHeap()

        # Resource tracking
        self._resource_handles: dict[int, NEResourceEntry] = {}  # handle -> entry
        self._loaded_resources: dict[int, int] = {}  # find_handle -> heap_handle
        self._next_resource_handle: int = 0x3000

        # Handle counters for fake GDI/USER objects
        self._next_handle: int = 0x2000
        self._next_atom: int = 0xC000
        self._next_hwnd: int = 0x100
        self._tick_count: int = 0
        self._show_sims: bool = False
        self._output_json: bool = False
        self._build_spec: dict | None = None

        # Handler dispatch: linear stub addr -> handler function
        self._stub_handlers: dict[int, StubHandler] = {}

        # Call trap for call_far_pascal: a tiny code segment with HLT
        self._call_trap_hit = False

        self._assign_segments()
        self._build_stubs()
        self._setup_call_trap()
        self._install_gdt()
        self._load_segments()
        self._apply_all_relocations()
        self._init_registers()
        self._install_hooks()

    # ── Resource tracking ──────────────────────────────────────────────

    def _register_resource(self, entry: NEResourceEntry) -> int:
        """Register a resource entry and return a synthetic handle."""
        handle = self._next_resource_handle
        self._next_resource_handle += 1
        self._resource_handles[handle] = entry
        return handle

    # ── GDT management ───────────────────────────────────────────────

    def _alloc_selector(self, base: int, limit: int, *, code: bool) -> int:
        """Allocate a GDT descriptor and return its selector value."""
        sel = self._next_selector
        self._next_selector += 8

        if sel + 8 > GDT_LIMIT:
            raise RuntimeError("GDT full")

        access = 0x9A if code else 0x92
        if limit > 0xFFFF:
            flags_hi = 0x8  # G=1, D=0
            gdt_limit = limit >> 12
        else:
            flags_hi = 0x0  # G=0, D=0
            gdt_limit = limit

        entry = _gdt_entry(base, gdt_limit, access, flags_hi)
        self._gdt[sel : sel + 8] = entry
        self.selector_bases[sel] = base

        # If GDT is already installed, update it live
        if self.mu.reg_read(UC_X86_REG_CR0) & 1:
            self.mu.mem_write(GDT_ADDR + sel, entry)

        return sel

    def _install_gdt(self) -> None:
        """Write the GDT to Unicorn memory and load GDTR."""
        self.mu.mem_write(GDT_ADDR, bytes(self._gdt))
        self.mu.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, GDT_LIMIT - 1, 0))
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

            sel = self._alloc_selector(base, limit, code=seg.is_code)
            self.seg_selectors[seg.index] = sel
            self.seg_bases[seg.index] = base

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

        Each thunk is just `retf N` (or `retf` for cdecl). The code hook
        sets AX=0 by default and dispatches to Python handlers for stubs
        that need real behaviour.
        """
        lookup = build_stub_lookup()
        offset = 0

        for key, stub in lookup.items():
            addr = STUB_BASE + offset
            self.stub_locations[key] = (0, offset)  # selector patched below
            self.stub_addrs[addr] = stub

            # Register handler if one exists
            handler = STUB_HANDLERS.get(key)
            if handler is not None:
                self._stub_handlers[addr] = handler

            code = bytearray()
            if stub.param_bytes > 0:
                code += b"\xca"
                code += struct.pack("<H", stub.param_bytes)
            else:
                code += b"\xcb"
            self.mu.mem_write(addr, bytes(code))
            offset += len(code)

        # Code selector for stubs
        stub_limit = max(offset - 1, 0)
        self._stub_selector = self._alloc_selector(STUB_BASE, stub_limit, code=True)

        for key in self.stub_locations:
            _, off = self.stub_locations[key]
            self.stub_locations[key] = (self._stub_selector, off)

        log.info(
            "Built %d API stubs (%d with handlers) at selector 0x%02X",
            len(lookup),
            len(self._stub_handlers),
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
            remaining = seg.alloc_size - seg.length
            if remaining > 0:
                self.mu.mem_write(base + seg.length, b"\x00" * remaining)
        log.info("Loaded %d segments into memory", len(self.ne.segments))

    # ── Relocations ──────────────────────────────────────────────────

    def _apply_all_relocations(self) -> None:
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
            target_seg_idx = reloc.param1 & 0xFF
            target_offset = reloc.param2
            if target_seg_idx == 0:
                return None
            sel = self.seg_selectors.get(target_seg_idx)
            if sel is None:
                return None
            return (sel, target_offset)

        if kind == NERelocation.IMPORTED_ORDINAL:
            mod_idx = reloc.param1 - 1
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
        self, seg_base: int, reloc: NERelocation, target_sel: int, target_off: int
    ) -> None:
        offset = reloc.offset
        visited = set()
        while offset != 0xFFFF and offset not in visited:
            visited.add(offset)
            addr = seg_base + offset
            next_offset = struct.unpack("<H", self.mu.mem_read(addr, 2))[0]
            self._write_fixup(addr, reloc.src_type, target_sel, target_off)
            offset = next_offset

    def _write_fixup(
        self, addr: int, src_type: int, target_sel: int, target_off: int
    ) -> None:
        if src_type == NERelocation.SRC_FAR32:
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
        fixup_type = reloc.param1
        if fixup_type == 5:
            dgroup_sel = self.seg_selectors.get(self.ne.auto_data_seg, 0)
            # OSFIXUP DGROUP: write the selector value to the target.
            # For SRC_OFF16, the "offset" to write IS the selector value
            # (OSFIXUP semantics differ from INTERNAL — it's always the selector).
            if reloc.is_additive:
                self._write_fixup(
                    seg_base + reloc.offset, reloc.src_type, dgroup_sel, dgroup_sel
                )
            else:
                self._patch_chain(seg_base, reloc, dgroup_sel, dgroup_sel)

    # ── Register init ────────────────────────────────────────────────

    def _init_registers(self) -> None:
        cs_sel = self.seg_selectors[self.ne.entry_cs]
        ss_sel = self.seg_selectors[self.ne.stack_ss]
        dgroup_sel = self.seg_selectors.get(self.ne.auto_data_seg, ss_sel)

        self.mu.reg_write(UC_X86_REG_CS, cs_sel)
        self.mu.reg_write(UC_X86_REG_EIP, self.ne.entry_ip)
        self.mu.reg_write(UC_X86_REG_SS, ss_sel)
        self.mu.reg_write(UC_X86_REG_SP, self.ne.stack_sp or 0xFFFE)
        self.mu.reg_write(UC_X86_REG_DS, dgroup_sel)
        self.mu.reg_write(UC_X86_REG_ES, dgroup_sel)

        self.mu.reg_write(UC_X86_REG_AX, dgroup_sel)
        self.mu.reg_write(UC_X86_REG_BX, self.ne.stack_sp or 0x1000)
        self.mu.reg_write(UC_X86_REG_CX, 0x1000)
        self.mu.reg_write(UC_X86_REG_DI, dgroup_sel)
        self.mu.reg_write(UC_X86_REG_SI, 0)
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

    # ── Call trap (for call_far_pascal) ────────────────────────────

    def _setup_call_trap(self) -> None:
        """Set up return traps for both far and near call_* methods."""
        # Far call trap: a small code segment with HLT
        self._call_trap_sel = self._alloc_selector(CALL_TRAP_BASE, 15, code=True)
        self.mu.mem_write(CALL_TRAP_BASE, b"\xf4")

        self._call_trap_hit = False
        # Per-segment near-call trap offsets: seg_index -> offset of HLT within that segment
        self._near_trap_offsets: dict[int, int] = {}

    def _ensure_near_trap(self, ne_seg: int) -> int:
        """Ensure a HLT trap exists just past the code in NE segment ne_seg.

        Extends the GDT limit if necessary. Returns the trap's offset within
        the segment.
        """
        if ne_seg in self._near_trap_offsets:
            return self._near_trap_offsets[ne_seg]

        seg = self.ne.segments[ne_seg - 1]
        trap_offset = seg.alloc_size  # first byte past original code
        sel = self.seg_selectors[ne_seg]
        seg_base = self.seg_bases[ne_seg]

        # Extend the GDT limit to cover the trap byte
        new_limit = trap_offset  # limit = last valid offset = trap_offset
        access = 0x9A  # code, present, DPL=0
        flags_hi = 0x0  # 16-bit, byte granularity
        entry = _gdt_entry(seg_base, new_limit, access, flags_hi)
        self._gdt[sel : sel + 8] = entry
        self.mu.mem_write(GDT_ADDR + sel, entry)

        # Write HLT at the trap offset
        self.mu.mem_write(seg_base + trap_offset, b"\xf4")

        # Install a code hook for this specific address
        trap_linear = seg_base + trap_offset
        self.mu.hook_add(
            UC_HOOK_CODE,
            self._on_call_trap,
            begin=trap_linear,
            end=trap_linear + 1,
        )

        self._near_trap_offsets[ne_seg] = trap_offset
        log.debug(
            "Near trap for seg %d at offset 0x%04X (linear 0x%06X)",
            ne_seg,
            trap_offset,
            trap_linear,
        )
        return trap_offset

    def _on_call_trap(self, mu: Uc, address: int, size: int, _user_data) -> None:
        """Code hook: fires when execution reaches a call trap (function returned)."""
        self._call_trap_hit = True
        mu.emu_stop()

    # ── Hooks ────────────────────────────────────────────────────────

    def _install_hooks(self) -> None:
        stub_end = STUB_BASE + 0x10000
        self.mu.hook_add(
            UC_HOOK_CODE, self._on_stub_execute, begin=STUB_BASE, end=stub_end
        )
        self.mu.hook_add(UC_HOOK_INTR, self._on_interrupt)
        # Far call trap hook (for call_far_pascal return detection)
        self.mu.hook_add(
            UC_HOOK_CODE,
            self._on_call_trap,
            begin=CALL_TRAP_BASE,
            end=CALL_TRAP_BASE + 1,
        )
        # Trace hook for debugging — keeps a ring buffer of recent instructions
        self._trace_buf: list[tuple[int, int, int]] = []  # (cs, ip, size)
        # self.mu.hook_add(UC_HOOK_CODE, self._on_trace)

    def _handle_dpmi(self, mu: Uc) -> None:
        """Handle INT 31h (DPMI) calls."""
        ax = mu.reg_read(UC_X86_REG_AX)
        if ax == 0x0000:
            # Allocate LDT descriptors — CX = count
            # Return AX = first selector
            cx = mu.reg_read(UC_X86_REG_CX)
            sel = self._alloc_selector(0, 0, code=False)
            for _ in range(cx - 1):
                self._alloc_selector(0, 0, code=False)
            mu.reg_write(UC_X86_REG_AX, sel)
            log.debug("DPMI 0000h: AllocLDT(%d) -> sel=0x%04X", cx, sel)
        elif ax == 0x0001:
            # Free LDT descriptor — BX = selector
            log.debug("DPMI 0001h: FreeLDT(0x%04X) -> ok", mu.reg_read(UC_X86_REG_BX))
        elif ax == 0x0006:
            # Get Segment Base Address — BX = selector
            bx = mu.reg_read(UC_X86_REG_BX)
            base = self.selector_bases.get(bx, 0)
            mu.reg_write(UC_X86_REG_CX, (base >> 16) & 0xFFFF)
            mu.reg_write(UC_X86_REG_DX, base & 0xFFFF)
            log.debug("DPMI 0006h: GetSegBase(0x%04X) -> 0x%08X", bx, base)
        elif ax == 0x0007:
            # Set Segment Base Address — BX=selector, CX:DX=base
            bx = mu.reg_read(UC_X86_REG_BX)
            cx = mu.reg_read(UC_X86_REG_CX)
            dx = mu.reg_read(UC_X86_REG_DX)
            new_base = (cx << 16) | dx
            self.selector_bases[bx] = new_base
            # Update GDT entry
            access = 0x92  # data segment
            entry = _gdt_entry(new_base, 0xFFFF, access, 0x0)
            self._gdt[bx : bx + 8] = entry
            mu.mem_write(GDT_ADDR + bx, entry)
            log.debug("DPMI 0007h: SetSegBase(0x%04X, 0x%08X)", bx, new_base)
        elif ax == 0x0008:
            # Set Segment Limit — BX=selector, CX:DX=limit
            bx = mu.reg_read(UC_X86_REG_BX)
            cx = mu.reg_read(UC_X86_REG_CX)
            dx = mu.reg_read(UC_X86_REG_DX)
            limit = (cx << 16) | dx
            base = self.selector_bases.get(bx, 0)
            access = 0x92
            if limit > 0xFFFF:
                flags_hi = 0x8  # G=1
                gdt_limit = limit >> 12
            else:
                flags_hi = 0x0
                gdt_limit = limit
            entry = _gdt_entry(base, gdt_limit, access, flags_hi)
            self._gdt[bx : bx + 8] = entry
            mu.mem_write(GDT_ADDR + bx, entry)
            log.debug("DPMI 0008h: SetSegLimit(0x%04X, 0x%08X)", bx, limit)
        elif ax == 0x0009:
            # Set Descriptor Access Rights — BX=selector, CL=access, CH=flags_hi
            bx = mu.reg_read(UC_X86_REG_BX)
            cx = mu.reg_read(UC_X86_REG_CX)
            log.debug("DPMI 0009h: SetDescRights(0x%04X, 0x%04X) -> ok", bx, cx)
        elif ax == 0x000A:
            # Get Descriptor — BX=selector, ES:DI=8-byte buffer to write to
            bx = mu.reg_read(UC_X86_REG_BX)
            es = mu.reg_read(UC_X86_REG_ES)
            di = mu.reg_read(UC_X86_REG_DI)
            es_base = self.selector_bases.get(es, 0)
            desc = bytes(self._gdt[bx : bx + 8])
            mu.mem_write(es_base + di, desc)
            base_val = desc[2] | (desc[3] << 8) | (desc[4] << 16) | (desc[7] << 24)
            log.debug(
                "DPMI 000Ah: GetDescriptor(sel=0x%04X) -> base=0x%08X", bx, base_val
            )
        elif ax == 0x000B:
            # Set Descriptor — BX=selector, ES:DI -> 8-byte descriptor
            bx = mu.reg_read(UC_X86_REG_BX)
            es = mu.reg_read(UC_X86_REG_ES)
            di = mu.reg_read(UC_X86_REG_DI)
            cs = mu.reg_read(UC_X86_REG_CS)
            es_base = self.selector_bases.get(es, 0)

            # Borland USE32 thunk: SetDescriptor on current CS is part of a
            # thunk that switches the code segment to 32-bit (D=1).  The thunk
            # reads from an uninitialized stack buffer (which on real hardware
            # would hold a copy of the current descriptor), ORs the D bit, and
            # loops until the mode switch takes effect via DPMI IRET.  We
            # short-circuit: write the current descriptor with D=1 set, then
            # reload CS so the mode switch happens immediately.
            if bx == cs:
                current_desc = bytearray(self._gdt[bx : bx + 8])
                current_desc[6] |= 0x40  # Set D bit (32-bit default operand size)
                desc = bytes(current_desc)
                # Write modified descriptor to buffer so the thunk code sees it
                mu.mem_write(es_base + di, desc)
            else:
                desc = bytes(mu.mem_read(es_base + di, 8))

            # Write descriptor to GDT
            self._gdt[bx : bx + 8] = desc
            mu.mem_write(GDT_ADDR + bx, desc)
            # Update base cache
            base = desc[2] | (desc[3] << 8) | (desc[4] << 16) | (desc[7] << 24)
            self.selector_bases[bx] = base
            limit = desc[0] | (desc[1] << 8) | ((desc[6] & 0x0F) << 16)
            log.debug(
                "DPMI 000Bh: SetDescriptor(sel=0x%04X, base=0x%08X, limit=0x%05X, ES:DI=%04X:%04X, bytes=%s)",
                bx,
                base,
                limit,
                es,
                di,
                desc.hex(),
            )
            # Reload segment registers that use this selector so the CPU
            # picks up the new descriptor (simulates IRET after DPMI call).
            for reg in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
                if mu.reg_read(reg) == bx:
                    mu.reg_write(reg, bx)
        elif ax == 0x000C:
            # Create Alias Descriptor — BX = selector
            bx = mu.reg_read(UC_X86_REG_BX)
            base = self.selector_bases.get(bx, 0)
            # Copy the full descriptor from the source selector
            src_desc = bytes(self._gdt[bx : bx + 8])
            new_sel = self._next_selector
            self._next_selector += 8
            if new_sel + 8 > GDT_LIMIT:
                log.error("GDT full in DPMI CreateAlias")
                mu.emu_stop()
                return
            self._gdt[new_sel : new_sel + 8] = src_desc
            mu.mem_write(GDT_ADDR + new_sel, src_desc)
            self.selector_bases[new_sel] = base
            mu.reg_write(UC_X86_REG_AX, new_sel)
            log.debug(
                "DPMI 000Ch: CreateAlias(0x%04X) -> 0x%04X (base=0x%08X)",
                bx,
                new_sel,
                base,
            )
        elif ax == 0x0501:
            # Allocate Memory Block — BX:CX = size
            bx = mu.reg_read(UC_X86_REG_BX)
            cx = mu.reg_read(UC_X86_REG_CX)
            size = (bx << 16) | cx
            linear = self.heap._next_linear
            linear = (linear + 15) & ~15
            self.heap._next_linear = linear + size
            mu.reg_write(UC_X86_REG_BX, (linear >> 16) & 0xFFFF)
            mu.reg_write(UC_X86_REG_CX, linear & 0xFFFF)
            mu.reg_write(UC_X86_REG_SI, (linear >> 16) & 0xFFFF)  # handle
            mu.reg_write(UC_X86_REG_DI, linear & 0xFFFF)
            log.debug("DPMI 0501h: AllocMem(%d) -> 0x%08X", size, linear)
        else:
            cs = mu.reg_read(UC_X86_REG_CS)
            eip = mu.reg_read(UC_X86_REG_EIP)
            log.warning("Unhandled DPMI AX=%04Xh at %04X:%04X", ax, cs, eip)
            mu.emu_stop()
            return
        # Clear carry flag to indicate success (DPMI convention)
        eflags = mu.reg_read(UC_X86_REG_EFLAGS)
        mu.reg_write(UC_X86_REG_EFLAGS, eflags & ~1)  # clear CF

    def _on_trace(self, mu: Uc, address: int, size: int, _user_data) -> None:
        cs = mu.reg_read(UC_X86_REG_CS)
        eip = mu.reg_read(UC_X86_REG_EIP)
        self._trace_buf.append((cs, eip, size))
        if len(self._trace_buf) > 50:
            self._trace_buf.pop(0)
        pass  # trace collection only (for _dump_trace)

    def _dump_trace(self) -> None:
        """Print the last N instructions from the trace buffer."""
        for cs, eip, size in self._trace_buf[-20:]:
            base = self.selector_bases.get(cs, 0)
            code = bytes(self.mu.mem_read(base + eip, min(size, 8)))
            log.info("  TRACE %04X:%04X [%s]", cs, eip, code.hex())

    def _on_interrupt(self, mu: Uc, intno: int, _user_data) -> None:
        """Handle software interrupts (INT N)."""
        if intno == 0x21:
            ah = mu.reg_read(UC_X86_REG_AH)
            if ah == 0x4C:
                # DOS terminate — exit code in AL
                exit_code = mu.reg_read(UC_X86_REG_AL)
                cs = mu.reg_read(UC_X86_REG_CS)
                eip = mu.reg_read(UC_X86_REG_EIP)
                log.info(
                    "INT 21h/4Ch: DOS terminate (exit code %d) at %04X:%04X",
                    exit_code,
                    cs,
                    eip,
                )
                mu.emu_stop()
            elif ah == 0x30:
                # GetVersion: AL=major, AH=minor (report DOS 5.0)
                mu.reg_write(UC_X86_REG_AX, 0x0005)  # DOS 5.0
                mu.reg_write(UC_X86_REG_BX, 0x0000)
                mu.reg_write(UC_X86_REG_CX, 0x0000)
                log.debug("INT 21h/30h: GetVersion -> 5.0")
            elif ah == 0x35:
                # Get interrupt vector: AL=int number -> ES:BX=handler
                # Return a null pointer (no handler installed)
                mu.reg_write(UC_X86_REG_BX, 0)
                log.debug(
                    "INT 21h/35h: GetInterruptVector(%02Xh) -> 0:0",
                    mu.reg_read(UC_X86_REG_AL),
                )
            elif ah == 0x25:
                # Set interrupt vector — ignore
                log.debug(
                    "INT 21h/25h: SetInterruptVector(%02Xh) -> no-op",
                    mu.reg_read(UC_X86_REG_AL),
                )
            elif ah == 0x44:
                # IOCTL — subfunction in AL
                al = mu.reg_read(UC_X86_REG_AL)
                if al == 0x00:
                    # Get device info for handle in BX
                    # Return DX=0x80 (character device) for stdin/stdout/stderr
                    bx = mu.reg_read(UC_X86_REG_BX)
                    if bx <= 2:
                        mu.reg_write(UC_X86_REG_DX, 0x80D3)  # char device, not EOF
                    else:
                        mu.reg_write(UC_X86_REG_DX, 0x0000)  # disk file
                    mu.reg_write(UC_X86_REG_AX, mu.reg_read(UC_X86_REG_DX))
                    log.debug(
                        "INT 21h/4400h: IOCTL GetDevInfo(handle=%d) -> DX=%04X",
                        bx,
                        mu.reg_read(UC_X86_REG_DX),
                    )
                else:
                    log.debug("INT 21h/44%02Xh: IOCTL subfn %02Xh -> no-op", al, al)
            elif ah == 0x48:
                # Allocate memory — BX=paragraphs requested
                # Return AX=segment (just return a fake value; not really used in Win16)
                mu.reg_write(UC_X86_REG_AX, 0x1000)
                log.debug("INT 21h/48h: AllocMem -> AX=0x1000")
            elif ah == 0x1A:
                # Set DTA (Disk Transfer Area) — DS:DX
                log.debug("INT 21h/1Ah: SetDTA -> no-op")
            else:
                cs = mu.reg_read(UC_X86_REG_CS)
                eip = mu.reg_read(UC_X86_REG_EIP)
                log.warning("Unhandled INT 21h AH=%02Xh at %04X:%04X", ah, cs, eip)
                mu.emu_stop()
        elif intno == 0x31:
            self._handle_dpmi(mu)
        elif intno == 0x03:
            # INT 3 — debug breakpoint
            cs = mu.reg_read(UC_X86_REG_CS)
            eip = mu.reg_read(UC_X86_REG_EIP)
            log.info("INT 3 breakpoint at %04X:%04X", cs, eip)
        else:
            cs = mu.reg_read(UC_X86_REG_CS)
            eip = mu.reg_read(UC_X86_REG_EIP)
            log.warning("Unhandled INT 0x%02X at %04X:%04X", intno, cs, eip)
            if intno == 0x0D:
                log.info("GPF trace (last 20 instructions):")
                self._dump_trace()
                sp = mu.reg_read(UC_X86_REG_SP)
                ss = mu.reg_read(UC_X86_REG_SS)
                ss_base = self.selector_bases.get(ss, 0)
                stack_data = bytes(mu.mem_read(ss_base + sp, 32))
                log.info("Stack at SS:%04X: %s", sp, stack_data.hex())
            mu.emu_stop()

    def _on_stub_execute(self, mu: Uc, address: int, size: int, _user_data) -> None:
        """Called when execution enters the stub region.

        Sets AX=DX=0 by default, then dispatches to a custom handler if one
        is registered. The handler can override AX/DX. After the hook returns,
        the `retf N` thunk instruction executes and returns to the caller.
        """
        stub = self.stub_addrs.get(address)
        if stub is None:
            return

        # Default return: AX=0, DX=0
        mu.reg_write(UC_X86_REG_AX, 0)
        mu.reg_write(UC_X86_REG_DX, 0)

        handler = self._stub_handlers.get(address)
        if handler is not None:
            handler(self, stub)
        else:
            log.debug(
                "STUB CALL: %s.%s (ordinal %d, param_bytes=%d)",
                stub.module,
                stub.name,
                stub.ordinal,
                stub.param_bytes,
            )

    # ── Game-state inspection ───────────────────────────────────────

    @property
    def _ds_base(self) -> int:
        """Linear base address of DGROUP (auto data segment)."""
        return self.seg_bases[self.ne.auto_data_seg]

    def _ds_u8(self, off: int) -> int:
        return struct.unpack_from("B", self.mu.mem_read(self._ds_base + off, 1))[0]

    def _ds_i16(self, off: int) -> int:
        return struct.unpack_from("<h", self.mu.mem_read(self._ds_base + off, 2))[0]

    def _ds_u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.mu.mem_read(self._ds_base + off, 2))[0]

    def _ds_i32(self, off: int) -> int:
        return struct.unpack_from("<i", self.mu.mem_read(self._ds_base + off, 4))[0]

    def _resolve_near_or_selector(self, raw: int) -> int | None:
        """Resolve a 16-bit value that could be a selector or near ptr."""
        if raw == 0:
            return None
        if raw in self.selector_bases:
            return self.selector_bases[raw]
        # Treat as near offset within DS
        return self._ds_base + raw

    def _resolve_sim_table_base(self) -> int | None:
        """Return the linear base of the sim/entity table, or None.

        sim_table_ptr is a far pointer: offset at DS+0xC04E, selector at DS+0xC050.
        """
        off16 = self._ds_u16(DS_OFF["sim_table_ptr"])
        seg16 = self._ds_u16(DS_OFF["sim_table_ptr"] + 2)
        if seg16 == 0:
            return None
        seg_base = self.selector_bases.get(seg16)
        if seg_base is None:
            return None
        return seg_base + off16

    def _read_sim_record(self, base: int, idx: int) -> dict:
        off = base + idx * SIM_REC_SIZE
        rec = bytes(self.mu.mem_read(off, SIM_REC_SIZE))
        trip_count = rec[9]
        last_trip_tick = struct.unpack_from("<H", rec, 10)[0]
        elapsed_packed = struct.unpack_from("<H", rec, 12)[0]
        accumulated_elapsed = struct.unpack_from("<H", rec, 14)[0]
        # Stress = average elapsed ticks per trip (higher = worse)
        stress = (accumulated_elapsed // trip_count) if trip_count > 0 else 0
        return {
            "floor": rec[0],
            "subtype": rec[1],
            "occupant": struct.unpack_from("<H", rec, 2)[0],
            "family": rec[4],
            "state": rec[5],
            "route_mode": rec[6],
            "spawn_floor": rec[7],
            "route_carrier": rec[8],
            "trip_count": trip_count,
            "last_trip_tick": last_trip_tick,
            "elapsed_packed": elapsed_packed,
            "accumulated_elapsed": accumulated_elapsed,
            "stress": stress,
        }

    def _resolve_floor_blob(self, floor_idx: int) -> int | None:
        """Return linear address of floor blob for floor_idx (0..119), or None."""
        base_off = DS_OFF["floor_tables_ptr"] + floor_idx * 4
        off16 = self._ds_u16(base_off)
        seg16 = self._ds_u16(base_off + 2)
        if seg16 == 0:
            return None
        seg_base = self.selector_bases.get(seg16)
        if seg_base is None:
            return None
        return seg_base + off16

    def _read_floor_objects(self, floor_idx: int) -> list[dict]:
        """Read placed-object records for one floor."""
        blob = self._resolve_floor_blob(floor_idx)
        if blob is None:
            return []
        count = struct.unpack_from("<H", self.mu.mem_read(blob, 2))[0]
        if count == 0 or count > 150:
            return []
        objs = []
        for i in range(count):
            off = blob + i * OBJ_STRIDE
            rec = bytes(self.mu.mem_read(off, OBJ_STRIDE))
            type_code = rec[10]  # +0x0a
            unit_status = rec[11]  # +0x0b
            objs.append(
                {
                    "type": type_code,
                    "unit_status": unit_status,
                    "sidecar": struct.unpack_from("<H", rec, 12)[0],
                    "runtime_idx": struct.unpack_from("<h", rec, 14)[0],
                }
            )
        return objs

    def _collect_tick_state(self, show_sims: bool) -> dict:
        """Collect the current simulation state as a dict."""
        d = DS_OFF
        state: dict = {
            "day": self._ds_i32(d["day_counter"]),
            "tick": self._ds_u16(d["day_tick"]),
            "daypart": self._ds_u8(d["daypart_index"]),
            "stars": self._ds_u16(d["star_count"]),
            "cash": self._ds_i32(d["cash_balance"]) * 100,
            "calendar_phase": self._ds_u8(d["calendar_phase"]),
            "metro_floor": self._ds_i16(d["metro_floor"]),
            "population": self._ds_i32(d["primary_family_ledger_total"]),
            "gates": {
                "security": bool(self._ds_u8(d["security_placed"])),
                "office": bool(self._ds_u8(d["office_placed"])),
                "recycling": bool(self._ds_u8(d["recycling_ok"])),
                "route": bool(self._ds_u8(d["route_viable"])),
            },
        }

        if not show_sims:
            return state

        sim_base = self._resolve_sim_table_base()
        sim_count = self._ds_i32(d["sim_count"])
        if sim_base is None or sim_count <= 0:
            state["sims"] = {}
            return state

        family_counts: dict[int, int] = defaultdict(int)
        family_stress: dict[int, list[int]] = defaultdict(list)
        state_hist: dict[int, dict[int, int]] = defaultdict(lambda: defaultdict(int))

        count = min(sim_count, 4096)
        for i in range(count):
            rec = self._read_sim_record(sim_base, i)
            fam = rec["family"]
            if fam == 0 and rec["state"] == 0:
                continue
            family_counts[fam] += 1
            if rec["stress"] > 0:
                family_stress[fam].append(rec["stress"])
            state_hist[fam][rec["state"]] += 1

        sims: dict[str, dict] = {}
        for fam in sorted(family_counts):
            label = FAMILY_NAMES.get(fam, f"0x{fam:02x}")
            stresses = family_stress.get(fam, [])
            states = state_hist[fam]
            sims[label] = {
                "count": family_counts[fam],
                "stress_avg": sum(stresses) // len(stresses) if stresses else 0,
                "stress_min": min(stresses) if stresses else 0,
                "stress_max": max(stresses) if stresses else 0,
                "states": {s: c for s, c in states.items()},
            }
        state["sims"] = sims
        state["sim_allocated"] = sim_count
        return state

    def dump_tick_state(self, show_sims: bool | None = None) -> None:
        """Print a summary of the current simulation state."""
        if show_sims is None:
            show_sims = self._show_sims

        state = self._collect_tick_state(show_sims)

        if self._output_json:
            print(json.dumps(state), flush=True)
            return

        d = state
        print(
            f"TICK day={d['day']} tick={d['tick']} daypart={d['daypart']} "
            f"stars={d['stars']} cash=${d['cash']:,} cal_phase={d['calendar_phase']} "
            f"metro={d['metro_floor']} pop={d['population']}"
        )

        gates = d["gates"]
        flags = []
        if gates["security"]:
            flags.append("sec")
        if gates["office"]:
            flags.append("ofc")
        if gates["recycling"]:
            flags.append("rec")
        if gates["route"]:
            flags.append("rte")
        if flags:
            print(f"  gates: {' '.join(flags)}")

        if not show_sims:
            return
        sims = d.get("sims", {})
        if not sims:
            print("  (no active sims)")
            return

        total_active = sum(s["count"] for s in sims.values())
        print(f"  sims: {total_active} active ({d.get('sim_allocated', '?')} allocated)")
        for label, s in sims.items():
            n = s["count"]
            stresses = s
            states = s["states"]
            top_states = sorted(states.items(), key=lambda x: -x[1])[:5]
            st_str = " ".join(
                f"{SIM_STATE_NAMES.get(st, f'0x{st:02x}')}:{c}" for st, c in top_states
            )
            if stresses["stress_max"] > 0:
                stress_str = (
                    f"stress={stresses['stress_avg']:4d} "
                    f"[{stresses['stress_min']}-{stresses['stress_max']}]"
                )
            else:
                stress_str = "stress=   -"
            print(f"  {label:14s} n={n:4d}  {stress_str}  [{st_str}]")

    def _on_scheduler_entry(self, mu: Uc, address: int, size: int, _user_data) -> None:
        """Code hook: fires when run_simulation_day_scheduler is entered."""
        if address != self._scheduler_linear:
            return
        self._tick_hook_count += 1
        if self._tick_hook_count == 1:
            pass  # First scheduler tick — init is complete.
        # Dump every N ticks (skip the very first call — state not yet initialized)
        if (
            self._tick_hook_count > 1
            and (self._tick_hook_count - 1) % self._tick_dump_interval == 0
        ):
            self.dump_tick_state()

    def _install_scheduler_hook(self, dump_interval: int = 100) -> None:
        """Register a code hook on the scheduler function for periodic state dumps."""
        seg_base = self.seg_bases.get(SCHEDULER_NE_SEG)
        if seg_base is None:
            log.warning(
                "Cannot install scheduler hook: segment %d not loaded", SCHEDULER_NE_SEG
            )
            return
        self._scheduler_linear = seg_base + SCHEDULER_SEG_OFFSET
        self._tick_hook_count = 0
        self._tick_dump_interval = dump_interval
        # Hook just the first instruction of the scheduler function
        self.mu.hook_add(
            UC_HOOK_CODE,
            self._on_scheduler_entry,
            begin=self._scheduler_linear,
            end=self._scheduler_linear + 1,
        )
        log.info(
            "Scheduler hook installed at linear 0x%06X (every %d ticks)",
            self._scheduler_linear,
            dump_interval,
        )

    # ── Programmatic construction ───────────────────────────────────

    def call_far(
        self,
        ne_seg: int,
        offset: int,
        params: list[int],
        max_instructions: int = 10_000_000,
    ) -> int:
        """Call a __cdecl16far function in the NE binary.

        Parameters are pushed **right-to-left** (C/cdecl convention — first
        param ends up closest to SP after the return address). The callee
        returns via ``retf`` without stack cleanup; the caller (us) restores SP.

        Saves and restores all CPU registers; memory side-effects are kept.

        Args:
            ne_seg: NE segment number (1-based).
            offset: Offset within the segment.
            params: Parameters in source-order (leftmost first). Each is a WORD.
            max_instructions: Safety cap on executed instructions.

        Returns:
            AX register value after the call completes.
        """
        target_sel = self.seg_selectors[ne_seg]

        save_regs = (
            UC_X86_REG_AX,
            UC_X86_REG_BX,
            UC_X86_REG_CX,
            UC_X86_REG_DX,
            UC_X86_REG_SI,
            UC_X86_REG_DI,
            UC_X86_REG_BP,
            UC_X86_REG_CS,
            UC_X86_REG_EIP,
            UC_X86_REG_SS,
            UC_X86_REG_SP,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_EFLAGS,
        )
        saved = {r: self.mu.reg_read(r) for r in save_regs}

        ss = self.mu.reg_read(UC_X86_REG_SS)
        sp = self.mu.reg_read(UC_X86_REG_SP)
        ss_base = self.selector_bases[ss]

        # Push params right-to-left (cdecl: first param closest to SP)
        for param in reversed(params):
            sp = (sp - 2) & 0xFFFF
            self.mu.mem_write(ss_base + sp, struct.pack("<H", param & 0xFFFF))

        # Push far return address: CS then IP
        sp = (sp - 2) & 0xFFFF
        self.mu.mem_write(ss_base + sp, struct.pack("<H", self._call_trap_sel))
        sp = (sp - 2) & 0xFFFF
        self.mu.mem_write(ss_base + sp, struct.pack("<H", 0))  # IP = 0

        self.mu.reg_write(UC_X86_REG_SP, sp)
        self.mu.reg_write(UC_X86_REG_CS, target_sel)
        self.mu.reg_write(UC_X86_REG_EIP, offset)

        self._call_trap_hit = False
        remaining = max_instructions
        chunk = min(100_000, max_instructions)
        while remaining > 0 and not self._call_trap_hit:
            run_count = min(chunk, remaining)
            try:
                eip_now = self.mu.reg_read(UC_X86_REG_EIP)
                self.mu.emu_start(eip_now, 0xFFFF, count=run_count)
            except UcError as e:
                if not self._call_trap_hit:
                    cs_now = self.mu.reg_read(UC_X86_REG_CS)
                    ip_now = self.mu.reg_read(UC_X86_REG_EIP)
                    log.error("call_far error at %04X:%04X: %s", cs_now, ip_now, e)
                    raise
            remaining -= run_count

        if not self._call_trap_hit:
            log.warning("call_far: function did not return (ran out of instructions?)")

        result_ax = self.mu.reg_read(UC_X86_REG_AX)

        # Restore all registers (SP restoration also handles cdecl stack cleanup)
        for r, v in saved.items():
            self.mu.reg_write(r, v)

        return result_ax

    def ensure_floor_blob(self, floor_idx: int) -> int:
        """Ensure a floor blob exists for the given floor index.

        Allocates a zeroed heap block and writes its far pointer into the floor
        table if one doesn't already exist.

        Returns:
            Linear address of the floor blob.
        """
        existing = self._resolve_floor_blob(floor_idx)
        if existing is not None:
            return existing

        # 6-byte header + 150 × 0x12-byte records
        blob_size = 6 + 150 * OBJ_STRIDE
        handle = self.heap.alloc(blob_size, 0x0040, self)  # GMEM_ZEROINIT
        if handle == 0:
            raise RuntimeError(f"Failed to allocate floor blob for floor {floor_idx}")

        block = self.heap.blocks[handle]
        # Write far pointer (offset:segment) into floor_tables array
        base_off = DS_OFF["floor_tables_ptr"] + floor_idx * 4
        ds_base = self._ds_base
        self.mu.mem_write(ds_base + base_off, struct.pack("<HH", 0, handle))

        log.info(
            "Allocated floor blob for floor_idx=%d at linear 0x%06X (sel 0x%04X)",
            floor_idx,
            block.linear,
            handle,
        )
        return block.linear

    def build_object(
        self,
        type_code: int,
        floor_logical: int,
        left_tile: int,
        right_tile: int,
        *,
        variant: int = 0,
        aux: int = 0,
        skip_cost: bool = True,
    ) -> bool:
        """Place an object by calling place_object_on_floor in the binary.

        Args:
            type_code: Facility type (3=single, 4=twin, 5=suite, 6=retail,
                       7=office, 9=condo, 0xA=fast-food, 0xC=restaurant,
                       0xE=security, 0xF=housekeeping).
            floor_logical: Logical floor (-10 to 109; 0 = lobby).
            left_tile: Left tile index.
            right_tile: Right tile index (left + width_in_tiles).
            variant: Sub-variant byte (default 0).
            aux: Family-specific auxiliary word (default 0).
            skip_cost: If True, skip cost/funds validation (default True).

        Returns:
            True if placement succeeded (AX != 0).

        Note:
            Above-grade floors (>0) require support from a lobby/floor span on
            floor 0. Place a lobby first or use write_floor_object_direct to
            bypass validation.
        """
        floor_idx = floor_logical + 10
        self.ensure_floor_blob(floor_idx)

        # place_object_on_floor(type, variant, aux, floor_idx, left, right, skip_cost)
        # 7 params — the decompiler's "param_1" was a phantom CS register, not a real arg.
        params = [
            type_code,
            variant,
            aux,
            floor_idx,
            left_tile,
            right_tile,
            1 if skip_cost else 0,
        ]
        result = self.call_far(PLACE_OBJ_NE_SEG, PLACE_OBJ_OFFSET, params)
        ok = result != 0
        label = FAMILY_NAMES.get(type_code, f"0x{type_code:02x}")
        if ok:
            log.info(
                "Built %s on floor %d tiles [%d, %d)",
                label,
                floor_logical,
                left_tile,
                right_tile,
            )
        else:
            log.warning(
                "Failed to build %s on floor %d tiles [%d, %d)",
                label,
                floor_logical,
                left_tile,
                right_tile,
            )
        return ok

    def build_stairs(
        self,
        top_floor_logical: int,
        left_tile: int,
    ) -> bool:
        """Place a 1-floor stairway connecting top_floor and the floor below it.

        Calls place_stairs_or_escalator_link in the binary.
        Params (cdecl16far): cost_param, top_floor_idx, tile_pos, mode.
        mode bit 0 = 1 for stairs; upper bits encode half-span (0 for 1-floor).
        """
        top_floor_idx = top_floor_logical + 10
        # Ensure floor blobs exist for both floors
        self.ensure_floor_blob(top_floor_idx)
        self.ensure_floor_blob(top_floor_idx - 1)

        # cost_param: pass 0 (funds are available, game has $20k internal)
        params = [0, top_floor_idx, left_tile, 1]  # mode=1 = stairs
        result = self.call_far(PLACE_STAIRS_NE_SEG, PLACE_STAIRS_OFFSET, params)
        ok = result != 0
        if ok:
            log.info(
                "Built stairs from floor %d to %d at tile %d",
                top_floor_logical - 1,
                top_floor_logical,
                left_tile,
            )
        else:
            log.warning(
                "Failed to build stairs from floor %d to %d at tile %d",
                top_floor_logical - 1,
                top_floor_logical,
                left_tile,
            )
        return ok

    def setup_floor_support(
        self,
        floor_logical: int,
        left_tile: int,
        right_tile: int,
    ) -> None:
        """Ensure the floor below has a blob with enough span for the support
        validator to accept placements on *floor_logical*.

        The binary's support table at DS:0xBE6A + idx*4 is really the floor
        blob table at DS:0xBE6E + (idx-1)*4.  Support for floor N is derived
        from the object extent recorded in floor_blob[N-1].

        This method ensures floor_blob[floor_logical-1] exists and that its
        header records a span at least as wide as [left_tile, right_tile).
        """
        below_idx = floor_logical + 10 - 1  # floor index of the floor below
        blob_addr = self.ensure_floor_blob(below_idx)

        # Read current header: count(u16), left(u16), right(u16)
        hdr = bytes(self.mu.mem_read(blob_addr, 6))
        count, cur_left, cur_right = struct.unpack_from("<HHH", hdr)

        if count == 0:
            # Empty blob — set a phantom count of 1 and the requested span
            self.mu.mem_write(blob_addr, struct.pack("<HHH", 1, left_tile, right_tile))
        else:
            # Widen the span if necessary
            new_left = min(cur_left, left_tile)
            new_right = max(cur_right, right_tile)
            if new_left != cur_left or new_right != cur_right:
                self.mu.mem_write(
                    blob_addr + 2, struct.pack("<HH", new_left, new_right)
                )

        log.info(
            "Set support for floor %d via floor_blob[%d]: tiles [%d, %d)",
            floor_logical,
            below_idx,
            left_tile,
            right_tile,
        )

    def write_floor_object_direct(
        self,
        floor_logical: int,
        type_code: int,
        left_tile: int,
        right_tile: int,
        *,
        variant: int = 0,
        aux: int = 0,
        unit_status: int = 0xFF,
        occupied: int = 1,
        eval_level: int | None = None,
    ) -> int:
        """Write an object record directly into a floor blob, bypassing all
        binary validation and runtime entity setup.

        Useful for bootstrapping tower state (e.g. lobby/support spans) before
        calling build_object for types that need validation to pass.

        Returns:
            The slot index of the new object, or -1 on failure.
        """
        floor_idx = floor_logical + 10
        blob = self.ensure_floor_blob(floor_idx)

        count = struct.unpack_from("<H", self.mu.mem_read(blob, 2))[0]
        if count >= 150:
            log.error("Floor %d is full (150 objects)", floor_logical)
            return -1

        slot = count
        # Update count
        self.mu.mem_write(blob, struct.pack("<H", count + 1))

        # Update floor left/right boundaries
        fl = struct.unpack_from("<H", self.mu.mem_read(blob + 2, 2))[0]
        fr = struct.unpack_from("<H", self.mu.mem_read(blob + 4, 2))[0]
        if count == 0:
            fl, fr = left_tile, right_tile
        else:
            fl = min(fl, left_tile)
            fr = max(fr, right_tile)
        self.mu.mem_write(blob + 2, struct.pack("<HH", fl, fr))

        if eval_level is None:
            eval_level = 1 if type_code in (3, 4, 5, 7, 9, 10) else 4

        # Write the 0x12-byte record at blob + 6 + slot * OBJ_STRIDE
        rec_off = blob + 6 + slot * OBJ_STRIDE
        rec = bytearray(OBJ_STRIDE)
        struct.pack_into("<HH", rec, 0, left_tile, right_tile)
        rec[4] = type_code & 0xFF
        rec[5] = variant & 0xFF
        struct.pack_into("<H", rec, 6, aux & 0xFFFF)
        # bytes 8..11 left as zero
        rec[0xC] = unit_status & 0xFF
        rec[0xD] = 1
        rec[0xE] = occupied & 0xFF
        rec[0xF] = 0xFF
        rec[0x10] = eval_level & 0xFF
        rec[0x11] = 0
        self.mu.mem_write(rec_off, bytes(rec))

        label = FAMILY_NAMES.get(type_code, f"0x{type_code:02x}")
        log.info(
            "Direct-wrote %s slot %d on floor %d tiles [%d, %d)",
            label,
            slot,
            floor_logical,
            left_tile,
            right_tile,
        )
        return slot

    # ── Execution ────────────────────────────────────────────────────

    def run(self, max_instructions: int = 10_000_000) -> None:
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
        return " ".join(
            f"{name}={self.mu.reg_read(reg):04X}" for name, reg in regs.items()
        )


def _apply_build_json(emu: SimTowerEmulator, path: str) -> None:
    """Load a build-JSON file and store the build plan on the emulator.

    JSON format:
    {
        "floor_extent": {
            "0": {"left": 80, "right": 220},
            "1": {"left": 100, "right": 200},
            "2": {"left": 100, "right": 200}
        },
        "facilities": [
            {"type": "office", "floor": 1, "left": 100},
            {"type": "office", "floor": 1, "left": 109},
            {"type": "stairs", "floor": 1, "left": 100},
            ...
        ]
    }

    floor_extent keys are floor numbers (as strings for JSON compat).
    Floor 0 extent is used as the lobby span. Each above-grade floor
    gets a support span from its entry. Floors without an explicit entry
    inherit the widest extent from the entries below them.

    Facility "right" is optional — computed from FACILITY_WIDTHS when omitted.

    Supported facility types: any FAMILY_NAMES value (e.g. "office", "single",
    "condo", "retail", "security", "restaurant", ...) plus "lobby" and "stairs".
    """
    with open(path) as f:
        spec = json.load(f)
    emu._build_spec = spec


# Reverse lookup: name -> type code
_NAME_TO_TYPE: dict[str, int] = {v: k for k, v in FAMILY_NAMES.items()}
_NAME_TO_TYPE["lobby"] = 0x18


def _resolve_type_code(name: str) -> int | None:
    """Resolve a facility name to a type code, or None if unknown."""
    tc = _NAME_TO_TYPE.get(name)
    if tc is not None:
        return tc
    try:
        return int(name, 0)
    except ValueError:
        return None


def _resolve_right(fac: dict, type_code: int) -> int | None:
    """Get right tile from explicit value or width lookup."""
    if "right" in fac:
        return fac["right"]
    width = FACILITY_WIDTHS.get(type_code)
    if width is None:
        return None
    return fac["left"] + width


def _apply_default_build(emu: SimTowerEmulator) -> None:
    """Set the hardcoded default build plan (the old --mode=build behavior)."""
    emu._build_spec = {
        "floor_extent": {
            "0": {"left": 100, "right": 200},
            "1": {"left": 100, "right": 200},
            "2": {"left": 100, "right": 200},
        },
        "facilities": [
            {"type": "office", "floor": 1, "left": 100},
            {"type": "office", "floor": 1, "left": 109},
            {"type": "office", "floor": 2, "left": 100},
            {"type": "office", "floor": 2, "left": 109},
            {"type": "stairs", "floor": 1, "left": 100},
            {"type": "stairs", "floor": 2, "left": 100},
        ],
    }


def _place_build_objects(emu: SimTowerEmulator) -> None:
    """Execute the build plan stored on the emulator by _apply_build_json or
    _apply_default_build."""
    spec = getattr(emu, "_build_spec", None)
    if spec is None:
        return

    # Parse per-floor extents
    raw_extents: dict = spec.get("floor_extent", {})
    floor_extents: dict[int, tuple[int, int]] = {}
    for k, v in raw_extents.items():
        floor_extents[int(k)] = (v["left"], v["right"])

    if not floor_extents:
        floor_extents[0] = (100, 200)

    # Write lobby on floor 0
    lobby_l, lobby_r = floor_extents.get(0, (100, 200))
    emu.write_floor_object_direct(0, type_code=0x18, left_tile=lobby_l, right_tile=lobby_r)

    # Determine max floor needed from facilities and extents
    max_floor = max((f.get("floor", 0) for f in spec.get("facilities", [])), default=0)
    max_floor = max(max_floor, max(floor_extents.keys(), default=0))

    # Set up per-floor support spans, widening to cover any explicit extent
    running_l, running_r = lobby_l, lobby_r
    for fl in range(1, max_floor + 2):
        if fl in floor_extents:
            fl_l, fl_r = floor_extents[fl]
            running_l = min(running_l, fl_l)
            running_r = max(running_r, fl_r)
        emu.setup_floor_support(fl, left_tile=running_l, right_tile=running_r)

    # Place each facility
    for fac in spec.get("facilities", []):
        ftype = fac["type"]
        floor = fac.get("floor", 0)

        if ftype == "stairs":
            emu.build_stairs(top_floor_logical=floor, left_tile=fac["left"])
            continue

        type_code = _resolve_type_code(ftype)
        if type_code is None:
            log.warning("Unknown facility type %r, skipping", ftype)
            continue

        if ftype == "lobby":
            right = _resolve_right(fac, type_code)
            if right is None:
                log.warning("Cannot determine width for lobby, skipping")
                continue
            emu.write_floor_object_direct(
                floor, type_code=0x18, left_tile=fac["left"], right_tile=right
            )
            continue

        right = _resolve_right(fac, type_code)
        if right is None:
            log.warning(
                "No known width for type %r (0x%02x) and no 'right' given, skipping",
                ftype, type_code,
            )
            continue
        emu.build_object(
            type_code=type_code,
            floor_logical=floor,
            left_tile=fac["left"],
            right_tile=right,
            variant=fac.get("variant", 0),
            aux=fac.get("aux", 0),
        )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="SimTower NE emulator")
    parser.add_argument("exe", nargs="?", default="src/simtower/SIMTOWER.EXE")
    parser.add_argument("--mode", choices=["run", "build"], default="run")
    parser.add_argument("--dump-interval", type=int, default=100,
                        help="dump state every N scheduler ticks")
    parser.add_argument("--max-insns", type=int, default=100_000_000)
    parser.add_argument("--sims", action="store_true",
                        help="show per-family sim state/stress each tick dump")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                        help="output format: text (default) or json (JSONL)")
    parser.add_argument("--build-json", type=str, default=None,
                        help="path to JSON file describing tower to build")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(name)s %(levelname)s: %(message)s"
    )

    emu = SimTowerEmulator(args.exe)
    emu._show_sims = args.sims
    emu._output_json = args.output == "json"
    emu._install_scheduler_hook(dump_interval=args.dump_interval)
    if not emu._output_json:
        print(f"Initial registers: {emu.dump_regs()}")

    if args.build_json:
        _apply_build_json(emu, args.build_json)
    elif args.mode == "build":
        _apply_default_build(emu)

    if args.mode == "build" or args.build_json:
        if not emu._output_json:
            print("\n=== Phase 1: Run through initialization ===")
        try:
            emu.run(max_instructions=20_000_000)
        except RuntimeError as e:
            if not emu._output_json:
                print(f"Init stopped: {e}")

        if not emu._output_json:
            print("\n=== Phase 1 complete (ticks=%d) ===" % emu._tick_hook_count)
        emu.dump_tick_state()

        _place_build_objects(emu)

        if not emu._output_json:
            print("\n=== Phase 3: Continue simulation ===")
        emu.dump_tick_state()
        try:
            emu.run(max_instructions=args.max_insns)
        except RuntimeError as e:
            print(f"Stopped: {e}")
    else:
        try:
            emu.run(max_instructions=args.max_insns)
        except RuntimeError as e:
            print(f"Stopped: {e}")

    if not emu._output_json:
        print(f"\nFinal registers: {emu.dump_regs()}")
        print(f"Scheduler entered {emu._tick_hook_count} times")
    if emu._tick_hook_count > 0:
        if not emu._output_json:
            print("\n--- Final state ---")
        emu.dump_tick_state(show_sims=True)


if __name__ == "__main__":
    main()
