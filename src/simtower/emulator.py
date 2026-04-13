"""SimTower NE executable emulator using Unicorn engine.

Loads the 16-bit NE binary into Unicorn in 16-bit protected mode
(UC_MODE_32 with a GDT of 16-bit descriptors). Each NE segment gets
its own GDT entry with the correct base and limit. Imported Win16 API
functions are stubbed with `retf N` thunks; a code hook sets return
values (default AX=0) and dispatches to Python handlers for functions
that need real behaviour (GlobalAlloc, GlobalLock, etc.).
"""

from __future__ import annotations

import logging
import struct
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
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

from simtower.ne_loader import (
    NEHeader,
    NERelocation,
    NEResourceEntry,
    NESegmentEntry,
    parse_segment_relocations,
)
from simtower.stubs import StubDef, build_stub_lookup

log = logging.getLogger(__name__)

# ── Memory layout ────────────────────────────────────────────────────
MEM_SIZE = 16 * 1024 * 1024  # 16 MiB address space
GDT_ADDR = 0x1000  # linear address of GDT
GDT_LIMIT = 0x10000  # 64 KiB = room for 8192 descriptors
LOAD_BASE = 0x10_0000  # 1 MiB: linear base for NE segments
STUB_BASE = 0x80_0000  # 8 MiB: linear base for API stub thunks
HEAP_BASE = 0xA0_0000  # 10 MiB: linear base for GlobalAlloc heap
CALL_TRAP_BASE = 0x9F_0000  # just below heap: return-trap for call_far_pascal
FIRST_SELECTOR = 0x08  # first usable GDT selector (skip null)

# ── Ghidra ↔ emulator address mapping ───────────────────────────────
# Ghidra maps NE segment N to 0x10000000 + (N-1) * 0x80000.
# DGROUP (auto data segment) is NE segment 82 → Ghidra 0x12880000.
GHIDRA_SEG_BASE = 0x1000_0000
GHIDRA_SEG_STRIDE = 0x8_0000

# DS-relative offsets for key globals (Ghidra addr − 0x12880000)
DS_OFF = {
    "day_tick": 0xBC52,  # uint16
    "day_counter": 0xBC54,  # int32
    "daypart_index": 0xBB8B,  # uint8
    "calendar_phase": 0xBB8A,  # uint8
    "star_count": 0xBC40,  # uint16
    "cash_balance": 0xBC42,  # int32
    "progress_override": 0xBC58,  # uint16
    "metro_floor": 0xBC5C,  # int16 (-1 = none)
    "eval_entity_idx": 0xBC60,  # int16
    "recycling_count": 0xBC68,  # uint16
    "security_count": 0xBC6E,  # uint16
    "ent_link_count": 0xBC74,  # uint16
    "sim_table_ptr": 0xC04E,  # uint16  (near ptr / selector)
    "sim_count": 0xC052,  # int32
    "primary_family_ledger_total": 0xC13A,  # int32 — population ledger
    "floor_tables_ptr": 0xBE6E,  # start of far-pointer array (120 × 4-byte far ptrs)
    # interleaved with support table at 0xBE6A
    "security_placed": 0xC19E,  # uint8
    "office_placed": 0xC19F,  # uint8
    "recycling_ok": 0xC1A0,  # uint8
    "route_viable": 0xC1A1,  # uint8
}

# run_simulation_day_scheduler lives in NE segment 66 at offset 0x0196.
SCHEDULER_NE_SEG = 66
SCHEDULER_SEG_OFFSET = 0x0196

# Per-entity sim record: 16 bytes, accessed via g_sim_table + index*16
SIM_REC_SIZE = 16

# Placed-object record stride: 0x12 bytes per slot inside floor blob
OBJ_STRIDE = 0x12

# place_object_on_floor: Ghidra 0x12001847 = NE segment 65, offset 0x1847
PLACE_OBJ_NE_SEG = 65
PLACE_OBJ_OFFSET = 0x1847

# place_mergeable_span_object_on_floor: Ghidra 0x1200293e = NE seg 65, offset 0x293e
PLACE_SPAN_NE_SEG = 65
PLACE_SPAN_OFFSET = 0x293E

# dispatch_drag_span_placement (for lobby/floor spans): Ghidra 0x120027ce = seg 65, offset 0x27ce
DRAG_SPAN_NE_SEG = 65
DRAG_SPAN_OFFSET = 0x27CE

# Family code → human label (most common families)
FAMILY_NAMES: dict[int, str] = {
    3: "single",
    4: "twin",
    5: "suite",
    6: "retail",
    7: "office",
    9: "condo",
    10: "fast-food",
    0xC: "restaurant",
    0xE: "security",
    0xF: "housekeeping",
    0x12: "entertainment",
    0x1D: "cinema",
    0x21: "cathedral",
}

# Type alias for stub handler functions
StubHandler = Callable[["SimTowerEmulator", StubDef], None]


def _gdt_entry(base: int, limit: int, access: int, flags_hi: int) -> bytes:
    """Build an 8-byte GDT descriptor.

    access:   P(1) DPL(2) S(1) Type(4)
    flags_hi: G(1) D/B(1) 0(1) AVL(1)  — upper nibble of byte 6
    """
    entry = bytearray(8)
    entry[0] = limit & 0xFF
    entry[1] = (limit >> 8) & 0xFF
    entry[2] = base & 0xFF
    entry[3] = (base >> 8) & 0xFF
    entry[4] = (base >> 16) & 0xFF
    entry[5] = access
    entry[6] = ((limit >> 16) & 0x0F) | ((flags_hi & 0x0F) << 4)
    entry[7] = (base >> 24) & 0xFF
    return bytes(entry)


# ── Heap allocation tracking ─────────────────────────────────────────


@dataclass
class HeapBlock:
    """Metadata for a GlobalAlloc'd block."""

    handle: int  # the selector (== handle in Win16)
    linear: int  # linear address in Unicorn memory
    size: int  # allocation size in bytes
    selector: int  # GDT selector for this block
    lock_count: int = 0
    flags: int = 0


class GlobalHeap:
    """Simple heap manager for Win16 GlobalAlloc/GlobalFree.

    Allocations are backed by Unicorn memory starting at HEAP_BASE.
    Freed blocks are cached per exact size for reuse.
    """

    def __init__(self) -> None:
        self._next_linear = HEAP_BASE
        # handle (selector) -> HeapBlock
        self.blocks: dict[int, HeapBlock] = {}
        # size -> list of (linear_addr) for freed blocks
        self._free_cache: dict[int, list[int]] = defaultdict(list)

    def alloc(self, size: int, flags: int, emu: SimTowerEmulator) -> int:
        """Allocate a block. Returns the handle (selector), or 0 on failure."""
        if size == 0:
            size = 1  # Win16 allows 0-size allocs, give them 1 byte

        # Check free cache for an exact-size match
        cached = self._free_cache.get(size)
        if cached:
            linear = cached.pop()
            # Zero-init if GMEM_ZEROINIT (0x0040)
            if flags & 0x0040:
                emu.mu.mem_write(linear, b"\x00" * size)
        else:
            linear = self._next_linear
            # Align to 16 bytes
            linear = (linear + 15) & ~15
            self._next_linear = linear + size
            if self._next_linear > MEM_SIZE:
                log.error("GlobalAlloc: out of memory (need 0x%X)", size)
                return 0
            # New memory is already zero from mem_map

        # Create a data selector for this block
        sel = emu._alloc_selector(linear, max(size - 1, 0), code=False)

        block = HeapBlock(
            handle=sel,
            linear=linear,
            size=size,
            selector=sel,
            lock_count=0,
            flags=flags,
        )
        self.blocks[sel] = block
        return sel

    def free(self, handle: int) -> int:
        """Free a block. Returns 0 on success, handle on failure."""
        block = self.blocks.pop(handle, None)
        if block is None:
            return handle  # failure
        # Cache by exact size
        self._free_cache[block.size].append(block.linear)
        return 0

    def lock(self, handle: int) -> tuple[int, int]:
        """Lock a block. Returns (selector, offset=0) as a far pointer."""
        block = self.blocks.get(handle)
        if block is None:
            return (0, 0)
        block.lock_count += 1
        return (block.selector, 0)

    def unlock(self, handle: int) -> int:
        """Unlock a block. Returns remaining lock count."""
        block = self.blocks.get(handle)
        if block is None:
            return 0
        if block.lock_count > 0:
            block.lock_count -= 1
        return block.lock_count

    def size(self, handle: int) -> int:
        """Return the size of a block, or 0 if invalid."""
        block = self.blocks.get(handle)
        return block.size if block else 0

    def flags(self, handle: int) -> int:
        """Return lock count in low byte, flags in high byte."""
        block = self.blocks.get(handle)
        if block is None:
            return 0
        return block.lock_count & 0xFF

    def handle_for_selector(self, sel: int) -> int:
        """Given a selector, return the handle (same value for us)."""
        if sel in self.blocks:
            return sel
        return 0

    def realloc(
        self, handle: int, new_size: int, flags: int, emu: SimTowerEmulator
    ) -> int:
        """Reallocate a block. Returns new handle, or 0 on failure."""
        block = self.blocks.get(handle)
        if block is None:
            return 0

        if new_size == 0:
            new_size = 1

        if new_size <= block.size:
            # Shrinking — just update the size (don't bother reclaiming)
            block.size = new_size
            return handle

        # Need more space — allocate new, copy, free old
        new_handle = self.alloc(new_size, flags, emu)
        if new_handle == 0:
            return 0

        # Copy old data
        old_data = emu.mu.mem_read(block.linear, block.size)
        new_block = self.blocks[new_handle]
        emu.mu.mem_write(new_block.linear, bytes(old_data))

        # Free old
        self.blocks.pop(handle)
        self._free_cache[block.size].append(block.linear)

        return new_handle


# ── Stub handlers ────────────────────────────────────────────────────
# Each handler reads parameters from the stack and writes return values
# to AX (and DX for DWORD returns). The `retf N` thunk handles stack cleanup.
#
# Stack layout on entry (16-bit far call, Pascal convention):
#   [SS:SP+0] = return IP
#   [SS:SP+2] = return CS
#   [SS:SP+4] = last param (rightmost)
#   ...
#   [SS:SP+4+N-size_of_first] = first param (leftmost)


def _read_stack_word(emu: SimTowerEmulator, offset: int) -> int:
    """Read a WORD from the stack at SS:SP+offset."""
    ss = emu.mu.reg_read(UC_X86_REG_SS)
    sp = emu.mu.reg_read(UC_X86_REG_SP)
    base = emu.selector_bases.get(ss, 0)
    addr = base + ((sp + offset) & 0xFFFF)
    return struct.unpack("<H", emu.mu.mem_read(addr, 2))[0]


def _read_stack_dword(emu: SimTowerEmulator, offset: int) -> int:
    """Read a DWORD from the stack at SS:SP+offset."""
    ss = emu.mu.reg_read(UC_X86_REG_SS)
    sp = emu.mu.reg_read(UC_X86_REG_SP)
    base = emu.selector_bases.get(ss, 0)
    addr = base + ((sp + offset) & 0xFFFF)
    return struct.unpack("<I", emu.mu.mem_read(addr, 4))[0]


def _handle_global_alloc(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalAlloc(UINT fuFlags, DWORD dwBytes) -> HGLOBAL

    Pascal stack (left-to-right push):
      [SP+4] = dwBytes (DWORD)  — pushed second (closer to SP)
      [SP+8] = fuFlags (WORD)   — pushed first (deeper)
    """
    dw_bytes = _read_stack_dword(emu, 4)
    fu_flags = _read_stack_word(emu, 8)
    handle = emu.heap.alloc(dw_bytes, fu_flags, emu)
    log.debug(
        "GlobalAlloc(flags=0x%04X, size=%d) -> handle=0x%04X",
        fu_flags,
        dw_bytes,
        handle,
    )
    emu.mu.reg_write(UC_X86_REG_AX, handle)


def _handle_global_realloc(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalReAlloc(HGLOBAL hMem, DWORD dwBytes, UINT fuFlags) -> HGLOBAL

    Pascal stack:
      [SP+4] = fuFlags (WORD)
      [SP+6] = dwBytes (DWORD)
      [SP+10] = hMem (WORD)
    """
    fu_flags = _read_stack_word(emu, 4)
    dw_bytes = _read_stack_dword(emu, 6)
    h_mem = _read_stack_word(emu, 10)
    handle = emu.heap.realloc(h_mem, dw_bytes, fu_flags, emu)
    log.debug(
        "GlobalReAlloc(h=0x%04X, size=%d, flags=0x%04X) -> 0x%04X",
        h_mem,
        dw_bytes,
        fu_flags,
        handle,
    )
    emu.mu.reg_write(UC_X86_REG_AX, handle)


def _handle_global_free(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalFree(HGLOBAL hMem) -> HGLOBAL (0 on success)

    Pascal stack:
      [SP+4] = hMem (WORD)
    """
    h_mem = _read_stack_word(emu, 4)
    result = emu.heap.free(h_mem)
    log.debug("GlobalFree(h=0x%04X) -> 0x%04X", h_mem, result)
    emu.mu.reg_write(UC_X86_REG_AX, result)


def _handle_global_lock(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalLock(HGLOBAL hMem) -> LPVOID (far pointer in DX:AX)

    Pascal stack:
      [SP+4] = hMem (WORD)
    """
    h_mem = _read_stack_word(emu, 4)
    sel, off = emu.heap.lock(h_mem)
    log.debug("GlobalLock(h=0x%04X) -> %04X:%04X", h_mem, sel, off)
    emu.mu.reg_write(UC_X86_REG_DX, sel)
    emu.mu.reg_write(UC_X86_REG_AX, off)


def _handle_global_unlock(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalUnlock(HGLOBAL hMem) -> BOOL

    Pascal stack:
      [SP+4] = hMem (WORD)
    """
    h_mem = _read_stack_word(emu, 4)
    remaining = emu.heap.unlock(h_mem)
    # Returns TRUE if still locked
    emu.mu.reg_write(UC_X86_REG_AX, 1 if remaining > 0 else 0)


def _handle_global_size(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalSize(HGLOBAL hMem) -> DWORD (in DX:AX)

    Pascal stack:
      [SP+4] = hMem (WORD)
    """
    h_mem = _read_stack_word(emu, 4)
    size = emu.heap.size(h_mem)
    emu.mu.reg_write(UC_X86_REG_DX, (size >> 16) & 0xFFFF)
    emu.mu.reg_write(UC_X86_REG_AX, size & 0xFFFF)


def _handle_global_flags(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalFlags(HGLOBAL hMem) -> UINT"""
    h_mem = _read_stack_word(emu, 4)
    emu.mu.reg_write(UC_X86_REG_AX, emu.heap.flags(h_mem))


def _handle_global_handle(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalHandle(UINT wMem) -> DWORD (handle in DX:AX)"""
    w_mem = _read_stack_word(emu, 4)
    handle = emu.heap.handle_for_selector(w_mem)
    emu.mu.reg_write(UC_X86_REG_DX, handle)
    emu.mu.reg_write(UC_X86_REG_AX, handle)


def _handle_global_compact(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalCompact(DWORD dwMinFree) -> DWORD (largest free block)"""
    # Return a large value to indicate plenty of memory
    emu.mu.reg_write(UC_X86_REG_DX, 0x0040)  # ~4 MB
    emu.mu.reg_write(UC_X86_REG_AX, 0x0000)


def _handle_get_module_filename(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetModuleFileName(HMODULE hModule, LPSTR lpFilename, int nSize) -> int

    Pascal stack:
      [SP+4] = nSize (WORD)
      [SP+6] = lpFilename (DWORD - seg:off)
      [SP+10] = hModule (WORD)
    """
    n_size = _read_stack_word(emu, 4)
    buf_ptr = _read_stack_dword(emu, 6)
    buf_seg = (buf_ptr >> 16) & 0xFFFF
    buf_off = buf_ptr & 0xFFFF
    base = emu.selector_bases.get(buf_seg, 0)
    filename = b"C:\\SIMTOWER\\SIMTOWER.EXE\x00"
    write_len = min(len(filename), n_size)
    emu.mu.mem_write(base + buf_off, filename[:write_len])
    emu.mu.reg_write(UC_X86_REG_AX, write_len - 1)  # exclude null
    log.debug("GetModuleFileName() -> %d chars", write_len - 1)


def _handle_register_class(emu: SimTowerEmulator, stub: StubDef) -> None:
    """RegisterClass(LPWNDCLASS lpWndClass) -> ATOM (non-zero on success)."""
    emu._next_atom += 1
    atom = emu._next_atom
    emu.mu.reg_write(UC_X86_REG_AX, atom)
    log.debug("RegisterClass() -> atom=0x%04X", atom)


def _handle_create_window(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateWindow(...) -> HWND (non-zero on success)."""
    emu._next_hwnd += 1
    hwnd = emu._next_hwnd
    emu.mu.reg_write(UC_X86_REG_AX, hwnd)
    log.debug("CreateWindow() -> hwnd=0x%04X", hwnd)


def _handle_get_stock_object(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetStockObject(int fnObject) -> HGDIOBJ.

    Return a fake non-zero GDI handle.
    """
    fn_obj = _read_stack_word(emu, 4)
    # Use a deterministic handle based on the stock object ID
    handle = 0x8000 | (fn_obj & 0xFF)
    emu.mu.reg_write(UC_X86_REG_AX, handle)
    log.debug("GetStockObject(%d) -> 0x%04X", fn_obj, handle)


def _handle_load_icon(emu: SimTowerEmulator, stub: StubDef) -> None:
    """LoadIcon(HINSTANCE hInst, LPCSTR lpIconName) -> HICON."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("LoadIcon() -> 0x%04X", emu._next_handle)


def _handle_load_cursor(emu: SimTowerEmulator, stub: StubDef) -> None:
    """LoadCursor(HINSTANCE hInst, LPCSTR lpCursorName) -> HCURSOR."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("LoadCursor() -> 0x%04X", emu._next_handle)


def _handle_load_accelerators(emu: SimTowerEmulator, stub: StubDef) -> None:
    """LoadAccelerators(HINSTANCE hInst, LPCSTR lpTableName) -> HACCEL."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("LoadAccelerators() -> 0x%04X", emu._next_handle)


def _handle_show_window(emu: SimTowerEmulator, stub: StubDef) -> None:
    """ShowWindow(HWND hWnd, int nCmdShow) -> BOOL (previous visibility)."""
    emu.mu.reg_write(UC_X86_REG_AX, 0)  # was not visible before
    log.debug("ShowWindow() -> 0")


def _handle_update_window(emu: SimTowerEmulator, stub: StubDef) -> None:
    """UpdateWindow(HWND hWnd) -> BOOL."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("UpdateWindow() -> 1")


def _handle_get_dc(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetDC(HWND hWnd) -> HDC."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("GetDC() -> 0x%04X", emu._next_handle)


def _handle_release_dc(emu: SimTowerEmulator, stub: StubDef) -> None:
    """ReleaseDC(HWND hWnd, HDC hDC) -> int."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)


def _handle_get_device_caps(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetDeviceCaps(HDC hdc, int nIndex) -> int.

    Pascal stack:
      [SP+4] = nIndex (WORD)
      [SP+6] = hdc (WORD)
    """
    n_index = _read_stack_word(emu, 4)
    # Win16 device cap indices (different from Win32!)
    caps = {
        0: 1,  # DRIVERVERSION
        2: 1,  # TECHNOLOGY (DT_RASDISPLAY)
        4: 320,  # HORZSIZE (mm)
        6: 240,  # VERTSIZE (mm)
        8: 640,  # HORZRES (pixels)
        10: 480,  # VERTRES (pixels)
        12: 8,  # BITSPIXEL
        14: 1,  # PLANES
        16: 64,  # NUMBRUSHES
        18: 16,  # NUMPENS
        22: 128,  # NUMFONTS
        24: 256,  # NUMCOLORS
        34: 0x6001,  # TEXTCAPS
        36: 36,  # CLIPCAPS
        38: 0x7E99,  # RASTERCAPS
        40: 36,  # ASPECTX
        42: 36,  # ASPECTY
        44: 51,  # ASPECTXY
        88: 96,  # LOGPIXELSX
        90: 96,  # LOGPIXELSY
        104: 256,  # SIZEPALETTE
        106: 20,  # NUMRESERVED
        108: 18,  # COLORRES
    }
    val = caps.get(n_index, 0)
    emu.mu.reg_write(UC_X86_REG_AX, val)
    log.debug("GetDeviceCaps(index=%d) -> %d", n_index, val)


def _handle_get_system_metrics(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetSystemMetrics(int nIndex) -> int.

    Pascal stack: [SP+4] = nIndex (WORD)
    """
    n_index = _read_stack_word(emu, 4)
    metrics = {
        0: 640,  # SM_CXSCREEN
        1: 480,  # SM_CYSCREEN
        2: 20,  # SM_CXVSCROLL
        3: 20,  # SM_CYHSCROLL
        4: 20,  # SM_CYCAPTION
        5: 1,  # SM_CXBORDER
        6: 1,  # SM_CYBORDER
        7: 4,  # SM_CXDLGFRAME
        8: 4,  # SM_CYDLGFRAME
        9: 16,  # SM_CYVTHUMB
        10: 16,  # SM_CXHTHUMB
        11: 32,  # SM_CXICON
        12: 32,  # SM_CYICON
        13: 32,  # SM_CXCURSOR
        14: 32,  # SM_CYCURSOR
        15: 4,  # SM_CXFRAME (SM_CXSIZEFRAME)
        16: 4,  # SM_CYFRAME
        20: 20,  # SM_CXHSCROLL
        21: 20,  # SM_CYVSCROLL
        23: 1,  # SM_MOUSEPRESENT
        28: 112,  # SM_CXMIN
        29: 27,  # SM_CYMIN
    }
    val = metrics.get(n_index, 0)
    emu.mu.reg_write(UC_X86_REG_AX, val)
    log.debug("GetSystemMetrics(%d) -> %d", n_index, val)


def _handle_create_compatible_dc(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateCompatibleDC(HDC hdc) -> HDC."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreateCompatibleDC() -> 0x%04X", emu._next_handle)


def _handle_select_object(emu: SimTowerEmulator, stub: StubDef) -> None:
    """SelectObject(HDC hdc, HGDIOBJ hObj) -> HGDIOBJ (previous)."""
    h_obj = _read_stack_word(emu, 4)
    # Return a fake previous object
    emu.mu.reg_write(UC_X86_REG_AX, 0x8001)
    log.debug("SelectObject(obj=0x%04X) -> 0x8001", h_obj)


def _handle_create_solid_brush(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateSolidBrush(COLORREF crColor) -> HBRUSH."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreateSolidBrush() -> 0x%04X", emu._next_handle)


def _handle_create_pen(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreatePen(int fnPenStyle, int nWidth, COLORREF crColor) -> HPEN."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreatePen() -> 0x%04X", emu._next_handle)


def _handle_create_font_indirect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateFontIndirect(LPLOGFONT lplf) -> HFONT."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreateFontIndirect() -> 0x%04X", emu._next_handle)


def _handle_create_palette(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreatePalette(LPLOGPALETTE lplgpl) -> HPALETTE."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreatePalette() -> 0x%04X", emu._next_handle)


def _handle_select_palette(emu: SimTowerEmulator, stub: StubDef) -> None:
    """SelectPalette(HDC hdc, HPALETTE hpal, BOOL bForceBackground) -> HPALETTE."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("SelectPalette() -> previous palette handle")


def _handle_realize_palette(emu: SimTowerEmulator, stub: StubDef) -> None:
    """RealizePalette(HDC hdc) -> UINT (number of entries mapped)."""
    emu.mu.reg_write(UC_X86_REG_AX, 256)
    log.debug("RealizePalette() -> 256")


def _handle_create_bitmap(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateBitmap(int nWidth, int nHeight, UINT cPlanes, UINT cBitsPerPel, LPVOID lpvBits) -> HBITMAP."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreateBitmap() -> 0x%04X", emu._next_handle)


def _handle_create_compatible_bitmap(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateCompatibleBitmap(HDC hdc, int cx, int cy) -> HBITMAP."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreateCompatibleBitmap() -> 0x%04X", emu._next_handle)


def _handle_create_rect_rgn(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateRectRgn(int x1, int y1, int x2, int y2) -> HRGN."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreateRectRgn() -> 0x%04X", emu._next_handle)


def _handle_set_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """SetRect(LPRECT lprc, int xLeft, int yTop, int xRight, int yBottom) -> BOOL.

    Pascal stack:
      [SP+4] = yBottom (WORD)
      [SP+6] = xRight (WORD)
      [SP+8] = yTop (WORD)
      [SP+10] = xLeft (WORD)
      [SP+12] = lprc (DWORD)
    """
    bottom = _read_stack_word(emu, 4)
    right = _read_stack_word(emu, 6)
    top = _read_stack_word(emu, 8)
    left = _read_stack_word(emu, 10)
    rc_ptr = _read_stack_dword(emu, 12)
    seg = (rc_ptr >> 16) & 0xFFFF
    off = rc_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    emu.mu.mem_write(base + off, struct.pack("<HHHH", left, top, right, bottom))
    emu.mu.reg_write(UC_X86_REG_AX, 1)


def _handle_set_rect_empty(emu: SimTowerEmulator, stub: StubDef) -> None:
    """SetRectEmpty(LPRECT lprc) -> BOOL."""
    rc_ptr = _read_stack_dword(emu, 4)
    seg = (rc_ptr >> 16) & 0xFFFF
    off = rc_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    emu.mu.mem_write(base + off, struct.pack("<HHHH", 0, 0, 0, 0))
    emu.mu.reg_write(UC_X86_REG_AX, 1)


def _handle_copy_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CopyRect(LPRECT lpDst, LPRECT lpSrc) -> BOOL.

    Pascal stack:
      [SP+4] = lpSrc (DWORD)
      [SP+8] = lpDst (DWORD)
    """
    src_ptr = _read_stack_dword(emu, 4)
    dst_ptr = _read_stack_dword(emu, 8)
    src_seg, src_off = (src_ptr >> 16) & 0xFFFF, src_ptr & 0xFFFF
    dst_seg, dst_off = (dst_ptr >> 16) & 0xFFFF, dst_ptr & 0xFFFF
    src_base = emu.selector_bases.get(src_seg, 0)
    dst_base = emu.selector_bases.get(dst_seg, 0)
    data = bytes(emu.mu.mem_read(src_base + src_off, 8))
    emu.mu.mem_write(dst_base + dst_off, data)
    emu.mu.reg_write(UC_X86_REG_AX, 1)


def _handle_inflate_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """InflateRect(LPRECT lprc, int dx, int dy) -> BOOL.

    Pascal stack:
      [SP+4] = dy (WORD)
      [SP+6] = dx (WORD)
      [SP+8] = lprc (DWORD)
    """
    dy = _read_stack_word(emu, 4)
    dx = _read_stack_word(emu, 6)
    # Sign extend
    if dy >= 0x8000:
        dy -= 0x10000
    if dx >= 0x8000:
        dx -= 0x10000
    rc_ptr = _read_stack_dword(emu, 8)
    seg = (rc_ptr >> 16) & 0xFFFF
    off = rc_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    left, top, right, bottom = struct.unpack("<hhhh", emu.mu.mem_read(base + off, 8))
    left = (left - dx) & 0xFFFF
    top = (top - dy) & 0xFFFF
    right = (right + dx) & 0xFFFF
    bottom = (bottom + dy) & 0xFFFF
    emu.mu.mem_write(base + off, struct.pack("<HHHH", left, top, right, bottom))
    emu.mu.reg_write(UC_X86_REG_AX, 1)


def _handle_offset_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """OffsetRect(LPRECT lprc, int dx, int dy) -> BOOL.

    Pascal stack:
      [SP+4] = dy (WORD)
      [SP+6] = dx (WORD)
      [SP+8] = lprc (DWORD)
    """
    dy = _read_stack_word(emu, 4)
    dx = _read_stack_word(emu, 6)
    if dy >= 0x8000:
        dy -= 0x10000
    if dx >= 0x8000:
        dx -= 0x10000
    rc_ptr = _read_stack_dword(emu, 8)
    seg = (rc_ptr >> 16) & 0xFFFF
    off = rc_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    left, top, right, bottom = struct.unpack("<hhhh", emu.mu.mem_read(base + off, 8))
    emu.mu.mem_write(
        base + off,
        struct.pack(
            "<HHHH",
            (left + dx) & 0xFFFF,
            (top + dy) & 0xFFFF,
            (right + dx) & 0xFFFF,
            (bottom + dy) & 0xFFFF,
        ),
    )
    emu.mu.reg_write(UC_X86_REG_AX, 1)


def _handle_intersect_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """IntersectRect(LPRECT lpDst, LPRECT lpSrc1, LPRECT lpSrc2) -> BOOL.

    Pascal stack:
      [SP+4] = lpSrc2 (DWORD)
      [SP+8] = lpSrc1 (DWORD)
      [SP+12] = lpDst (DWORD)
    """
    s2_ptr = _read_stack_dword(emu, 4)
    s1_ptr = _read_stack_dword(emu, 8)
    d_ptr = _read_stack_dword(emu, 12)

    def read_rect(ptr):
        seg, off = (ptr >> 16) & 0xFFFF, ptr & 0xFFFF
        base = emu.selector_bases.get(seg, 0)
        return struct.unpack("<hhhh", emu.mu.mem_read(base + off, 8))

    l1, t1, r1, b1 = read_rect(s1_ptr)
    l2, t2, r2, b2 = read_rect(s2_ptr)
    il = max(l1, l2)
    it = max(t1, t2)
    ir = min(r1, r2)
    ib = min(b1, b2)
    d_seg, d_off = (d_ptr >> 16) & 0xFFFF, d_ptr & 0xFFFF
    d_base = emu.selector_bases.get(d_seg, 0)
    if il < ir and it < ib:
        emu.mu.mem_write(
            d_base + d_off,
            struct.pack("<HHHH", il & 0xFFFF, it & 0xFFFF, ir & 0xFFFF, ib & 0xFFFF),
        )
        emu.mu.reg_write(UC_X86_REG_AX, 1)
    else:
        emu.mu.mem_write(d_base + d_off, struct.pack("<HHHH", 0, 0, 0, 0))
        emu.mu.reg_write(UC_X86_REG_AX, 0)


def _handle_union_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """UnionRect(LPRECT lpDst, LPRECT lpSrc1, LPRECT lpSrc2) -> BOOL."""
    s2_ptr = _read_stack_dword(emu, 4)
    s1_ptr = _read_stack_dword(emu, 8)
    d_ptr = _read_stack_dword(emu, 12)

    def read_rect(ptr):
        seg, off = (ptr >> 16) & 0xFFFF, ptr & 0xFFFF
        base = emu.selector_bases.get(seg, 0)
        return struct.unpack("<hhhh", emu.mu.mem_read(base + off, 8))

    l1, t1, r1, b1 = read_rect(s1_ptr)
    l2, t2, r2, b2 = read_rect(s2_ptr)
    d_seg, d_off = (d_ptr >> 16) & 0xFFFF, d_ptr & 0xFFFF
    d_base = emu.selector_bases.get(d_seg, 0)
    emu.mu.mem_write(
        d_base + d_off,
        struct.pack(
            "<HHHH",
            min(l1, l2) & 0xFFFF,
            min(t1, t2) & 0xFFFF,
            max(r1, r2) & 0xFFFF,
            max(b1, b2) & 0xFFFF,
        ),
    )
    emu.mu.reg_write(UC_X86_REG_AX, 1)


def _handle_pt_in_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """PtInRect(LPRECT lprc, POINT pt) -> BOOL.

    Pascal stack:
      [SP+4] = pt (DWORD - y:x packed)
      [SP+8] = lprc (DWORD)
    """
    pt = _read_stack_dword(emu, 4)
    px = pt & 0xFFFF
    py = (pt >> 16) & 0xFFFF
    if px >= 0x8000:
        px -= 0x10000
    if py >= 0x8000:
        py -= 0x10000
    rc_ptr = _read_stack_dword(emu, 8)
    seg, off = (rc_ptr >> 16) & 0xFFFF, rc_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    left, top, right, bottom = struct.unpack("<hhhh", emu.mu.mem_read(base + off, 8))
    result = 1 if (left <= px < right and top <= py < bottom) else 0
    emu.mu.reg_write(UC_X86_REG_AX, result)


def _handle_is_rect_empty(emu: SimTowerEmulator, stub: StubDef) -> None:
    """IsRectEmpty(LPRECT lprc) -> BOOL."""
    rc_ptr = _read_stack_dword(emu, 4)
    seg, off = (rc_ptr >> 16) & 0xFFFF, rc_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    left, top, right, bottom = struct.unpack("<hhhh", emu.mu.mem_read(base + off, 8))
    result = 1 if (left >= right or top >= bottom) else 0
    emu.mu.reg_write(UC_X86_REG_AX, result)


def _handle_equal_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """EqualRect(LPRECT lprc1, LPRECT lprc2) -> BOOL."""
    r1_ptr = _read_stack_dword(emu, 4)
    r2_ptr = _read_stack_dword(emu, 8)

    def read_rect(ptr):
        seg, off = (ptr >> 16) & 0xFFFF, ptr & 0xFFFF
        base = emu.selector_bases.get(seg, 0)
        return bytes(emu.mu.mem_read(base + off, 8))

    emu.mu.reg_write(UC_X86_REG_AX, 1 if read_rect(r1_ptr) == read_rect(r2_ptr) else 0)


def _handle_get_desktop_window(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetDesktopWindow() -> HWND."""
    emu.mu.reg_write(UC_X86_REG_AX, 0x0001)  # fake desktop HWND
    log.debug("GetDesktopWindow() -> 0x0001")


def _handle_get_client_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetClientRect(HWND hWnd, LPRECT lpRect) -> BOOL.

    Pascal stack:
      [SP+4] = lpRect (DWORD)
      [SP+8] = hWnd (WORD)
    """
    rect_ptr = _read_stack_dword(emu, 4)
    seg = (rect_ptr >> 16) & 0xFFFF
    off = rect_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    # Write a 640x480 rect: left=0, top=0, right=640, bottom=480
    emu.mu.mem_write(base + off, struct.pack("<HHHH", 0, 0, 640, 480))
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("GetClientRect() -> (0,0,640,480)")


def _handle_get_window_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetWindowRect(HWND hWnd, LPRECT lpRect) -> BOOL.

    Pascal stack:
      [SP+4] = lpRect (DWORD)
      [SP+8] = hWnd (WORD)
    """
    rect_ptr = _read_stack_dword(emu, 4)
    seg = (rect_ptr >> 16) & 0xFFFF
    off = rect_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    emu.mu.mem_write(base + off, struct.pack("<HHHH", 0, 0, 640, 480))
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("GetWindowRect() -> (0,0,640,480)")


def _handle_set_timer(emu: SimTowerEmulator, stub: StubDef) -> None:
    """SetTimer(HWND hWnd, UINT nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc) -> UINT."""
    n_id = _read_stack_word(emu, 8)  # nIDEvent
    emu.mu.reg_write(UC_X86_REG_AX, n_id if n_id else 1)
    log.debug("SetTimer(id=%d) -> %d", n_id, n_id if n_id else 1)


def _handle_get_menu(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetMenu(HWND hWnd) -> HMENU."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("GetMenu() -> 0x%04X", emu._next_handle)


def _handle_get_sub_menu(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetSubMenu(HMENU hMenu, int nPos) -> HMENU."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("GetSubMenu() -> 0x%04X", emu._next_handle)


def _handle_peek_message(emu: SimTowerEmulator, stub: StubDef) -> None:
    """PeekMessage(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg) -> BOOL.

    Return 0 (no message available) to let the idle loop proceed.
    """
    emu.mu.reg_write(UC_X86_REG_AX, 0)


def _handle_get_tick_count(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetTickCount() -> DWORD (milliseconds since boot)."""
    emu._tick_count += 55  # ~18.2 Hz tick
    emu.mu.reg_write(UC_X86_REG_AX, emu._tick_count & 0xFFFF)
    emu.mu.reg_write(UC_X86_REG_DX, (emu._tick_count >> 16) & 0xFFFF)


def _handle_lstrlen(emu: SimTowerEmulator, stub: StubDef) -> None:
    """lstrlen(LPCSTR lpString) -> int.

    Pascal stack: [SP+4] = lpString (DWORD - seg:off)
    """
    ptr = _read_stack_dword(emu, 4)
    seg = (ptr >> 16) & 0xFFFF
    off = ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    # Read up to 1024 bytes looking for null terminator
    data = bytes(emu.mu.mem_read(base + off, 1024))
    null_pos = data.find(0)
    length = null_pos if null_pos >= 0 else 1024
    emu.mu.reg_write(UC_X86_REG_AX, length)
    log.debug("lstrlen() -> %d", length)


def _handle_lstrcpy(emu: SimTowerEmulator, stub: StubDef) -> None:
    """lstrcpy(LPSTR lpDst, LPCSTR lpSrc) -> LPSTR.

    Pascal stack:
      [SP+4] = lpSrc (DWORD)
      [SP+8] = lpDst (DWORD)
    """
    src_ptr = _read_stack_dword(emu, 4)
    dst_ptr = _read_stack_dword(emu, 8)
    src_seg = (src_ptr >> 16) & 0xFFFF
    src_off = src_ptr & 0xFFFF
    dst_seg = (dst_ptr >> 16) & 0xFFFF
    dst_off = dst_ptr & 0xFFFF
    src_base = emu.selector_bases.get(src_seg, 0)
    dst_base = emu.selector_bases.get(dst_seg, 0)
    # Read source string
    data = bytes(emu.mu.mem_read(src_base + src_off, 1024))
    null_pos = data.find(0)
    if null_pos >= 0:
        data = data[: null_pos + 1]
    emu.mu.mem_write(dst_base + dst_off, data)
    emu.mu.reg_write(UC_X86_REG_DX, dst_seg)
    emu.mu.reg_write(UC_X86_REG_AX, dst_off)
    log.debug(
        "lstrcpy(%04X:%04X <- %04X:%04X, len=%d)",
        dst_seg,
        dst_off,
        src_seg,
        src_off,
        len(data) - 1,
    )


def _handle_lstrcat(emu: SimTowerEmulator, stub: StubDef) -> None:
    """lstrcat(LPSTR lpDst, LPCSTR lpSrc) -> LPSTR.

    Pascal stack:
      [SP+4] = lpSrc (DWORD)
      [SP+8] = lpDst (DWORD)
    """
    src_ptr = _read_stack_dword(emu, 4)
    dst_ptr = _read_stack_dword(emu, 8)
    src_seg = (src_ptr >> 16) & 0xFFFF
    src_off = src_ptr & 0xFFFF
    dst_seg = (dst_ptr >> 16) & 0xFFFF
    dst_off = dst_ptr & 0xFFFF
    src_base = emu.selector_bases.get(src_seg, 0)
    dst_base = emu.selector_bases.get(dst_seg, 0)
    # Find end of dst
    dst_data = bytes(emu.mu.mem_read(dst_base + dst_off, 1024))
    dst_end = dst_data.find(0)
    if dst_end < 0:
        dst_end = 1024
    # Read source
    src_data = bytes(emu.mu.mem_read(src_base + src_off, 1024))
    null_pos = src_data.find(0)
    if null_pos >= 0:
        src_data = src_data[: null_pos + 1]
    emu.mu.mem_write(dst_base + dst_off + dst_end, src_data)
    emu.mu.reg_write(UC_X86_REG_DX, dst_seg)
    emu.mu.reg_write(UC_X86_REG_AX, dst_off)


def _handle_hmemcpy(emu: SimTowerEmulator, stub: StubDef) -> None:
    """hmemcpy(LPVOID lpDest, LPCVOID lpSource, DWORD cbCopy) -> void.

    Pascal stack:
      [SP+4] = cbCopy (DWORD)
      [SP+8] = lpSource (DWORD)
      [SP+12] = lpDest (DWORD)
    """
    cb = _read_stack_dword(emu, 4)
    src = _read_stack_dword(emu, 8)
    dst = _read_stack_dword(emu, 12)
    src_seg, src_off = (src >> 16) & 0xFFFF, src & 0xFFFF
    dst_seg, dst_off = (dst >> 16) & 0xFFFF, dst & 0xFFFF
    src_base = emu.selector_bases.get(src_seg, 0)
    dst_base = emu.selector_bases.get(dst_seg, 0)
    if cb > 0 and cb < 0x100000:  # sanity limit
        data = bytes(emu.mu.mem_read(src_base + src_off, cb))
        emu.mu.mem_write(dst_base + dst_off, data)
    log.debug(
        "hmemcpy(%04X:%04X <- %04X:%04X, %d bytes)",
        dst_seg,
        dst_off,
        src_seg,
        src_off,
        cb,
    )


def _handle_find_resource(emu: SimTowerEmulator, stub: StubDef) -> None:
    """FindResource(HMODULE hInst, LPCSTR lpName, LPCSTR lpType) -> HRSRC.

    Pascal stack:
      [SP+4] = lpType (DWORD — seg:off or MAKEINTRESOURCE)
      [SP+8] = lpName (DWORD — seg:off or MAKEINTRESOURCE)
      [SP+12] = hInst (WORD)

    Win16 MAKEINTRESOURCE: high word = 0 (or selector = 0), low word = integer ID.
    Actually for 16-bit: if the pointer's segment is 0, the offset IS the integer resource ID.
    """
    type_ptr = _read_stack_dword(emu, 4)
    name_ptr = _read_stack_dword(emu, 8)

    log.debug("FindResource raw: type_ptr=%08X name_ptr=%08X", type_ptr, name_ptr)

    # Decode type — check if it's an integer resource (MAKEINTRESOURCE: segment=0)
    type_seg = (type_ptr >> 16) & 0xFFFF
    type_off = type_ptr & 0xFFFF
    # Decode type
    type_seg = (type_ptr >> 16) & 0xFFFF
    type_off = type_ptr & 0xFFFF
    type_name_str: str | None = None
    type_id: int = 0
    if type_seg == 0:
        type_id = type_off
    else:
        base = emu.selector_bases.get(type_seg, 0)
        data = bytes(emu.mu.mem_read(base + type_off, 64))
        null_pos = data.find(0)
        if null_pos >= 0:
            data = data[:null_pos]
        type_name_str = data.decode("ascii", errors="replace")

    # Decode name
    name_seg = (name_ptr >> 16) & 0xFFFF
    name_off = name_ptr & 0xFFFF
    if name_seg == 0:
        res_id = name_off
    else:
        base = emu.selector_bases.get(name_seg, 0)
        data = bytes(emu.mu.mem_read(base + name_off, 64))
        null_pos = data.find(0)
        if null_pos >= 0:
            data = data[:null_pos]
        log.debug(
            "FindResource: string name '%s' not supported",
            data.decode("ascii", errors="replace"),
        )
        emu.mu.reg_write(UC_X86_REG_AX, 0)
        return

    if type_name_str is not None:
        entry = emu.ne.find_resource_by_name(type_name_str, res_id)
    else:
        entry = emu.ne.find_resource(type_id, res_id)
    type_desc = type_name_str if type_name_str is not None else str(type_id)
    if entry is None:
        log.debug("FindResource(type=%s, id=%d) -> NOT FOUND", type_desc, res_id)
        emu.mu.reg_write(UC_X86_REG_AX, 0)
        return

    # Use a synthetic handle — store the resource entry for later LoadResource
    handle = emu._register_resource(entry)
    emu.mu.reg_write(UC_X86_REG_AX, handle)
    log.debug(
        "FindResource(type=%s, id=%d) -> handle=0x%04X (offset=0x%X, len=%d)",
        type_desc,
        res_id,
        handle,
        entry.file_offset,
        entry.length,
    )


def _handle_load_resource(emu: SimTowerEmulator, stub: StubDef) -> None:
    """LoadResource(HMODULE hInst, HRSRC hResInfo) -> HGLOBAL.

    Pascal stack:
      [SP+4] = hResInfo (WORD)
      [SP+6] = hInst (WORD)

    Load the resource data into heap memory and return the handle.
    """
    h_res = _read_stack_word(emu, 4)
    entry = emu._resource_handles.get(h_res)
    if entry is None:
        log.debug("LoadResource(0x%04X) -> NULL (invalid handle)", h_res)
        emu.mu.reg_write(UC_X86_REG_AX, 0)
        return

    # Check if already loaded
    existing = emu._loaded_resources.get(h_res)
    if existing:
        emu.mu.reg_write(UC_X86_REG_AX, existing)
        return

    # Allocate memory and copy resource data
    handle = emu.heap.alloc(entry.length, 0, emu)
    if handle == 0:
        emu.mu.reg_write(UC_X86_REG_AX, 0)
        return

    block = emu.heap.blocks[handle]
    data = emu.exe_bytes[entry.file_offset : entry.file_offset + entry.length]
    emu.mu.mem_write(block.linear, data)

    emu._loaded_resources[h_res] = handle
    emu.mu.reg_write(UC_X86_REG_AX, handle)
    log.debug(
        "LoadResource(0x%04X) -> heap handle 0x%04X (%d bytes)",
        h_res,
        handle,
        entry.length,
    )


def _handle_lock_resource(emu: SimTowerEmulator, stub: StubDef) -> None:
    """LockResource(HGLOBAL hResData) -> LPVOID (far pointer DX:AX).

    Pascal stack: [SP+4] = hResData (WORD)
    """
    h_res = _read_stack_word(emu, 4)
    sel, off = emu.heap.lock(h_res)
    emu.mu.reg_write(UC_X86_REG_DX, sel)
    emu.mu.reg_write(UC_X86_REG_AX, off)
    log.debug("LockResource(0x%04X) -> %04X:%04X", h_res, sel, off)


def _handle_free_resource(emu: SimTowerEmulator, stub: StubDef) -> None:
    """FreeResource(HGLOBAL hResData) -> BOOL (0 = success)."""
    h_res = _read_stack_word(emu, 4)
    result = emu.heap.free(h_res)
    emu.mu.reg_write(UC_X86_REG_AX, result)
    log.debug("FreeResource(0x%04X) -> %d", h_res, result)


def _handle_output_debug_string(emu: SimTowerEmulator, stub: StubDef) -> None:
    """OutputDebugString(LPCSTR lpszMsg) -> void."""
    ptr = _read_stack_dword(emu, 4)
    seg = (ptr >> 16) & 0xFFFF
    off = ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    data = bytes(emu.mu.mem_read(base + off, 256))
    null_pos = data.find(0)
    if null_pos >= 0:
        data = data[:null_pos]
    log.info("OutputDebugString: %s", data.decode("ascii", errors="replace"))


def _handle_get_profile_string(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetProfileString(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpDefault,
                        LPSTR lpReturnedString, int nSize) -> int.

    Pascal stack:
      [SP+4] = nSize (WORD)
      [SP+6] = lpReturnedString (DWORD)
      [SP+10] = lpDefault (DWORD)
      [SP+14] = lpKeyName (DWORD)
      [SP+18] = lpAppName (DWORD)

    Copy the default string to the return buffer.
    """
    n_size = _read_stack_word(emu, 4)
    ret_ptr = _read_stack_dword(emu, 6)
    def_ptr = _read_stack_dword(emu, 10)
    ret_seg, ret_off = (ret_ptr >> 16) & 0xFFFF, ret_ptr & 0xFFFF
    def_seg, def_off = (def_ptr >> 16) & 0xFFFF, def_ptr & 0xFFFF
    ret_base = emu.selector_bases.get(ret_seg, 0)
    def_base = emu.selector_bases.get(def_seg, 0)
    # Read default string
    def_data = bytes(emu.mu.mem_read(def_base + def_off, min(n_size, 256)))
    null_pos = def_data.find(0)
    if null_pos >= 0:
        def_data = def_data[: null_pos + 1]
    write_len = min(len(def_data), n_size)
    emu.mu.mem_write(ret_base + ret_off, def_data[:write_len])
    result_len = write_len - 1 if write_len > 0 else 0
    emu.mu.reg_write(UC_X86_REG_AX, result_len)
    log.debug("GetProfileString() -> %d (default)", result_len)


def _handle_get_private_profile_int(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetPrivateProfileInt(LPCSTR lpAppName, LPCSTR lpKeyName, INT nDefault, LPCSTR lpFileName) -> UINT.

    Pascal stack:
      [SP+4] = lpFileName (DWORD)
      [SP+8] = nDefault (WORD)
      [SP+10] = lpKeyName (DWORD)
      [SP+14] = lpAppName (DWORD)
    """
    n_default = _read_stack_word(emu, 8)
    emu.mu.reg_write(UC_X86_REG_AX, n_default)
    log.debug("GetPrivateProfileInt() -> %d (default)", n_default)


def _handle_message_box(emu: SimTowerEmulator, stub: StubDef) -> None:
    """MessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) -> int.

    Pascal stack:
      [SP+4] = uType (WORD)
      [SP+6] = lpCaption (DWORD)
      [SP+10] = lpText (DWORD)
      [SP+14] = hWnd (WORD)

    Read and log the message text, return IDOK (1) or IDYES (6) depending on style.
    """
    u_type = _read_stack_word(emu, 4)
    text_ptr = _read_stack_dword(emu, 10)
    text_seg = (text_ptr >> 16) & 0xFFFF
    text_off = text_ptr & 0xFFFF
    text_base = emu.selector_bases.get(text_seg, 0)
    data = bytes(emu.mu.mem_read(text_base + text_off, 256))
    null_pos = data.find(0)
    if null_pos >= 0:
        data = data[:null_pos]
    text = data.decode("ascii", errors="replace")

    # MB_YESNO=0x04, MB_YESNOCANCEL=0x03
    button_style = u_type & 0x0F
    if button_style in (0x03, 0x04):
        result = 6  # IDYES
    elif button_style == 0x01:  # MB_OKCANCEL
        result = 1  # IDOK
    else:
        result = 1  # IDOK

    emu.mu.reg_write(UC_X86_REG_AX, result)
    log.info("MessageBox('%s', type=0x%04X) -> %d", text, u_type, result)


def _handle_get_text_metrics(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetTextMetrics(HDC hdc, LPTEXTMETRIC lptm) -> BOOL.

    Pascal stack:
      [SP+4] = lptm (DWORD)
      [SP+8] = hdc (WORD)

    Write a reasonable TEXTMETRIC structure (Win16: 31 bytes).
    """
    tm_ptr = _read_stack_dword(emu, 4)
    seg = (tm_ptr >> 16) & 0xFFFF
    off = tm_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    # TEXTMETRIC16 structure (31 bytes):
    # tmHeight(2) tmAscent(2) tmDescent(2) tmInternalLeading(2)
    # tmExternalLeading(2) tmAveCharWidth(2) tmMaxCharWidth(2)
    # tmWeight(2) tmItalic(1) tmUnderlined(1) tmStruckOut(1)
    # tmFirstChar(1) tmLastChar(1) tmDefaultChar(1) tmBreakChar(1)
    # tmPitchAndFamily(1) tmCharSet(1) tmOverhang(2)
    # tmDigitizedAspectX(2) tmDigitizedAspectY(2)
    tm = struct.pack(
        "<hhhhhhhhBBBBBBBBBxhhh",
        16,  # tmHeight
        13,  # tmAscent
        3,  # tmDescent
        2,  # tmInternalLeading
        0,  # tmExternalLeading
        7,  # tmAveCharWidth
        14,  # tmMaxCharWidth
        400,  # tmWeight (FW_NORMAL)
        0,  # tmItalic
        0,  # tmUnderlined
        0,  # tmStruckOut
        0x20,  # tmFirstChar
        0xFF,  # tmLastChar
        0x2E,  # tmDefaultChar ('.')
        0x20,  # tmBreakChar (' ')
        0x20,  # tmPitchAndFamily (VARIABLE_PITCH | FF_SWISS)
        0,  # tmCharSet (ANSI_CHARSET)
        # x = pad byte for alignment
        0,  # tmOverhang
        96,  # tmDigitizedAspectX
        96,  # tmDigitizedAspectY
    )
    emu.mu.mem_write(base + off, tm)
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("GetTextMetrics() -> 1")


def _handle_get_rasterizer_caps(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetRasterizerCaps(LPRASTERIZER_STATUS lprs, UINT cb) -> BOOL.

    Pascal stack:
      [SP+4] = cb (WORD)
      [SP+6] = lprs (DWORD)

    RASTERIZER_STATUS: nSize(2) wFlags(2) nLanguageID(2)
    TT_AVAILABLE=1, TT_ENABLED=2
    """
    cb = _read_stack_word(emu, 4)
    rs_ptr = _read_stack_dword(emu, 6)
    seg = (rs_ptr >> 16) & 0xFFFF
    off = rs_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    rs = struct.pack("<HHH", min(cb, 6), 0x03, 0)  # TT_AVAILABLE | TT_ENABLED
    emu.mu.mem_write(base + off, rs[: min(cb, 6)])
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("GetRasterizerCaps() -> TT_AVAILABLE|TT_ENABLED")


def _handle_save_dc(emu: SimTowerEmulator, stub: StubDef) -> None:
    """SaveDC(HDC hdc) -> int (saved DC index, non-zero on success)."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("SaveDC() -> 1")


def _handle_get_palette_entries(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetPaletteEntries(HPALETTE hpal, UINT iStartIndex, UINT cEntries, LPPALETTEENTRY lppe) -> UINT.

    Pascal stack:
      [SP+4] = lppe (DWORD)
      [SP+8] = cEntries (WORD)
      [SP+10] = iStartIndex (WORD)
      [SP+12] = hpal (WORD)

    Fill with a standard 256-color VGA palette.
    """
    lppe = _read_stack_dword(emu, 4)
    c_entries = _read_stack_word(emu, 8)
    i_start = _read_stack_word(emu, 10)

    if lppe != 0 and c_entries > 0:
        seg = (lppe >> 16) & 0xFFFF
        off = lppe & 0xFFFF
        base = emu.selector_bases.get(seg, 0)
        # Write PALETTEENTRY structs (4 bytes each: R, G, B, flags)
        for i in range(c_entries):
            idx = (i_start + i) & 0xFF
            # Simple grayscale ramp
            r = g = b = idx
            emu.mu.mem_write(base + off + i * 4, struct.pack("BBBB", r, g, b, 0))

    emu.mu.reg_write(UC_X86_REG_AX, c_entries)
    log.debug(
        "GetPaletteEntries(start=%d, count=%d) -> %d", i_start, c_entries, c_entries
    )


def _handle_wing_create_dc(emu: SimTowerEmulator, stub: StubDef) -> None:
    """WinGCreateDC() -> HDC."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("WinGCreateDC() -> 0x%04X", emu._next_handle)


def _handle_wing_recommend_dib(emu: SimTowerEmulator, stub: StubDef) -> None:
    """WinGRecommendDIBFormat(LPBITMAPINFO lpbi) -> BOOL.

    Pascal stack: [SP+4] = lpbi (DWORD)
    Fill in a 640x480 8bpp top-down DIB format.
    """
    bi_ptr = _read_stack_dword(emu, 4)
    seg = (bi_ptr >> 16) & 0xFFFF
    off = bi_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    # BITMAPINFOHEADER: biSize(4) biWidth(4) biHeight(4) biPlanes(2)
    # biBitCount(2) biCompression(4) biSizeImage(4) ...
    bih = struct.pack(
        "<IiiHHIIiiII",
        40,  # biSize
        640,  # biWidth
        -480,  # biHeight (negative = top-down)
        1,  # biPlanes
        8,  # biBitCount
        0,  # biCompression (BI_RGB)
        640 * 480,  # biSizeImage
        0,  # biXPelsPerMeter
        0,  # biYPelsPerMeter
        256,  # biClrUsed
        0,  # biClrImportant
    )
    emu.mu.mem_write(base + off, bih)
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("WinGRecommendDIBFormat() -> 1 (640x480 8bpp)")


def _handle_wing_create_bitmap(emu: SimTowerEmulator, stub: StubDef) -> None:
    """WinGCreateBitmap(HDC hWinGDC, LPBITMAPINFO lpHeader, void FAR *FAR *ppBits) -> HBITMAP.

    Pascal stack:
      [SP+4] = ppBits (DWORD — pointer to far pointer, output)
      [SP+8] = lpHeader (DWORD — BITMAPINFO with header + colors)
      [SP+12] = hWinGDC (WORD)

    Reads the BITMAPINFOHEADER to get dimensions, allocates a pixel buffer,
    returns the HBITMAP and writes the pixel data far pointer to *ppBits.
    """
    pp_bits = _read_stack_dword(emu, 4)
    lp_header = _read_stack_dword(emu, 8)

    # Read BITMAPINFOHEADER to get size
    hdr_seg = (lp_header >> 16) & 0xFFFF
    hdr_off = lp_header & 0xFFFF
    hdr_base = emu.selector_bases.get(hdr_seg, 0)
    bih = emu.mu.mem_read(hdr_base + hdr_off, 40)
    width = struct.unpack_from("<i", bih, 4)[0]
    height = struct.unpack_from("<i", bih, 8)[0]
    bpp = struct.unpack_from("<H", bih, 14)[0]

    abs_height = abs(height)
    stride = ((abs(width) * bpp + 31) // 32) * 4
    pixel_size = stride * abs_height

    # Allocate pixel buffer
    handle = emu.heap.alloc(pixel_size, 0x0040, emu)  # GMEM_ZEROINIT
    if handle == 0:
        emu.mu.reg_write(UC_X86_REG_AX, 0)
        return

    block = emu.heap.blocks[handle]

    # Write far pointer to ppBits if provided
    if pp_bits != 0:
        pp_seg = (pp_bits >> 16) & 0xFFFF
        pp_off = pp_bits & 0xFFFF
        pp_base = emu.selector_bases.get(pp_seg, 0)
        # Write far pointer: offset=0, selector=block's selector
        emu.mu.mem_write(pp_base + pp_off, struct.pack("<HH", 0, block.selector))

    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug(
        "WinGCreateBitmap(%dx%d %dbpp, %d bytes) -> hbm=0x%04X, bits=%04X:0000",
        width,
        abs_height,
        bpp,
        pixel_size,
        emu._next_handle,
        block.selector,
    )


def _handle_fpmath(emu: SimTowerEmulator, stub: StubDef) -> None:
    """WIN87EM.__FPMATH — floating-point math emulator entry point.

    The C runtime's FP init calls this to check/init FP support.
    Return AX=1 to signal "FP available".
    """
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("__FPMATH() -> AX=1 (FP available)")


def _handle_get_current_task(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetCurrentTask() -> HTASK (must be non-zero)."""
    emu.mu.reg_write(UC_X86_REG_AX, 0x1234)  # fake task handle
    log.debug("GetCurrentTask() -> 0x1234")


def _handle_make_proc_instance(emu: SimTowerEmulator, stub: StubDef) -> None:
    """MakeProcInstance(FARPROC lpProc, HINSTANCE hInst) -> FARPROC

    In Win16, this creates a thunk that sets DS before calling lpProc.
    We just return the original function pointer unchanged.

    Pascal stack:
      [SP+4] = hInstance (WORD)
      [SP+6] = lpProc (DWORD - seg:off)
    """
    proc = _read_stack_dword(emu, 6)
    seg = (proc >> 16) & 0xFFFF
    off = proc & 0xFFFF
    emu.mu.reg_write(UC_X86_REG_DX, seg)
    emu.mu.reg_write(UC_X86_REG_AX, off)
    log.debug("MakeProcInstance(%04X:%04X) -> passthrough", seg, off)


def _handle_free_proc_instance(emu: SimTowerEmulator, stub: StubDef) -> None:
    """FreeProcInstance(FARPROC lpProc) — no-op since we don't create thunks."""
    log.debug("FreeProcInstance() -> no-op")


def _handle_get_win_flags(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetWinFlags() -> DWORD

    Return flags indicating 386 enhanced mode with math coprocessor.
    WF_ENHANCED=0x20, WF_80x87=0x400, WF_PMODE=0x01
    """
    flags = 0x0020 | 0x0400 | 0x0001  # enhanced + 80x87 + pmode
    emu.mu.reg_write(UC_X86_REG_AX, flags & 0xFFFF)
    emu.mu.reg_write(UC_X86_REG_DX, (flags >> 16) & 0xFFFF)
    log.debug("GetWinFlags() -> 0x%04X", flags)


def _handle_get_free_space(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetFreeSpace(UINT fuFlags) -> DWORD (bytes free)."""
    free = 4 * 1024 * 1024  # report 4 MB free
    emu.mu.reg_write(UC_X86_REG_AX, free & 0xFFFF)
    emu.mu.reg_write(UC_X86_REG_DX, (free >> 16) & 0xFFFF)
    log.debug("GetFreeSpace() -> %d", free)


def _handle_get_module_usage(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetModuleUsage(HMODULE hModule) -> int (reference count)."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("GetModuleUsage() -> 1")


def _handle_load_library(emu: SimTowerEmulator, stub: StubDef) -> None:
    """LoadLibrary(LPCSTR lpLibFileName) -> HINSTANCE

    Return a fake non-zero handle. Returning < 32 means error in Win16.
    """
    emu.mu.reg_write(UC_X86_REG_AX, 0x100)  # fake module handle
    log.debug("LoadLibrary() -> 0x0100")


def _handle_init_app(emu: SimTowerEmulator, stub: StubDef) -> None:
    """InitApp(HINSTANCE hInstance) -> BOOL. Return 1 (success)."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("InitApp() -> 1")


def _handle_init_task(emu: SimTowerEmulator, stub: StubDef) -> None:
    """InitTask() — Win16 task initialization.

    Wine's InitTask16 reads BX (stack size), CX (heap size), DS,
    then sets up instance data and returns:
      AX = 1 (success)
      BX = offset of command line in PSP (0x81)
      CX = stack limit
      DX = nCmdShow (SW_SHOW = 1)
      SI = previous instance (0)
      DI = instance handle (DGROUP selector)
      ES = PDB/PSP selector (we use DGROUP)
    """
    dgroup_sel = emu.seg_selectors.get(emu.ne.auto_data_seg, 0)
    emu.mu.reg_write(UC_X86_REG_AX, 1)  # success
    emu.mu.reg_write(UC_X86_REG_BX, 0x81)  # command line offset in PSP
    emu.mu.reg_write(UC_X86_REG_CX, 0x1000)  # stack limit
    emu.mu.reg_write(UC_X86_REG_DX, 1)  # nCmdShow = SW_SHOW
    emu.mu.reg_write(UC_X86_REG_SI, 0)  # no previous instance
    emu.mu.reg_write(UC_X86_REG_DI, dgroup_sel)  # instance handle
    emu.mu.reg_write(UC_X86_REG_ES, dgroup_sel)  # PDB selector
    log.debug("InitTask() -> AX=1 DI=%04X", dgroup_sel)


def _handle_get_cursor_pos(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetCursorPos(LPPOINT lpPoint) -> void.

    Pascal stack: [SP+4] = lpPoint (DWORD seg:off)
    Write a POINT {x=400, y=300} (center of an 800x600 screen).
    """
    ptr = _read_stack_dword(emu, 4)
    seg, off = (ptr >> 16) & 0xFFFF, ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    # POINT = {INT x, INT y} = 4 bytes total (2+2) in Win16
    struct.pack_into("<hh", (buf := bytearray(4)), 0, 400, 300)
    emu.mu.mem_write(base + off, bytes(buf))


def _handle_screen_to_client(emu: SimTowerEmulator, stub: StubDef) -> None:
    """ScreenToClient(HWND hWnd, LPPOINT lpPoint) -> void.

    Pascal stack: [SP+4] = lpPoint (DWORD), [SP+8] = hWnd (WORD)
    Convert screen coords to client — for us, no offset needed.
    """
    pass  # coordinates unchanged (our window is at 0,0)


def _handle_client_to_screen(emu: SimTowerEmulator, stub: StubDef) -> None:
    """ClientToScreen(HWND hWnd, LPPOINT lpPoint) -> void.

    No offset needed — our window is at 0,0.
    """
    pass


def _handle_get_nearest_color(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetNearestColor(HDC hdc, COLORREF crColor) -> COLORREF.

    Pascal stack: [SP+4] = crColor (DWORD), [SP+8] = hdc (WORD)
    Return the same color (we have a true-color DC).
    """
    color = _read_stack_dword(emu, 4)
    emu.mu.reg_write(UC_X86_REG_AX, color & 0xFFFF)
    emu.mu.reg_write(UC_X86_REG_DX, (color >> 16) & 0xFFFF)


def _handle_get_nearest_palette_index(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetNearestPaletteIndex(HPALETTE hPal, COLORREF crColor) -> UINT.

    Pascal stack: [SP+4] = crColor (DWORD), [SP+8] = hPal (WORD)
    Return index 0 as a reasonable default.
    """
    emu.mu.reg_write(UC_X86_REG_AX, 0)


def _handle_get_text_extent(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetTextExtent(HDC hdc, LPCSTR lpString, int nCount) -> DWORD (cx in low, cy in high).

    Pascal stack: [SP+4] = nCount (WORD), [SP+6] = lpString (DWORD), [SP+10] = hdc (WORD)
    Return approximate text dimensions: width = nCount * 8, height = 16.
    """
    n_count = _read_stack_word(emu, 4)
    width = n_count * 8  # ~8 pixels per character
    height = 16
    emu.mu.reg_write(UC_X86_REG_AX, width & 0xFFFF)
    emu.mu.reg_write(UC_X86_REG_DX, height & 0xFFFF)


def _handle_get_object(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetObject(HGDIOBJ hObj, int cbBuffer, LPVOID lpvObject) -> int.

    Pascal stack: [SP+4] = lpvObject (DWORD), [SP+8] = cbBuffer (WORD), [SP+10] = hObj (WORD)
    Zero-fill the output buffer and return cbBuffer.
    """
    lp = _read_stack_dword(emu, 4)
    cb = _read_stack_word(emu, 8)
    seg, off = (lp >> 16) & 0xFFFF, lp & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    if cb > 0 and cb < 256:
        emu.mu.mem_write(base + off, b"\x00" * cb)
    emu.mu.reg_write(UC_X86_REG_AX, cb)


def _handle_fill_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """FillRect(HDC hDC, LPCRECT lpRect, HBRUSH hBrush) -> int. Return 1."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)


def _handle_draw_text(emu: SimTowerEmulator, stub: StubDef) -> None:
    """DrawText(HDC hDC, LPCSTR lpString, int nCount, LPRECT lpRect, UINT uFormat) -> int.

    Return 16 (height of text drawn).
    """
    emu.mu.reg_write(UC_X86_REG_AX, 16)


def _handle_get_async_key_state(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetAsyncKeyState(int vKey) -> int. Return 0 (key not pressed)."""
    emu.mu.reg_write(UC_X86_REG_AX, 0)


def _handle_wvsprintf(emu: SimTowerEmulator, stub: StubDef) -> None:
    """wvsprintf(LPSTR lpOutput, LPCSTR lpFormat, va_list arglist) -> int.

    Pascal stack: [SP+4] = arglist (DWORD), [SP+8] = lpFormat (DWORD), [SP+12] = lpOutput (DWORD)
    Simple implementation handling %d, %s, %x, %u, %ld, %lu, %lx, %02d, etc.
    """
    args_ptr = _read_stack_dword(emu, 4)
    fmt_ptr = _read_stack_dword(emu, 8)
    out_ptr = _read_stack_dword(emu, 12)

    # Read format string
    fmt_seg, fmt_off = (fmt_ptr >> 16) & 0xFFFF, fmt_ptr & 0xFFFF
    fmt_base = emu.selector_bases.get(fmt_seg, 0)
    fmt_data = bytes(emu.mu.mem_read(fmt_base + fmt_off, 256))
    null = fmt_data.find(0)
    if null >= 0:
        fmt_data = fmt_data[:null]
    fmt_str = fmt_data.decode("ascii", errors="replace")

    # Read args from va_list pointer
    args_seg, args_off = (args_ptr >> 16) & 0xFFFF, args_ptr & 0xFFFF
    args_base = emu.selector_bases.get(args_seg, 0)
    args_data = bytes(emu.mu.mem_read(args_base + args_off, 64))
    arg_pos = 0

    def read_word() -> int:
        nonlocal arg_pos
        val = struct.unpack_from("<H", args_data, arg_pos)[0]
        arg_pos += 2
        return val

    def read_dword() -> int:
        nonlocal arg_pos
        val = struct.unpack_from("<I", args_data, arg_pos)[0]
        arg_pos += 4
        return val

    def read_string() -> str:
        ptr = read_dword()
        s, o = (ptr >> 16) & 0xFFFF, ptr & 0xFFFF
        b = emu.selector_bases.get(s, 0)
        d = bytes(emu.mu.mem_read(b + o, 256))
        n = d.find(0)
        return (
            d[:n].decode("ascii", errors="replace")
            if n >= 0
            else d.decode("ascii", errors="replace")
        )

    # Simple format string parser
    result = []
    i = 0
    while i < len(fmt_str):
        if fmt_str[i] == "%":
            i += 1
            if i >= len(fmt_str):
                break
            # Skip flags and width
            flags = ""
            while i < len(fmt_str) and fmt_str[i] in "-+ #0123456789.":
                flags += fmt_str[i]
                i += 1
            if i >= len(fmt_str):
                break
            # Check for 'l' prefix
            is_long = False
            if fmt_str[i] == "l":
                is_long = True
                i += 1
            if i >= len(fmt_str):
                break
            spec = fmt_str[i]
            i += 1
            if spec == "%":
                result.append("%")
            elif spec == "s":
                result.append(read_string())
            elif spec in ("d", "i"):
                val = read_dword() if is_long else read_word()
                if not is_long:
                    if val & 0x8000:
                        val = val - 0x10000
                else:
                    if val & 0x80000000:
                        val = val - 0x100000000
                py_fmt = f"%{flags}d"
                result.append(py_fmt % val)
            elif spec == "u":
                val = read_dword() if is_long else read_word()
                py_fmt = f"%{flags}d"
                result.append(py_fmt % val)
            elif spec in ("x", "X"):
                val = read_dword() if is_long else read_word()
                py_fmt = f"%{flags}{spec}"
                result.append(py_fmt % val)
            elif spec == "c":
                result.append(chr(read_word() & 0xFF))
            else:
                result.append(f"%{flags}{spec}")
        else:
            result.append(fmt_str[i])
            i += 1

    output = "".join(result)
    # Write output
    out_seg, out_off = (out_ptr >> 16) & 0xFFFF, out_ptr & 0xFFFF
    out_base = emu.selector_bases.get(out_seg, 0)
    out_bytes = output.encode("ascii", errors="replace") + b"\x00"
    emu.mu.mem_write(out_base + out_off, out_bytes)
    emu.mu.reg_write(UC_X86_REG_AX, len(output))
    log.debug("wvsprintf('%s') -> '%s' (%d chars)", fmt_str, output, len(output))


def _handle_wsprintf(emu: SimTowerEmulator, stub: StubDef) -> None:
    """_wsprintf(LPSTR buf, LPCSTR fmt, ...) -> int.

    This is cdecl (caller cleans stack). The stub has param_bytes=0.
    The return address is at SP+0 (FAR ptr = 4 bytes).
    Arguments start at SP+4: buf (DWORD), fmt (DWORD), then varargs.

    We build a va_list on the stack and call the wvsprintf handler logic.
    """
    # Read buf and fmt from stack (cdecl, after return address)
    out_ptr = _read_stack_dword(emu, 4)
    fmt_ptr = _read_stack_dword(emu, 8)

    # Read format string
    fmt_seg, fmt_off = (fmt_ptr >> 16) & 0xFFFF, fmt_ptr & 0xFFFF
    fmt_base = emu.selector_bases.get(fmt_seg, 0)
    fmt_data = bytes(emu.mu.mem_read(fmt_base + fmt_off, 256))
    null = fmt_data.find(0)
    if null >= 0:
        fmt_data = fmt_data[:null]
    fmt_str = fmt_data.decode("ascii", errors="replace")

    # Varargs start at SP+12 (after ret addr, buf, fmt)
    ss = emu.mu.reg_read(UC_X86_REG_SS)
    sp = emu.mu.reg_read(UC_X86_REG_SP)
    ss_base = emu.selector_bases.get(ss, 0)
    args_data = bytes(emu.mu.mem_read(ss_base + sp + 12, 64))
    arg_pos = 0

    def read_word() -> int:
        nonlocal arg_pos
        val = struct.unpack_from("<H", args_data, arg_pos)[0]
        arg_pos += 2
        return val

    def read_dword() -> int:
        nonlocal arg_pos
        val = struct.unpack_from("<I", args_data, arg_pos)[0]
        arg_pos += 4
        return val

    def read_string() -> str:
        ptr = read_dword()
        s, o = (ptr >> 16) & 0xFFFF, ptr & 0xFFFF
        b = emu.selector_bases.get(s, 0)
        d = bytes(emu.mu.mem_read(b + o, 256))
        n = d.find(0)
        return (
            d[:n].decode("ascii", errors="replace")
            if n >= 0
            else d.decode("ascii", errors="replace")
        )

    # Simple format string parser (same logic as wvsprintf)
    result = []
    i = 0
    while i < len(fmt_str):
        if fmt_str[i] == "%":
            i += 1
            if i >= len(fmt_str):
                break
            flags = ""
            while i < len(fmt_str) and fmt_str[i] in "-+ #0123456789.":
                flags += fmt_str[i]
                i += 1
            if i >= len(fmt_str):
                break
            is_long = False
            if fmt_str[i] == "l":
                is_long = True
                i += 1
            if i >= len(fmt_str):
                break
            spec = fmt_str[i]
            i += 1
            if spec == "%":
                result.append("%")
            elif spec == "s":
                result.append(read_string())
            elif spec in ("d", "i"):
                val = read_dword() if is_long else read_word()
                if not is_long and val & 0x8000:
                    val -= 0x10000
                elif is_long and val & 0x80000000:
                    val -= 0x100000000
                result.append(f"%{flags}d" % val)
            elif spec == "u":
                val = read_dword() if is_long else read_word()
                result.append(f"%{flags}d" % val)
            elif spec in ("x", "X"):
                val = read_dword() if is_long else read_word()
                result.append(f"%{flags}{spec}" % val)
            elif spec == "c":
                result.append(chr(read_word() & 0xFF))
            else:
                result.append(f"%{flags}{spec}")
        else:
            result.append(fmt_str[i])
            i += 1

    output = "".join(result)
    out_seg, out_off = (out_ptr >> 16) & 0xFFFF, out_ptr & 0xFFFF
    out_base = emu.selector_bases.get(out_seg, 0)
    out_bytes = output.encode("ascii", errors="replace") + b"\x00"
    emu.mu.mem_write(out_base + out_off, out_bytes)
    emu.mu.reg_write(UC_X86_REG_AX, len(output))
    log.debug("_wsprintf('%s') -> '%s' (%d chars)", fmt_str, output, len(output))


def _handle_lopen(emu: SimTowerEmulator, stub: StubDef) -> None:
    """_lopen(LPCSTR lpPathName, int iReadWrite) -> HFILE.

    Pascal stack: [SP+4] = iReadWrite (WORD), [SP+6] = lpPathName (DWORD)
    Return -1 (HFILE_ERROR) since we don't support file I/O yet.
    """
    path_ptr = _read_stack_dword(emu, 6)
    seg, off = (path_ptr >> 16) & 0xFFFF, path_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    data = bytes(emu.mu.mem_read(base + off, 260))
    null = data.find(0)
    path = data[:null].decode("ascii", errors="replace") if null >= 0 else "<unknown>"
    log.info("_lopen('%s') -> HFILE_ERROR (-1)", path)
    emu.mu.reg_write(UC_X86_REG_AX, 0xFFFF)  # HFILE_ERROR


def _handle_lcreat(emu: SimTowerEmulator, stub: StubDef) -> None:
    """_lcreat(LPCSTR lpPathName, int iAttribute) -> HFILE.

    Return -1 (HFILE_ERROR).
    """
    path_ptr = _read_stack_dword(emu, 6)
    seg, off = (path_ptr >> 16) & 0xFFFF, path_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    data = bytes(emu.mu.mem_read(base + off, 260))
    null = data.find(0)
    path = data[:null].decode("ascii", errors="replace") if null >= 0 else "<unknown>"
    log.info("_lcreat('%s') -> HFILE_ERROR (-1)", path)
    emu.mu.reg_write(UC_X86_REG_AX, 0xFFFF)


def _handle_lclose(emu: SimTowerEmulator, stub: StubDef) -> None:
    """_lclose(HFILE hFile) -> 0 on success."""
    emu.mu.reg_write(UC_X86_REG_AX, 0)


def _handle_lread(emu: SimTowerEmulator, stub: StubDef) -> None:
    """_lread(HFILE hFile, LPVOID lpBuffer, UINT uBytes) -> UINT.

    Return 0 (read 0 bytes — EOF).
    """
    emu.mu.reg_write(UC_X86_REG_AX, 0)


def _handle_lwrite(emu: SimTowerEmulator, stub: StubDef) -> None:
    """_lwrite(HFILE hFile, LPCSTR lpBuffer, UINT uBytes) -> UINT.

    Return the number of bytes "written" (uBytes).
    """
    cb = _read_stack_word(emu, 4)
    emu.mu.reg_write(UC_X86_REG_AX, cb)


def _handle_llseek(emu: SimTowerEmulator, stub: StubDef) -> None:
    """_llseek(HFILE hFile, LONG lOffset, int iOrigin) -> LONG.

    Return 0 (current position = 0).
    """
    emu.mu.reg_write(UC_X86_REG_AX, 0)
    emu.mu.reg_write(UC_X86_REG_DX, 0)


def _handle_get_scroll_range(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetScrollRange(HWND hWnd, int nBar, LPINT lpMinPos, LPINT lpMaxPos) -> void.

    Pascal stack: [SP+4] = lpMaxPos (DWORD), [SP+8] = lpMinPos (DWORD),
                  [SP+12] = nBar (WORD), [SP+14] = hWnd (WORD)
    Write 0 for min and 100 for max.
    """
    max_ptr = _read_stack_dword(emu, 4)
    min_ptr = _read_stack_dword(emu, 8)
    for ptr, val in [(min_ptr, 0), (max_ptr, 100)]:
        seg, off = (ptr >> 16) & 0xFFFF, ptr & 0xFFFF
        base = emu.selector_bases.get(seg, 0)
        emu.mu.mem_write(base + off, struct.pack("<H", val))


def _handle_get_text_align(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetTextAlign(HDC hdc) -> UINT. Return 0 (TA_LEFT|TA_TOP)."""
    emu.mu.reg_write(UC_X86_REG_AX, 0)


def _handle_set_text_align(emu: SimTowerEmulator, stub: StubDef) -> None:
    """SetTextAlign(HDC hdc, UINT fMode) -> UINT. Return previous alignment (0)."""
    emu.mu.reg_write(UC_X86_REG_AX, 0)


def _handle_wave_out_get_dev_caps(emu: SimTowerEmulator, stub: StubDef) -> None:
    """waveOutGetDevCaps(UINT uDeviceID, LPWAVEOUTCAPS lpCaps, UINT uSize) -> UINT.

    Return MMSYSERR_NOERROR (0). Zero-fill the caps structure.
    """
    lp = _read_stack_dword(emu, 6)
    size = _read_stack_word(emu, 4)
    seg, off = (lp >> 16) & 0xFFFF, lp & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    if size > 0 and size < 256:
        emu.mu.mem_write(base + off, b"\x00" * size)
    emu.mu.reg_write(UC_X86_REG_AX, 0)


def _handle_write_profile_string(emu: SimTowerEmulator, stub: StubDef) -> None:
    """WriteProfileString(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString) -> BOOL.

    Return TRUE (1). We don't persist anything.
    """
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("WriteProfileString() -> 1")


def _handle_dialog_box_param(emu: SimTowerEmulator, stub: StubDef) -> None:
    """DialogBoxParam(...) -> int. Return IDOK (1)."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("DialogBoxParam() -> IDOK (1)")


def _handle_create_dialog_param(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateDialogParam(...) -> HWND. Return a fake window handle."""
    emu._next_hwnd += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_hwnd)
    log.debug("CreateDialogParam() -> hwnd=0x%04X", emu._next_hwnd)


# Handler dispatch table: (module, ordinal) -> handler function
STUB_HANDLERS: dict[tuple[str, int], StubHandler] = {
    # KERNEL — memory management
    ("KERNEL", 15): _handle_global_alloc,
    ("KERNEL", 16): _handle_global_realloc,
    ("KERNEL", 17): _handle_global_free,
    ("KERNEL", 18): _handle_global_lock,
    ("KERNEL", 19): _handle_global_unlock,
    ("KERNEL", 20): _handle_global_size,
    ("KERNEL", 21): _handle_global_handle,
    ("KERNEL", 22): _handle_global_flags,
    ("KERNEL", 25): _handle_global_compact,
    # KERNEL — task/module
    ("KERNEL", 30): lambda emu, stub: log.debug("WaitEvent() -> no-op"),
    ("KERNEL", 36): _handle_get_current_task,
    ("KERNEL", 48): _handle_get_module_usage,
    ("KERNEL", 49): _handle_get_module_filename,
    ("KERNEL", 51): _handle_make_proc_instance,
    ("KERNEL", 52): _handle_free_proc_instance,
    ("KERNEL", 60): _handle_find_resource,
    ("KERNEL", 61): _handle_load_resource,
    ("KERNEL", 62): _handle_lock_resource,
    ("KERNEL", 63): _handle_free_resource,
    # KERNEL — string ops
    ("KERNEL", 88): _handle_lstrcpy,
    ("KERNEL", 89): _handle_lstrcat,
    ("KERNEL", 90): _handle_lstrlen,
    # KERNEL — system
    ("KERNEL", 58): _handle_get_profile_string,
    ("KERNEL", 91): _handle_init_task,
    ("KERNEL", 95): _handle_load_library,
    ("KERNEL", 115): _handle_output_debug_string,
    ("KERNEL", 127): _handle_get_private_profile_int,
    ("KERNEL", 132): _handle_get_win_flags,
    ("KERNEL", 169): _handle_get_free_space,
    ("KERNEL", 348): _handle_hmemcpy,
    # GDI — queries
    ("GDI", 93): _handle_get_text_metrics,
    ("GDI", 313): _handle_get_rasterizer_caps,
    # GDI — DC management
    ("GDI", 30): _handle_save_dc,
    ("GDI", 52): _handle_create_compatible_dc,
    ("GDI", 68): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # DeleteDC
    ("GDI", 69): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # DeleteObject
    ("GDI", 80): _handle_get_device_caps,
    ("GDI", 45): _handle_select_object,
    ("GDI", 87): _handle_get_stock_object,
    # GDI — object creation
    ("GDI", 48): _handle_create_bitmap,
    ("GDI", 51): _handle_create_compatible_bitmap,
    ("GDI", 57): _handle_create_font_indirect,
    ("GDI", 61): _handle_create_pen,
    ("GDI", 65): _handle_create_rect_rgn,
    ("GDI", 66): _handle_create_solid_brush,
    # GDI — palette
    ("GDI", 360): _handle_create_palette,
    ("GDI", 363): _handle_get_palette_entries,
    # USER — window management
    ("USER", 1): _handle_message_box,
    ("USER", 5): _handle_init_app,
    ("USER", 10): _handle_set_timer,
    ("USER", 13): _handle_get_tick_count,
    ("USER", 32): _handle_get_window_rect,
    ("USER", 33): _handle_get_client_rect,
    ("USER", 41): _handle_create_window,
    ("USER", 42): _handle_show_window,
    ("USER", 57): _handle_register_class,
    ("USER", 66): _handle_get_dc,
    ("USER", 67): _handle_get_dc,  # GetWindowDC same as GetDC for us
    ("USER", 68): _handle_release_dc,
    # Rect operations
    ("USER", 72): _handle_set_rect,
    ("USER", 73): _handle_set_rect_empty,
    ("USER", 74): _handle_copy_rect,
    ("USER", 75): _handle_is_rect_empty,
    ("USER", 76): _handle_pt_in_rect,
    ("USER", 77): _handle_offset_rect,
    ("USER", 78): _handle_inflate_rect,
    ("USER", 79): _handle_intersect_rect,
    ("USER", 80): _handle_union_rect,
    ("USER", 109): _handle_peek_message,
    ("USER", 124): _handle_update_window,
    ("USER", 157): _handle_get_menu,
    ("USER", 159): _handle_get_sub_menu,
    ("USER", 173): _handle_load_cursor,
    ("USER", 174): _handle_load_icon,
    ("USER", 177): _handle_load_accelerators,
    ("USER", 179): _handle_get_system_metrics,
    ("USER", 244): _handle_equal_rect,
    ("USER", 249): _handle_get_async_key_state,
    ("USER", 282): _handle_select_palette,
    ("USER", 283): _handle_realize_palette,
    ("USER", 286): _handle_get_desktop_window,
    # USER — input
    ("USER", 17): _handle_get_cursor_pos,
    ("USER", 28): _handle_client_to_screen,
    ("USER", 29): _handle_screen_to_client,
    ("USER", 69): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # SetCursor -> prev cursor
    # USER — window ops (return success)
    ("USER", 31): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # IsIconic -> FALSE
    ("USER", 34): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # EnableWindow
    ("USER", 37): lambda emu, stub: None,  # SetWindowText (void)
    ("USER", 47): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 1
    ),  # IsWindow -> TRUE
    ("USER", 53): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # DestroyWindow
    ("USER", 56): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # MoveWindow
    ("USER", 62): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # SetScrollPos -> prev
    ("USER", 63): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 0),  # GetScrollPos
    ("USER", 64): lambda emu, stub: None,  # SetScrollRange (void)
    ("USER", 65): _handle_get_scroll_range,
    ("USER", 110): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # PostMessage
    ("USER", 113): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # TranslateMessage
    ("USER", 114): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # DispatchMessage
    ("USER", 125): lambda emu, stub: None,  # InvalidateRect (void)
    ("USER", 127): lambda emu, stub: None,  # ValidateRect (void)
    ("USER", 130): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # SetClassWord -> prev
    ("USER", 134): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # SetWindowWord -> prev
    ("USER", 154): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # CheckMenuItem -> prev
    ("USER", 155): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # EnableMenuItem -> prev
    ("USER", 180): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # GetSysColor -> 0 (black)
    ("USER", 232): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # SetWindowPos
    ("USER", 263): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 5
    ),  # GetMenuItemCount
    ("USER", 410): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # InsertMenu
    ("USER", 413): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # RemoveMenu
    ("USER", 458): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 1
    ),  # DestroyCursor
    ("USER", 466): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 0),  # DragDetect
    ("USER", 59): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # SetActiveWindow -> prev
    ("USER", 60): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0x101
    ),  # GetActiveWindow -> main hwnd
    ("USER", 225): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # EnumTaskWindows -> done
    # USER — drawing
    ("USER", 81): _handle_fill_rect,
    ("USER", 85): _handle_draw_text,
    # USER — dialogs
    ("USER", 87): _handle_dialog_box_param,  # DialogBox
    ("USER", 218): _handle_dialog_box_param,  # DialogBoxIndirect
    ("USER", 239): _handle_dialog_box_param,  # DialogBoxParam
    ("USER", 240): _handle_dialog_box_param,  # DialogBoxIndirectParam
    ("USER", 219): _handle_create_dialog_param,  # CreateDialogIndirect
    ("USER", 241): _handle_create_dialog_param,  # CreateDialogParam
    # USER — strings
    ("USER", 420): _handle_wsprintf,
    ("USER", 421): _handle_wvsprintf,
    # KERNEL — misc
    ("KERNEL", 59): _handle_write_profile_string,
    ("KERNEL", 113): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 3
    ),  # __AHSHIFT -> 3
    ("KERNEL", 137): lambda emu, stub: log.warning(
        "FatalAppExit called!"
    ),  # FatalAppExit
    # KERNEL — file I/O
    ("KERNEL", 81): _handle_lclose,
    ("KERNEL", 82): _handle_lread,
    ("KERNEL", 83): _handle_lcreat,
    ("KERNEL", 84): _handle_llseek,
    ("KERNEL", 85): _handle_lopen,
    ("KERNEL", 86): _handle_lwrite,
    # GDI — queries/color
    ("GDI", 82): _handle_get_object,
    ("GDI", 91): _handle_get_text_extent,
    ("GDI", 154): _handle_get_nearest_color,
    ("GDI", 345): _handle_get_text_align,
    ("GDI", 346): _handle_set_text_align,
    ("GDI", 370): _handle_get_nearest_palette_index,
    # GDI — drawing (return success)
    ("GDI", 1): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, _read_stack_dword(emu, 4) & 0xFFFF
    ),  # SetBkColor -> prev color
    ("GDI", 2): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # SetBkMode
    ("GDI", 9): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # SetTextColor -> prev (0=black)
    ("GDI", 19): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # LineTo
    ("GDI", 20): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # MoveTo -> prev pos (packed DWORD)
    ("GDI", 27): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # Rectangle
    ("GDI", 29): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # PatBlt
    ("GDI", 33): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # TextOut
    ("GDI", 34): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # BitBlt
    ("GDI", 39): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # RestoreDC
    ("GDI", 44): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # SelectClipRgn
    ("GDI", 78): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # GetCurrentPosition
    ("GDI", 366): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # UpdateColors
    ("GDI", 367): lambda emu, stub: None,  # AnimatePalette (void)
    ("GDI", 443): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 1
    ),  # SetDIBitsToDevice
    # MMSYSTEM
    ("MMSYSTEM", 402): _handle_wave_out_get_dev_caps,
    # USER — misc remaining
    ("USER", 6): lambda emu, stub: None,  # PostQuitMessage (void)
    ("USER", 12): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # KillTimer
    ("USER", 16): lambda emu, stub: None,  # ClipCursor (void)
    ("USER", 18): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # SetCapture -> prev hwnd
    ("USER", 19): lambda emu, stub: None,  # ReleaseCapture (void)
    ("USER", 22): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # SetFocus -> prev focus
    ("USER", 39): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, emu._next_handle
    ),  # BeginPaint -> HDC
    ("USER", 40): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # EndPaint
    ("USER", 83): _handle_fill_rect,  # FrameRect
    ("USER", 88): lambda emu, stub: None,  # EndDialog (void)
    ("USER", 90): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # IsDialogMessage
    ("USER", 91): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # GetDlgItem -> 0
    ("USER", 92): lambda emu, stub: None,  # SetDlgItemText (void)
    ("USER", 93): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # GetDlgItemText -> 0 chars
    ("USER", 94): lambda emu, stub: None,  # SetDlgItemInt (void)
    ("USER", 95): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # GetDlgItemInt -> 0
    ("USER", 101): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # SendDlgItemMessage
    ("USER", 104): lambda emu, stub: None,  # MessageBeep (void)
    ("USER", 107): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # DefWindowProc
    ("USER", 171): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # WinHelp
    ("USER", 178): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # TranslateAccelerator
    ("USER", 186): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # SwapMouseButton
    ("USER", 221): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # ScrollDC
    ("USER", 229): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 0),  # GetTopWindow
    # COMMDLG
    ("COMMDLG", 1): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # GetOpenFileName -> cancel
    # WAVMIX16 (all no-op, return 0)
    ("WAVMIX16", 3): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # WavMixInit -> NULL (no audio)
    ("WAVMIX16", 4): lambda emu, stub: None,  # WavMixActivate
    ("WAVMIX16", 5): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # WavMixOpenChannel
    ("WAVMIX16", 6): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # WavMixOpenWav
    ("WAVMIX16", 7): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 0),  # WavMixPlay
    ("WAVMIX16", 9): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # WavMixFlushChannel
    ("WAVMIX16", 10): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # WavMixCloseChannel
    ("WAVMIX16", 11): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # WavMixCloseSession
    ("WAVMIX16", 12): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 0
    ),  # WavMixFreeWav
    # WING
    ("WING", 1001): _handle_wing_create_dc,
    ("WING", 1002): _handle_wing_recommend_dib,
    ("WING", 1003): _handle_wing_create_bitmap,
    ("WING", 1005): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 256
    ),  # WinGGetDIBColorTable -> 256
    ("WING", 1006): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 256
    ),  # WinGSetDIBColorTable -> 256
    ("WING", 1009): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, 1
    ),  # WinGStretchBlt
    ("WING", 1010): lambda emu, stub: emu.mu.reg_write(UC_X86_REG_AX, 1),  # WinGBitBlt
    # WIN87EM
    ("WIN87EM", 1): _handle_fpmath,
}


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
        """Return the linear base of the sim/entity table, or None."""
        return self._resolve_near_or_selector(self._ds_u16(DS_OFF["sim_table_ptr"]))

    def _read_sim_record(self, base: int, idx: int) -> dict:
        off = base + idx * SIM_REC_SIZE
        rec = bytes(self.mu.mem_read(off, SIM_REC_SIZE))
        sample_count = rec[9]
        accumulated = struct.unpack_from("<H", rec, 14)[0]
        stress = (0x1000 // sample_count) if sample_count > 0 else 0
        return {
            "floor": rec[0],
            "subtype": rec[1],
            "occupant": struct.unpack_from("<H", rec, 2)[0],
            "family": rec[4],
            "state": rec[5],
            "aux": (rec[6], rec[7], rec[8]),
            "samples": sample_count,
            "accumulated": accumulated,
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

    def dump_tick_state(self) -> None:
        """Print a summary of the current simulation state."""
        d = DS_OFF
        day_tick = self._ds_u16(d["day_tick"])
        day_counter = self._ds_i32(d["day_counter"])
        daypart = self._ds_u8(d["daypart_index"])
        stars = self._ds_u16(d["star_count"])
        cash = self._ds_i32(d["cash_balance"]) * 100
        cal_phase = self._ds_u8(d["calendar_phase"])
        metro = self._ds_i16(d["metro_floor"])
        pop = self._ds_i32(d["primary_family_ledger_total"])

        print(
            f"TICK day={day_counter} tick={day_tick} daypart={daypart} "
            f"stars={stars} cash=${cash:,} cal_phase={cal_phase} "
            f"metro={metro} pop={pop}"
        )

        # Gate flags
        flags = []
        if self._ds_u8(d["security_placed"]):
            flags.append("sec")
        if self._ds_u8(d["office_placed"]):
            flags.append("ofc")
        if self._ds_u8(d["recycling_ok"]):
            flags.append("rec")
        if self._ds_u8(d["route_viable"]):
            flags.append("rte")
        if flags:
            print(f"  gates: {' '.join(flags)}")

        # Floor objects summary
        type_counts: dict[int, int] = defaultdict(int)
        floors_with_objects = 0
        for fi in range(120):
            objs = self._read_floor_objects(fi)
            if objs:
                floors_with_objects += 1
                for o in objs:
                    type_counts[o["type"]] += 1
        if type_counts:
            items = sorted(type_counts.items(), key=lambda x: -x[1])
            parts = [f"{FAMILY_NAMES.get(t, f'0x{t:02x}')}:{n}" for t, n in items]
            print(f"  objects ({floors_with_objects} floors): {' '.join(parts)}")

        # Sim table summary
        sim_base = self._resolve_sim_table_base()
        sim_count = self._ds_i32(d["sim_count"])
        if sim_base is None or sim_count <= 0:
            return

        family_counts: dict[int, int] = defaultdict(int)
        family_stress: dict[int, list[int]] = defaultdict(list)
        state_hist: dict[int, dict[int, int]] = defaultdict(lambda: defaultdict(int))

        count = min(sim_count, 4096)  # safety cap
        for i in range(count):
            rec = self._read_sim_record(sim_base, i)
            fam = rec["family"]
            if fam == 0 and rec["state"] == 0:
                continue  # skip empty slots
            family_counts[fam] += 1
            if rec["stress"] > 0:
                family_stress[fam].append(rec["stress"])
            state_hist[fam][rec["state"]] += 1

        if not family_counts:
            print("  (no active sims)")
            return

        # Print per-family summary
        for fam in sorted(family_counts):
            label = FAMILY_NAMES.get(fam, f"0x{fam:02x}")
            n = family_counts[fam]
            stresses = family_stress.get(fam, [])
            avg_stress = sum(stresses) // len(stresses) if stresses else 0
            states = state_hist[fam]
            top_states = sorted(states.items(), key=lambda x: -x[1])[:4]
            st_str = " ".join(f"0x{s:02x}:{c}" for s, c in top_states)
            print(
                f"  {label:14s} n={n:4d}  avg_stress={avg_stress:4d}  states=[{st_str}]"
            )

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


def main() -> None:
    import sys

    logging.basicConfig(
        level=logging.INFO, format="%(name)s %(levelname)s: %(message)s"
    )

    exe_path = sys.argv[1] if len(sys.argv) > 1 else "src/simtower/SIMTOWER.EXE"
    mode = sys.argv[2] if len(sys.argv) > 2 else "run"
    dump_interval = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    max_insns = int(sys.argv[4]) if len(sys.argv) > 4 else 50_000_000

    emu = SimTowerEmulator(exe_path)
    emu._install_scheduler_hook(dump_interval=dump_interval)
    print(f"Initial registers: {emu.dump_regs()}")

    if mode == "build":
        # Demo: run through init, build objects, then continue simulation
        print("\n=== Phase 1: Run through initialization ===")
        try:
            emu.run(max_instructions=5_000_000)
        except RuntimeError as e:
            print(f"Init stopped: {e}")

        print("\n=== Phase 2: Build objects ===")
        emu.dump_tick_state()

        # Bootstrap a lobby on floor 0 using direct write (lobby uses drag
        # placer in the binary, so we bypass validation here)
        emu.write_floor_object_direct(0, type_code=0x18, left_tile=100, right_tile=200)

        # Set up support spans for above-grade floors.  Support for floor N
        # is derived from the floor blob of floor N-1, so this ensures blobs
        # exist below each target floor with a wide-enough span header.
        for fl in range(1, 11):
            emu.setup_floor_support(fl, left_tile=100, right_tile=200)

        # Place objects via the binary's placement function
        placements = [
            (7, 1, 100, 108),  # Office (8 tiles)
            (7, 1, 108, 116),  # Office
            (7, 1, 116, 124),  # Office
            (3, 2, 100, 104),  # Single hotel (4 tiles)
            (3, 2, 104, 108),  # Single hotel
            (3, 2, 108, 112),  # Single hotel
            (9, 3, 100, 104),  # Condo (4 tiles)
            (9, 3, 104, 108),  # Condo
            (0xA, 1, 124, 132),  # Fast food (8 tiles)
            (0xC, 1, 132, 148),  # Restaurant (16 tiles)
            (6, 1, 148, 156),  # Retail (8 tiles)
        ]
        for typ, fl, left, right in placements:
            emu.build_object(
                type_code=typ, floor_logical=fl, left_tile=left, right_tile=right
            )

        print("\n=== Phase 3: Continue simulation ===")
        emu.dump_tick_state()
        try:
            emu.run(max_instructions=max_insns)
        except RuntimeError as e:
            print(f"Stopped: {e}")
    else:
        try:
            emu.run(max_instructions=max_insns)
        except RuntimeError as e:
            print(f"Stopped: {e}")

    print(f"\nFinal registers: {emu.dump_regs()}")
    print(f"Scheduler entered {emu._tick_hook_count} times")
    if emu._tick_hook_count > 0:
        print("\n--- Final state ---")
        emu.dump_tick_state()


if __name__ == "__main__":
    main()
