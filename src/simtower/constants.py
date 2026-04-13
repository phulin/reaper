"""SimTower emulator constants: memory layout, DS offsets, lookup tables."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from simtower.emulator import SimTowerEmulator
    from simtower.stubs import StubDef

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

# sample_lcg15 (RNG) lives in NE segment 1 at offset 0x324d.
RNG_NE_SEG = 1
RNG_SEG_OFFSET = 0x324D

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

# place_stairs_or_escalator_link: Ghidra 0x1200149c = NE seg 65, offset 0x149c
PLACE_STAIRS_NE_SEG = 65
PLACE_STAIRS_OFFSET = 0x149C

# Family code → human label (most common families)
FAMILY_NAMES: dict[int, str] = {
    3: "single",
    4: "twin",
    5: "suite",
    6: "restaurant",
    7: "office",
    9: "condo",
    0xA: "retail",
    0xC: "fast-food",
    0xE: "security",
    0xF: "housekeeping",
    0x12: "entertainment",
    0x1D: "cinema",
    0x21: "cathedral",
    0x24: "cathedral-a",
    0x25: "cathedral-b",
    0x26: "cathedral-c",
    0x27: "cathedral-d",
    0x28: "cathedral-e",
}

# Family code → tile width (from binary recovery: segment 1200 jump table)
FACILITY_WIDTHS: dict[int, int] = {
    0x00: 1,   # floor
    0x01: 4,   # std elevator
    0x03: 4,   # single room
    0x04: 8,   # twin room
    0x05: 16,  # suite
    0x06: 24,  # restaurant
    0x07: 9,   # office
    0x08: 2,
    0x09: 16,  # condo
    0x0A: 12,  # retail
    0x0B: 1,   # lobby
    0x0C: 16,  # fast-food
    0x0D: 26,  # sky lobby / medical
    0x0E: 8,   # security
    0x12: 24,  # cinema
    0x13: 24,  # cinema (lower)
    0x14: 8,   # recycling
    0x16: 8,   # stairs
    0x17: 8,
    0x18: 4,   # parking
    0x1B: 8,   # escalator
    0x1C: 8,
    0x1D: 24,  # party hall
    0x1E: 24,  # party hall (lower)
    0x1F: 30,  # VIP suite
    0x20: 30,
    0x21: 30,
    0x22: 7,   # entertainment link half
    0x23: 7,
    0x24: 28,  # cathedral
    0x25: 28,
    0x26: 28,
    0x27: 28,
    0x28: 28,
    0x2A: 6,   # express elevator
    0x2B: 4,   # service elevator
    0x2C: 1,   # vertical anchor
    0x30: 8,
}

# Sim state byte → human label (from PEOPLE.md / OFFICE.md state machines)
# Bit 6 (0x40) = in-transit flag; 0x4x = transit for 0x0x, 0x6x = transit for 0x2x
SIM_STATE_NAMES: dict[int, str] = {
    0x00: "at-work",
    0x01: "lunch-start",
    0x02: "lunch-return",
    0x03: "arrived",
    0x04: "sibling-sync",
    0x05: "evening-dep",
    0x10: "idle-ready",
    0x20: "morning-in",
    0x21: "to-office",
    0x22: "from-lunch",
    0x23: "at-lunch",
    0x24: "vacant",
    0x25: "park-open",
    0x26: "park-fail",
    0x27: "parked",
    0x40: "T-to-work",
    0x41: "T-to-lunch",
    0x42: "T-lunch-ret",
    0x45: "T-evening",
    0x60: "T-morning",
    0x61: "T-to-office",
    0x62: "T-from-lunch",
    0x63: "T-at-lunch",
}

# Type alias for stub handler functions
StubHandler = Callable[["SimTowerEmulator", "StubDef"], None]


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
