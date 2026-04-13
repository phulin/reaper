"""Shared helpers for stub handler modules."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from unicorn.x86_const import UC_X86_REG_AX, UC_X86_REG_SP, UC_X86_REG_SS

from simtower.constants import StubHandler
from simtower.stubs import StubDef

if TYPE_CHECKING:
    from simtower.emulator import SimTowerEmulator


def _ret(value: int) -> StubHandler:
    """Return a stub handler that sets AX to *value*."""
    def handler(emu: SimTowerEmulator, stub: StubDef) -> None:
        emu.mu.reg_write(UC_X86_REG_AX, value)
    return handler


def _nop(emu: SimTowerEmulator, stub: StubDef) -> None:
    """Stub handler that does nothing (for void Win16 APIs)."""


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
