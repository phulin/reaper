"""Win16 GlobalAlloc heap manager for the SimTower emulator."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from simtower.emulator import SimTowerEmulator

from simtower.constants import HEAP_BASE, MEM_SIZE

log = logging.getLogger(__name__)


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
