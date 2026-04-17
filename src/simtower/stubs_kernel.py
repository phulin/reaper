"""Win16 KERNEL API stub handlers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CX,
    UC_X86_REG_DI,
    UC_X86_REG_DX,
    UC_X86_REG_ES,
    UC_X86_REG_SI,
)

from simtower.constants import StubHandler
from simtower.stub_helpers import _read_stack_dword, _read_stack_word, _ret
from simtower.stubs import StubDef

if TYPE_CHECKING:
    from simtower.emulator import SimTowerEmulator

log = logging.getLogger(__name__)


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


def _handle_global_handle(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalHandle(UINT wMem) -> DWORD (handle in DX:AX)"""
    w_mem = _read_stack_word(emu, 4)
    handle = emu.heap.handle_for_selector(w_mem)
    emu.mu.reg_write(UC_X86_REG_DX, handle)
    emu.mu.reg_write(UC_X86_REG_AX, handle)


def _handle_global_flags(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalFlags(HGLOBAL hMem) -> UINT"""
    h_mem = _read_stack_word(emu, 4)
    emu.mu.reg_write(UC_X86_REG_AX, emu.heap.flags(h_mem))


def _handle_global_compact(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GlobalCompact(DWORD dwMinFree) -> DWORD (largest free block)"""
    # Return a large value to indicate plenty of memory
    emu.mu.reg_write(UC_X86_REG_DX, 0x0040)  # ~4 MB
    emu.mu.reg_write(UC_X86_REG_AX, 0x0000)


def _handle_get_current_task(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetCurrentTask() -> HTASK (must be non-zero)."""
    emu.mu.reg_write(UC_X86_REG_AX, 0x1234)  # fake task handle
    log.debug("GetCurrentTask() -> 0x1234")


def _handle_get_module_usage(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetModuleUsage(HMODULE hModule) -> int (reference count)."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("GetModuleUsage() -> 1")


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


def _handle_load_library(emu: SimTowerEmulator, stub: StubDef) -> None:
    """LoadLibrary(LPCSTR lpLibFileName) -> HINSTANCE

    Return a fake non-zero handle. Returning < 32 means error in Win16.
    """
    emu.mu.reg_write(UC_X86_REG_AX, 0x100)  # fake module handle
    log.debug("LoadLibrary() -> 0x0100")


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


def _handle_write_profile_string(emu: SimTowerEmulator, stub: StubDef) -> None:
    """WriteProfileString(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString) -> BOOL.

    Return TRUE (1). We don't persist anything.
    """
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("WriteProfileString() -> 1")


def _handle_lclose(emu: SimTowerEmulator, stub: StubDef) -> None:
    """_lclose(HFILE hFile) -> 0 on success."""
    emu.mu.reg_write(UC_X86_REG_AX, 0)


def _handle_lread(emu: SimTowerEmulator, stub: StubDef) -> None:
    """_lread(HFILE hFile, LPVOID lpBuffer, UINT uBytes) -> UINT.

    Return 0 (read 0 bytes — EOF).
    """
    emu.mu.reg_write(UC_X86_REG_AX, 0)


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


def _handle_llseek(emu: SimTowerEmulator, stub: StubDef) -> None:
    """_llseek(HFILE hFile, LONG lOffset, int iOrigin) -> LONG.

    Return 0 (current position = 0).
    """
    emu.mu.reg_write(UC_X86_REG_AX, 0)
    emu.mu.reg_write(UC_X86_REG_DX, 0)


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


def _handle_lwrite(emu: SimTowerEmulator, stub: StubDef) -> None:
    """_lwrite(HFILE hFile, LPCSTR lpBuffer, UINT uBytes) -> UINT.

    Return the number of bytes "written" (uBytes).
    """
    cb = _read_stack_word(emu, 4)
    emu.mu.reg_write(UC_X86_REG_AX, cb)


STUB_HANDLERS_KERNEL: dict[tuple[str, int], StubHandler] = {
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
    # KERNEL — misc
    ("KERNEL", 59): _handle_write_profile_string,
    ("KERNEL", 113): _ret(3),  # __AHSHIFT -> 3
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
}
