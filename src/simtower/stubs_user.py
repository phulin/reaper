"""Win16 USER API stub handlers."""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_DX,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)

from simtower.constants import StubHandler
from simtower.stub_helpers import _nop, _read_stack_dword, _read_stack_word, _ret
from simtower.stubs import StubDef

if TYPE_CHECKING:
    from simtower.emulator import SimTowerEmulator

log = logging.getLogger(__name__)


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




def _handle_init_app(emu: SimTowerEmulator, stub: StubDef) -> None:
    """InitApp(HINSTANCE hInstance) -> BOOL. Return 1 (success)."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("InitApp() -> 1")




def _handle_set_timer(emu: SimTowerEmulator, stub: StubDef) -> None:
    """SetTimer(HWND hWnd, UINT nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc) -> UINT."""
    n_id = _read_stack_word(emu, 8)  # nIDEvent
    emu.mu.reg_write(UC_X86_REG_AX, n_id if n_id else 1)
    log.debug("SetTimer(id=%d) -> %d", n_id, n_id if n_id else 1)




def _handle_get_tick_count(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetTickCount() -> DWORD (milliseconds since boot)."""
    emu._tick_count += 55  # ~18.2 Hz tick
    emu.mu.reg_write(UC_X86_REG_AX, emu._tick_count & 0xFFFF)
    emu.mu.reg_write(UC_X86_REG_DX, (emu._tick_count >> 16) & 0xFFFF)




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




def _handle_create_window(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateWindow(...) -> HWND (non-zero on success)."""
    emu._next_hwnd += 1
    hwnd = emu._next_hwnd
    emu.mu.reg_write(UC_X86_REG_AX, hwnd)
    log.debug("CreateWindow() -> hwnd=0x%04X", hwnd)




def _handle_show_window(emu: SimTowerEmulator, stub: StubDef) -> None:
    """ShowWindow(HWND hWnd, int nCmdShow) -> BOOL (previous visibility)."""
    emu.mu.reg_write(UC_X86_REG_AX, 0)  # was not visible before
    log.debug("ShowWindow() -> 0")




def _handle_register_class(emu: SimTowerEmulator, stub: StubDef) -> None:
    """RegisterClass(LPWNDCLASS lpWndClass) -> ATOM (non-zero on success)."""
    emu._next_atom += 1
    atom = emu._next_atom
    emu.mu.reg_write(UC_X86_REG_AX, atom)
    log.debug("RegisterClass() -> atom=0x%04X", atom)




def _handle_get_dc(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetDC(HWND hWnd) -> HDC."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("GetDC() -> 0x%04X", emu._next_handle)




def _handle_release_dc(emu: SimTowerEmulator, stub: StubDef) -> None:
    """ReleaseDC(HWND hWnd, HDC hDC) -> int."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)




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




def _handle_is_rect_empty(emu: SimTowerEmulator, stub: StubDef) -> None:
    """IsRectEmpty(LPRECT lprc) -> BOOL."""
    rc_ptr = _read_stack_dword(emu, 4)
    seg, off = (rc_ptr >> 16) & 0xFFFF, rc_ptr & 0xFFFF
    base = emu.selector_bases.get(seg, 0)
    left, top, right, bottom = struct.unpack("<hhhh", emu.mu.mem_read(base + off, 8))
    result = 1 if (left >= right or top >= bottom) else 0
    emu.mu.reg_write(UC_X86_REG_AX, result)




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




def _handle_peek_message(emu: SimTowerEmulator, stub: StubDef) -> None:
    """PeekMessage(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg) -> BOOL.

    Return 0 (no message available) to let the idle loop proceed.
    """
    emu.mu.reg_write(UC_X86_REG_AX, 0)




def _handle_update_window(emu: SimTowerEmulator, stub: StubDef) -> None:
    """UpdateWindow(HWND hWnd) -> BOOL."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("UpdateWindow() -> 1")




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




def _handle_load_cursor(emu: SimTowerEmulator, stub: StubDef) -> None:
    """LoadCursor(HINSTANCE hInst, LPCSTR lpCursorName) -> HCURSOR."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("LoadCursor() -> 0x%04X", emu._next_handle)




def _handle_load_icon(emu: SimTowerEmulator, stub: StubDef) -> None:
    """LoadIcon(HINSTANCE hInst, LPCSTR lpIconName) -> HICON."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("LoadIcon() -> 0x%04X", emu._next_handle)




def _handle_load_accelerators(emu: SimTowerEmulator, stub: StubDef) -> None:
    """LoadAccelerators(HINSTANCE hInst, LPCSTR lpTableName) -> HACCEL."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("LoadAccelerators() -> 0x%04X", emu._next_handle)




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




def _handle_equal_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """EqualRect(LPRECT lprc1, LPRECT lprc2) -> BOOL."""
    r1_ptr = _read_stack_dword(emu, 4)
    r2_ptr = _read_stack_dword(emu, 8)

    def read_rect(ptr):
        seg, off = (ptr >> 16) & 0xFFFF, ptr & 0xFFFF
        base = emu.selector_bases.get(seg, 0)
        return bytes(emu.mu.mem_read(base + off, 8))

    emu.mu.reg_write(UC_X86_REG_AX, 1 if read_rect(r1_ptr) == read_rect(r2_ptr) else 0)




def _handle_get_async_key_state(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetAsyncKeyState(int vKey) -> int. Return 0 (key not pressed)."""
    emu.mu.reg_write(UC_X86_REG_AX, 0)




def _handle_select_palette(emu: SimTowerEmulator, stub: StubDef) -> None:
    """SelectPalette(HDC hdc, HPALETTE hpal, BOOL bForceBackground) -> HPALETTE."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("SelectPalette() -> previous palette handle")




def _handle_realize_palette(emu: SimTowerEmulator, stub: StubDef) -> None:
    """RealizePalette(HDC hdc) -> UINT (number of entries mapped)."""
    emu.mu.reg_write(UC_X86_REG_AX, 256)
    log.debug("RealizePalette() -> 256")




def _handle_get_desktop_window(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetDesktopWindow() -> HWND."""
    emu.mu.reg_write(UC_X86_REG_AX, 0x0001)  # fake desktop HWND
    log.debug("GetDesktopWindow() -> 0x0001")




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




def _handle_client_to_screen(emu: SimTowerEmulator, stub: StubDef) -> None:
    """ClientToScreen(HWND hWnd, LPPOINT lpPoint) -> void.

    No offset needed — our window is at 0,0.
    """
    pass




def _handle_screen_to_client(emu: SimTowerEmulator, stub: StubDef) -> None:
    """ScreenToClient(HWND hWnd, LPPOINT lpPoint) -> void.

    Pascal stack: [SP+4] = lpPoint (DWORD), [SP+8] = hWnd (WORD)
    Convert screen coords to client — for us, no offset needed.
    """
    pass  # coordinates unchanged (our window is at 0,0)




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




def _handle_fill_rect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """FillRect(HDC hDC, LPCRECT lpRect, HBRUSH hBrush) -> int. Return 1."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)




def _handle_draw_text(emu: SimTowerEmulator, stub: StubDef) -> None:
    """DrawText(HDC hDC, LPCSTR lpString, int nCount, LPRECT lpRect, UINT uFormat) -> int.

    Return 16 (height of text drawn).
    """
    emu.mu.reg_write(UC_X86_REG_AX, 16)




def _handle_dialog_box_param(emu: SimTowerEmulator, stub: StubDef) -> None:
    """DialogBoxParam(...) -> int. Return IDOK (1)."""
    emu.mu.reg_write(UC_X86_REG_AX, 1)
    log.debug("DialogBoxParam() -> IDOK (1)")




def _handle_create_dialog_param(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateDialogParam(...) -> HWND. Return a fake window handle."""
    emu._next_hwnd += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_hwnd)
    log.debug("CreateDialogParam() -> hwnd=0x%04X", emu._next_hwnd)




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




STUB_HANDLERS_USER: dict[tuple[str, int], StubHandler] = {
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
    ("USER", 69): _ret(0),  # SetCursor -> prev cursor
    # USER — window ops (return success)
    ("USER", 31): _ret(0),  # IsIconic -> FALSE
    ("USER", 34): _ret(1),  # EnableWindow
    ("USER", 37): _nop,  # SetWindowText (void)
    ("USER", 47): _ret(1),  # IsWindow -> TRUE
    ("USER", 53): _ret(1),  # DestroyWindow
    ("USER", 56): _ret(1),  # MoveWindow
    ("USER", 62): _ret(0),  # SetScrollPos -> prev
    ("USER", 63): _ret(0),  # GetScrollPos
    ("USER", 64): _nop,  # SetScrollRange (void)
    ("USER", 65): _handle_get_scroll_range,
    ("USER", 110): _ret(1),  # PostMessage
    ("USER", 113): _ret(0),  # TranslateMessage
    ("USER", 114): _ret(0),  # DispatchMessage
    ("USER", 125): _nop,  # InvalidateRect (void)
    ("USER", 127): _nop,  # ValidateRect (void)
    ("USER", 130): _ret(0),  # SetClassWord -> prev
    ("USER", 134): _ret(0),  # SetWindowWord -> prev
    ("USER", 154): _ret(0),  # CheckMenuItem -> prev
    ("USER", 155): _ret(0),  # EnableMenuItem -> prev
    ("USER", 180): _ret(0),  # GetSysColor -> 0 (black)
    ("USER", 232): _ret(1),  # SetWindowPos
    ("USER", 263): _ret(5),  # GetMenuItemCount
    ("USER", 410): _ret(1),  # InsertMenu
    ("USER", 413): _ret(1),  # RemoveMenu
    ("USER", 458): _ret(1),  # DestroyCursor
    ("USER", 466): _ret(0),  # DragDetect
    ("USER", 59): _ret(0),  # SetActiveWindow -> prev
    ("USER", 60): _ret(0x101),  # GetActiveWindow -> main hwnd
    ("USER", 225): _ret(0),  # EnumTaskWindows -> done
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
    # USER — misc remaining
    ("USER", 6): _nop,  # PostQuitMessage (void)
    ("USER", 12): _ret(1),  # KillTimer
    ("USER", 16): _nop,  # ClipCursor (void)
    ("USER", 18): _ret(0),  # SetCapture -> prev hwnd
    ("USER", 19): _nop,  # ReleaseCapture (void)
    ("USER", 22): _ret(0),  # SetFocus -> prev focus
    ("USER", 39): lambda emu, stub: emu.mu.reg_write(
        UC_X86_REG_AX, emu._next_handle
    ),  # BeginPaint -> HDC
    ("USER", 40): _ret(1),  # EndPaint
    ("USER", 83): _handle_fill_rect,  # FrameRect
    ("USER", 88): _nop,  # EndDialog (void)
    ("USER", 90): _ret(0),  # IsDialogMessage
    ("USER", 91): _ret(0),  # GetDlgItem -> 0
    ("USER", 92): _nop,  # SetDlgItemText (void)
    ("USER", 93): _ret(0),  # GetDlgItemText -> 0 chars
    ("USER", 94): _nop,  # SetDlgItemInt (void)
    ("USER", 95): _ret(0),  # GetDlgItemInt -> 0
    ("USER", 101): _ret(0),  # SendDlgItemMessage
    ("USER", 104): _nop,  # MessageBeep (void)
    ("USER", 107): _ret(0),  # DefWindowProc
    ("USER", 171): _ret(1),  # WinHelp
    ("USER", 178): _ret(0),  # TranslateAccelerator
    ("USER", 186): _ret(0),  # SwapMouseButton
    ("USER", 221): _ret(1),  # ScrollDC
    ("USER", 229): _ret(0),  # GetTopWindow
}
