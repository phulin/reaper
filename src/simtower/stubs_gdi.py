"""Win16 GDI API stub handlers."""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_DX,
)

from simtower.constants import StubHandler
from simtower.stub_helpers import _nop, _read_stack_dword, _read_stack_word, _ret
from simtower.stubs import StubDef

if TYPE_CHECKING:
    from simtower.emulator import SimTowerEmulator

log = logging.getLogger(__name__)


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




def _handle_create_compatible_dc(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateCompatibleDC(HDC hdc) -> HDC."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreateCompatibleDC() -> 0x%04X", emu._next_handle)




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




def _handle_select_object(emu: SimTowerEmulator, stub: StubDef) -> None:
    """SelectObject(HDC hdc, HGDIOBJ hObj) -> HGDIOBJ (previous)."""
    h_obj = _read_stack_word(emu, 4)
    # Return a fake previous object
    emu.mu.reg_write(UC_X86_REG_AX, 0x8001)
    log.debug("SelectObject(obj=0x%04X) -> 0x8001", h_obj)




def _handle_get_stock_object(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetStockObject(int fnObject) -> HGDIOBJ.

    Return a fake non-zero GDI handle.
    """
    fn_obj = _read_stack_word(emu, 4)
    # Use a deterministic handle based on the stock object ID
    handle = 0x8000 | (fn_obj & 0xFF)
    emu.mu.reg_write(UC_X86_REG_AX, handle)
    log.debug("GetStockObject(%d) -> 0x%04X", fn_obj, handle)




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




def _handle_create_font_indirect(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateFontIndirect(LPLOGFONT lplf) -> HFONT."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreateFontIndirect() -> 0x%04X", emu._next_handle)




def _handle_create_pen(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreatePen(int fnPenStyle, int nWidth, COLORREF crColor) -> HPEN."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreatePen() -> 0x%04X", emu._next_handle)




def _handle_create_rect_rgn(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateRectRgn(int x1, int y1, int x2, int y2) -> HRGN."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreateRectRgn() -> 0x%04X", emu._next_handle)




def _handle_create_solid_brush(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreateSolidBrush(COLORREF crColor) -> HBRUSH."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreateSolidBrush() -> 0x%04X", emu._next_handle)




def _handle_create_palette(emu: SimTowerEmulator, stub: StubDef) -> None:
    """CreatePalette(LPLOGPALETTE lplgpl) -> HPALETTE."""
    emu._next_handle += 1
    emu.mu.reg_write(UC_X86_REG_AX, emu._next_handle)
    log.debug("CreatePalette() -> 0x%04X", emu._next_handle)




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




def _handle_get_nearest_color(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetNearestColor(HDC hdc, COLORREF crColor) -> COLORREF.

    Pascal stack: [SP+4] = crColor (DWORD), [SP+8] = hdc (WORD)
    Return the same color (we have a true-color DC).
    """
    color = _read_stack_dword(emu, 4)
    emu.mu.reg_write(UC_X86_REG_AX, color & 0xFFFF)
    emu.mu.reg_write(UC_X86_REG_DX, (color >> 16) & 0xFFFF)




def _handle_get_text_align(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetTextAlign(HDC hdc) -> UINT. Return 0 (TA_LEFT|TA_TOP)."""
    emu.mu.reg_write(UC_X86_REG_AX, 0)




def _handle_set_text_align(emu: SimTowerEmulator, stub: StubDef) -> None:
    """SetTextAlign(HDC hdc, UINT fMode) -> UINT. Return previous alignment (0)."""
    emu.mu.reg_write(UC_X86_REG_AX, 0)




def _handle_get_nearest_palette_index(emu: SimTowerEmulator, stub: StubDef) -> None:
    """GetNearestPaletteIndex(HPALETTE hPal, COLORREF crColor) -> UINT.

    Pascal stack: [SP+4] = crColor (DWORD), [SP+8] = hPal (WORD)
    Return index 0 as a reasonable default.
    """
    emu.mu.reg_write(UC_X86_REG_AX, 0)




STUB_HANDLERS_GDI: dict[tuple[str, int], StubHandler] = {
    # GDI — queries
    ("GDI", 93): _handle_get_text_metrics,
    ("GDI", 313): _handle_get_rasterizer_caps,
    # GDI — DC management
    ("GDI", 30): _handle_save_dc,
    ("GDI", 52): _handle_create_compatible_dc,
    ("GDI", 68): _ret(1),  # DeleteDC
    ("GDI", 69): _ret(1),  # DeleteObject
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
    ("GDI", 2): _ret(1),  # SetBkMode
    ("GDI", 9): _ret(0),  # SetTextColor -> prev (0=black)
    ("GDI", 19): _ret(1),  # LineTo
    ("GDI", 20): _ret(0),  # MoveTo -> prev pos (packed DWORD)
    ("GDI", 27): _ret(1),  # Rectangle
    ("GDI", 29): _ret(1),  # PatBlt
    ("GDI", 33): _ret(1),  # TextOut
    ("GDI", 34): _ret(1),  # BitBlt
    ("GDI", 39): _ret(1),  # RestoreDC
    ("GDI", 44): _ret(1),  # SelectClipRgn
    ("GDI", 78): _ret(0),  # GetCurrentPosition
    ("GDI", 366): _ret(1),  # UpdateColors
    ("GDI", 367): _nop,  # AnimatePalette (void)
    ("GDI", 443): _ret(1),  # SetDIBitsToDevice
}
