"""Win16 stub handlers for misc DLLs (MMSYSTEM, WIN87EM, WING, WAVMIX16, COMMDLG)."""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from unicorn.x86_const import (
    UC_X86_REG_AX,
)

from simtower.constants import StubHandler
from simtower.stub_helpers import _nop, _read_stack_dword, _read_stack_word, _ret
from simtower.stubs import StubDef

if TYPE_CHECKING:
    from simtower.emulator import SimTowerEmulator

log = logging.getLogger(__name__)


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




STUB_HANDLERS_MISC: dict[tuple[str, int], StubHandler] = {
    # MMSYSTEM
    ("MMSYSTEM", 402): _handle_wave_out_get_dev_caps,
    # COMMDLG
    ("COMMDLG", 1): _ret(0),  # GetOpenFileName -> cancel
    # WAVMIX16 (all no-op, return 0)
    ("WAVMIX16", 3): _ret(0),  # WavMixInit -> NULL (no audio)
    ("WAVMIX16", 4): _nop,  # WavMixActivate
    ("WAVMIX16", 5): _ret(0),  # WavMixOpenChannel
    ("WAVMIX16", 6): _ret(0),  # WavMixOpenWav
    ("WAVMIX16", 7): _ret(0),  # WavMixPlay
    ("WAVMIX16", 9): _ret(0),  # WavMixFlushChannel
    ("WAVMIX16", 10): _ret(0),  # WavMixCloseChannel
    ("WAVMIX16", 11): _ret(0),  # WavMixCloseSession
    ("WAVMIX16", 12): _ret(0),  # WavMixFreeWav
    # WING
    ("WING", 1001): _handle_wing_create_dc,
    ("WING", 1002): _handle_wing_recommend_dib,
    ("WING", 1003): _handle_wing_create_bitmap,
    ("WING", 1005): _ret(256),  # WinGGetDIBColorTable -> 256
    ("WING", 1006): _ret(256),  # WinGSetDIBColorTable -> 256
    ("WING", 1009): _ret(1),  # WinGStretchBlt
    ("WING", 1010): _ret(1),  # WinGBitBlt
    # WIN87EM
    ("WIN87EM", 1): _handle_fpmath,
}
