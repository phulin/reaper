"""Win16 API stub definitions for SimTower.

Each entry maps (MODULE, ordinal) -> (name, param_bytes), where param_bytes
is the total bytes of parameters pushed by the caller (Pascal calling convention).
The stub will execute `retf <param_bytes>` to clean up the stack correctly.

Ordinals and parameter types are from Wine's spec files:
  - dlls/user.exe16/user.exe16.spec
  - dlls/krnl386.exe16/krnl386.exe16.spec
  - dlls/gdi.exe16/gdi.exe16.spec
  - dlls/commdlg.dll16/commdlg.dll16.spec
  - dlls/mmsystem.dll16/mmsystem.dll16.spec
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class StubDef:
    """Definition of a single API stub."""

    module: str
    name: str
    ordinal: int
    param_bytes: int


# fmt: off
# All API functions imported by SIMTOWER.EX_, verified against Wine spec files.
# param_bytes computed from Wine's parameter type declarations:
#   word/s_word = 2, long = 4, ptr/str/segptr/segstr = 4

STUB_DEFS: list[StubDef] = [
    # ── COMMDLG ──────────────────────────────────────────────────────
    # 1 pascal GetOpenFileName(segptr)
    StubDef("COMMDLG", "GetOpenFileName", 1, 4),

    # ── GDI (38 ordinals) ───────────────────────────────────────────
    StubDef("GDI", "SetBkColor",              1, 6),   # (word long)
    StubDef("GDI", "SetBkMode",               2, 4),   # (word word)
    StubDef("GDI", "SetTextColor",            9, 6),   # (word long)
    StubDef("GDI", "LineTo",                 19, 6),   # (word s_word s_word)
    StubDef("GDI", "MoveTo",                 20, 6),   # (word s_word s_word)
    StubDef("GDI", "Rectangle",              27, 10),  # (word s_word s_word s_word s_word)
    StubDef("GDI", "PatBlt",                 29, 14),  # (word s_word s_word s_word s_word long)
    StubDef("GDI", "SaveDC",                 30, 2),   # (word)
    StubDef("GDI", "TextOut",                33, 12),  # (word s_word s_word str word)
    StubDef("GDI", "BitBlt",                 34, 20),  # (word s_word s_word s_word s_word word s_word s_word long)
    StubDef("GDI", "RestoreDC",              39, 4),   # (word s_word)
    StubDef("GDI", "SelectClipRgn",          44, 4),   # (word word)
    StubDef("GDI", "SelectObject",           45, 4),   # (word word)
    StubDef("GDI", "CreateBitmap",           48, 12),  # (word word word word ptr)
    StubDef("GDI", "CreateCompatibleBitmap", 51, 6),   # (word word word)
    StubDef("GDI", "CreateCompatibleDC",     52, 2),   # (word)
    StubDef("GDI", "CreateFontIndirect",     57, 4),   # (ptr)
    StubDef("GDI", "CreatePen",              61, 8),   # (s_word s_word long)
    StubDef("GDI", "CreateRectRgnIndirect",   65, 4),   # (ptr)
    StubDef("GDI", "CreateSolidBrush",       66, 4),   # (long)
    StubDef("GDI", "DeleteDC",               68, 2),   # (word)
    StubDef("GDI", "DeleteObject",           69, 2),   # (word)
    StubDef("GDI", "GetCurrentPosition",     78, 2),   # (word)
    StubDef("GDI", "GetDeviceCaps",          80, 4),   # (word s_word)
    StubDef("GDI", "GetObject",              82, 8),   # (word s_word ptr)
    StubDef("GDI", "GetStockObject",         87, 2),   # (word)
    StubDef("GDI", "GetTextExtent",          91, 8),   # (word ptr s_word)
    StubDef("GDI", "GetTextMetrics",         93, 6),   # (word ptr)
    StubDef("GDI", "GetNearestColor",       154, 6),   # (word long)
    StubDef("GDI", "GetRasterizerCaps",     313, 6),   # (ptr word)
    StubDef("GDI", "GetTextAlign",          345, 2),   # (word)
    StubDef("GDI", "SetTextAlign",          346, 4),   # (word word)
    StubDef("GDI", "CreatePalette",         360, 4),   # (ptr)
    StubDef("GDI", "GetPaletteEntries",     363, 10),  # (word word word ptr)
    StubDef("GDI", "UpdateColors",          366, 2),   # (word)
    StubDef("GDI", "AnimatePalette",        367, 10),  # (word word word ptr)
    StubDef("GDI", "GetNearestPaletteIndex",370, 6),   # (word long)
    StubDef("GDI", "SetDIBitsToDevice",     443, 28),  # (word s_word*6 word word ptr ptr word)

    # ── KERNEL (39 ordinals) ─────────────────────────────────────────
    StubDef("KERNEL", "GlobalAlloc",            15, 6),   # (word long)
    StubDef("KERNEL", "GlobalReAlloc",          16, 8),   # (word long word)
    StubDef("KERNEL", "GlobalFree",             17, 2),   # (word)
    StubDef("KERNEL", "GlobalLock",             18, 2),   # (word)
    StubDef("KERNEL", "GlobalUnlock",           19, 2),   # (word)
    StubDef("KERNEL", "GlobalSize",             20, 2),   # (word)
    StubDef("KERNEL", "GlobalHandle",           21, 2),   # (word)
    StubDef("KERNEL", "GlobalFlags",            22, 2),   # (word)
    StubDef("KERNEL", "GlobalCompact",          25, 4),   # (long)
    StubDef("KERNEL", "WaitEvent",              30, 2),   # (word)
    StubDef("KERNEL", "GetCurrentTask",         36, 0),   # ()
    StubDef("KERNEL", "GetModuleUsage",         48, 2),   # (word)
    StubDef("KERNEL", "GetModuleFileName",      49, 8),   # (word ptr s_word)
    StubDef("KERNEL", "MakeProcInstance",       51, 6),   # (segptr word)
    StubDef("KERNEL", "FreeProcInstance",       52, 4),   # (segptr)
    StubDef("KERNEL", "GetProfileString",       58, 18),  # (str str str ptr word)
    StubDef("KERNEL", "WriteProfileString",     59, 12),  # (str str str)
    StubDef("KERNEL", "FindResource",           60, 10),  # (word str str)
    StubDef("KERNEL", "LoadResource",           61, 4),   # (word word)
    StubDef("KERNEL", "LockResource",           62, 2),   # (word)
    StubDef("KERNEL", "FreeResource",           63, 2),   # (word)
    StubDef("KERNEL", "_lclose",                81, 2),   # (word)
    StubDef("KERNEL", "_lread",                 82, 8),   # (word segptr word)
    StubDef("KERNEL", "_lcreat",                83, 6),   # (str word)
    StubDef("KERNEL", "_llseek",                84, 8),   # (word long word)
    StubDef("KERNEL", "_lopen",                 85, 6),   # (str word)
    StubDef("KERNEL", "_lwrite",                86, 8),   # (word ptr word)
    StubDef("KERNEL", "lstrcpy",                88, 8),   # (segptr str)
    StubDef("KERNEL", "lstrcat",                89, 8),   # (segstr str)
    StubDef("KERNEL", "lstrlen",                90, 4),   # (str)
    StubDef("KERNEL", "InitTask",               91, 0),   # ()
    StubDef("KERNEL", "LoadLibrary",            95, 4),   # (str)
    StubDef("KERNEL", "__AHSHIFT",             113, 0),   # equate (constant = 3, not a function)
    StubDef("KERNEL", "OutputDebugString",     115, 4),   # (str)
    StubDef("KERNEL", "GetPrivateProfileInt",  127, 14),  # (str str s_word str)
    StubDef("KERNEL", "GetWinFlags",           132, 0),   # ()
    StubDef("KERNEL", "FatalAppExit",          137, 6),   # (word str)
    StubDef("KERNEL", "GetFreeSpace",          169, 2),   # (word)
    StubDef("KERNEL", "hmemcpy",               348, 12),  # (ptr ptr long)

    # ── MMSYSTEM ─────────────────────────────────────────────────────
    # 402 pascal waveOutGetDevCaps(word ptr word)
    StubDef("MMSYSTEM", "waveOutGetDevCaps", 402, 8),

    # ── USER (101 ordinals) ──────────────────────────────────────────
    StubDef("USER", "MessageBox",              1, 12),  # (word str str word)
    StubDef("USER", "InitApp",                 5, 2),   # (word)
    StubDef("USER", "PostQuitMessage",         6, 2),   # (word)
    StubDef("USER", "SetTimer",               10, 10),  # (word word word segptr)
    StubDef("USER", "KillTimer",              12, 4),   # (word word)
    StubDef("USER", "GetTickCount",           13, 0),   # ()
    StubDef("USER", "ClipCursor",             16, 4),   # (ptr)
    StubDef("USER", "GetCursorPos",           17, 4),   # (ptr)
    StubDef("USER", "SetCapture",             18, 2),   # (word)
    StubDef("USER", "ReleaseCapture",         19, 0),   # ()
    StubDef("USER", "SetFocus",               22, 2),   # (word)
    StubDef("USER", "ClientToScreen",         28, 6),   # (word ptr)
    StubDef("USER", "ScreenToClient",         29, 6),   # (word ptr)
    StubDef("USER", "IsIconic",               31, 2),   # (word)
    StubDef("USER", "GetWindowRect",          32, 6),   # (word ptr)
    StubDef("USER", "GetClientRect",          33, 6),   # (word ptr)
    StubDef("USER", "EnableWindow",           34, 4),   # (word word)
    StubDef("USER", "SetWindowText",          37, 6),   # (word segstr)
    StubDef("USER", "BeginPaint",             39, 6),   # (word ptr)
    StubDef("USER", "EndPaint",               40, 6),   # (word ptr)
    StubDef("USER", "CreateWindow",           41, 30),  # (str str long s_word*4 word word word segptr)
    StubDef("USER", "ShowWindow",             42, 4),   # (word word)
    StubDef("USER", "IsWindow",               47, 2),   # (word)
    StubDef("USER", "DestroyWindow",          53, 2),   # (word)
    StubDef("USER", "MoveWindow",             56, 12),  # (word word word word word word)
    StubDef("USER", "RegisterClass",          57, 4),   # (ptr)
    StubDef("USER", "SetActiveWindow",        59, 2),   # (word)
    StubDef("USER", "GetActiveWindow",        60, 0),   # ()
    StubDef("USER", "SetScrollPos",           62, 8),   # (word word s_word word)
    StubDef("USER", "GetScrollPos",           63, 4),   # (word word)
    StubDef("USER", "SetScrollRange",         64, 10),  # (word word s_word s_word word)
    StubDef("USER", "GetScrollRange",         65, 12),  # (word word ptr ptr)
    StubDef("USER", "GetDC",                  66, 2),   # (word)
    StubDef("USER", "GetWindowDC",            67, 2),   # (word)
    StubDef("USER", "ReleaseDC",              68, 4),   # (word word)
    StubDef("USER", "SetCursor",              69, 2),   # (word)
    StubDef("USER", "SetRect",                72, 12),  # (ptr s_word s_word s_word s_word)
    StubDef("USER", "SetRectEmpty",           73, 4),   # (ptr)
    StubDef("USER", "CopyRect",              74, 8),   # (ptr ptr)
    StubDef("USER", "IsRectEmpty",            75, 4),   # (ptr)
    StubDef("USER", "PtInRect",               76, 8),   # (ptr long)
    StubDef("USER", "OffsetRect",             77, 8),   # (ptr s_word s_word)
    StubDef("USER", "InflateRect",            78, 8),   # (ptr s_word s_word)
    StubDef("USER", "IntersectRect",          79, 12),  # (ptr ptr ptr)
    StubDef("USER", "UnionRect",              80, 12),  # (ptr ptr ptr)
    StubDef("USER", "FillRect",               81, 8),   # (word ptr word)
    StubDef("USER", "FrameRect",              83, 8),   # (word ptr word)
    StubDef("USER", "DrawText",               85, 14),  # (word str s_word ptr word)
    StubDef("USER", "DialogBox",              87, 12),  # (word str word segptr)
    StubDef("USER", "EndDialog",              88, 4),   # (word s_word)
    StubDef("USER", "IsDialogMessage",        90, 6),   # (word ptr)
    StubDef("USER", "GetDlgItem",             91, 4),   # (word word)
    StubDef("USER", "SetDlgItemText",         92, 8),   # (word word segstr)
    StubDef("USER", "GetDlgItemText",         93, 10),  # (word word segptr word)
    StubDef("USER", "SetDlgItemInt",          94, 8),   # (word word word word)
    StubDef("USER", "GetDlgItemInt",          95, 10),  # (word s_word ptr word)
    StubDef("USER", "SendDlgItemMessage",    101, 12),  # (word word word word long)
    StubDef("USER", "MessageBeep",           104, 2),   # (word)
    StubDef("USER", "DefWindowProc",         107, 10),  # (word word word long)
    StubDef("USER", "PeekMessage",           109, 12),  # (ptr word word word word)
    StubDef("USER", "PostMessage",           110, 10),  # (word word word long)
    StubDef("USER", "TranslateMessage",      113, 4),   # (ptr)
    StubDef("USER", "DispatchMessage",       114, 4),   # (ptr)
    StubDef("USER", "UpdateWindow",          124, 2),   # (word)
    StubDef("USER", "InvalidateRect",        125, 8),   # (word ptr word)
    StubDef("USER", "ValidateRect",          127, 6),   # (word ptr)
    StubDef("USER", "SetClassWord",          130, 6),   # (word s_word word)
    StubDef("USER", "SetWindowWord",         134, 6),   # (word s_word word)
    StubDef("USER", "CheckMenuItem",         154, 6),   # (word word word)
    StubDef("USER", "EnableMenuItem",        155, 6),   # (word word word)
    StubDef("USER", "GetMenu",               157, 2),   # (word)
    StubDef("USER", "GetSubMenu",            159, 4),   # (word word)
    StubDef("USER", "WinHelp",               171, 12),  # (word str word long)
    StubDef("USER", "LoadCursor",            173, 6),   # (word str)
    StubDef("USER", "LoadIcon",              174, 6),   # (word str)
    StubDef("USER", "LoadAccelerators",      177, 6),   # (word str)
    StubDef("USER", "TranslateAccelerator",  178, 8),   # (word word ptr)
    StubDef("USER", "GetSystemMetrics",      179, 2),   # (s_word)
    StubDef("USER", "GetSysColor",           180, 2),   # (word)
    StubDef("USER", "SwapMouseButton",       186, 2),   # (word)
    StubDef("USER", "DialogBoxIndirect",     218, 10),  # (word word word segptr)
    StubDef("USER", "CreateDialogIndirect",  219, 12),  # (word ptr word segptr)
    StubDef("USER", "ScrollDC",              221, 20),  # (word s_word s_word ptr ptr word ptr)
    StubDef("USER", "EnumTaskWindows",       225, 10),  # (word segptr long)
    StubDef("USER", "GetTopWindow",          229, 2),   # (word)
    StubDef("USER", "SetWindowPos",          232, 14),  # (word word word word word word word)
    StubDef("USER", "DialogBoxParam",        239, 16),  # (word str word segptr long)
    StubDef("USER", "DialogBoxIndirectParam", 240, 14), # (word word word segptr long)
    StubDef("USER", "CreateDialogParam",     241, 16),  # (word str word segptr long)
    StubDef("USER", "EqualRect",             244, 8),   # (ptr ptr)
    StubDef("USER", "GetAsyncKeyState",      249, 2),   # (word)
    StubDef("USER", "GetMenuItemCount",      263, 2),   # (word)
    StubDef("USER", "SelectPalette",         282, 6),   # (word word word)
    StubDef("USER", "RealizePalette",        283, 2),   # (word)
    StubDef("USER", "GetDesktopWindow",      286, 0),   # ()
    StubDef("USER", "InsertMenu",            410, 12),  # (word word word word segptr)
    StubDef("USER", "RemoveMenu",            413, 6),   # (word word word)
    StubDef("USER", "_wsprintf",             420, 0),   # varargs/cdecl - caller cleans stack
    StubDef("USER", "wvsprintf",             421, 12),  # (ptr str ptr)
    StubDef("USER", "DestroyCursor",         458, 2),   # (word)
    StubDef("USER", "DragDetect",            466, 6),   # (word long)

    # ── WAVMIX16 (9 ordinals) ───────────────────────────────────────
    # Third-party library; param sizes estimated from known WavMix API.
    StubDef("WAVMIX16", "WavMixInit",            3, 0),
    StubDef("WAVMIX16", "WavMixActivate",        4, 4),
    StubDef("WAVMIX16", "WavMixOpenChannel",     5, 8),
    StubDef("WAVMIX16", "WavMixOpenWav",         6, 8),
    StubDef("WAVMIX16", "WavMixPlay",            7, 6),
    StubDef("WAVMIX16", "WavMixFlushChannel",    9, 8),
    StubDef("WAVMIX16", "WavMixCloseChannel",   10, 8),
    StubDef("WAVMIX16", "WavMixCloseSession",   11, 2),
    StubDef("WAVMIX16", "WavMixFreeWav",        12, 6),

    # ── WIN87EM ─────────────────────────────────────────────────────
    StubDef("WIN87EM", "__FPMATH", 1, 0),

    # ── WING (6 ordinals) — verified from Wine wing.dll16.spec ────
    StubDef("WING", "WinGCreateDC",             1001, 0),
    StubDef("WING", "WinGRecommendDIBFormat",   1002, 4),   # (ptr)
    StubDef("WING", "WinGCreateBitmap",         1003, 10),  # (word ptr ptr)
    StubDef("WING", "WinGSetDIBColorTable",     1006, 10),  # (word word word ptr)
    StubDef("WING", "WinGGetDIBColorTable",     1005, 10),  # (word word word ptr)
    StubDef("WING", "WinGStretchBlt",            1009, 20),  # (word*10)
    StubDef("WING", "WinGBitBlt",               1010, 16),  # (word*8)
]
# fmt: on


def build_stub_lookup() -> dict[tuple[str, int], StubDef]:
    """Build a lookup table: (MODULE_NAME, ordinal) -> StubDef."""
    return {(s.module, s.ordinal): s for s in STUB_DEFS}
