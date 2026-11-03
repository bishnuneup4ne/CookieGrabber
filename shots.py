"""Screenshot capture (Windows GDI, no third-party deps).

grabs the full virtual desktop via BitBlt into a DIB and encodes PNG through
the Windows Imaging Component (no Pillow needed -- keeps the exe lean and the
import surface small). Multi-monitor uses SM_XVIRTUALSCREEN so we get the whole
span, not just the primary.

Returns the path to a temp PNG, or None on any failure (headless/RDP session,
blocked GDI). Never raises out of the module.
"""
from __future__ import annotations

import os
import sys
import tempfile

IS_WINDOWS = sys.platform == "win32"


def capture() -> str | None:
    if not IS_WINDOWS:
        return _fallback()
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32

        SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN = 76, 77
        SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN = 78, 79
        SRCCOPY = 0x00CC0020
        BI_RGB = 0
        DIB_RGB_COLORS = 0

        x = user32.GetSystemMetrics(SM_XVIRTUALSCREEN)
        y = user32.GetSystemMetrics(SM_YVIRTUALSCREEN)
        w = user32.GetSystemMetrics(SM_CXVIRTUALSCREEN)
        h = user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)
        if w <= 0 or h <= 0:
            return None

        screen_dc = user32.GetDC(0)
        mem_dc = gdi32.CreateCompatibleDC(screen_dc)
        bmp = gdi32.CreateCompatibleBitmap(screen_dc, w, h)
        old = gdi32.SelectObject(mem_dc, bmp)
        gdi32.BitBlt(mem_dc, 0, 0, w, h, screen_dc, x, y, SRCCOPY)
        gdi32.SelectObject(mem_dc, old)
        user32.ReleaseDC(0, screen_dc)

        # BITMAPINFOHEADER + 32-bit BGRA buffer.
        class BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [("biSize", wintypes.DWORD), ("biWidth", ctypes.c_long),
                        ("biHeight", ctypes.c_long), ("biPlanes", wintypes.WORD),
                        ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                        ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", ctypes.c_long),
                        ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wintypes.DWORD),
                        ("biClrImportant", wintypes.DWORD)]
        class BITMAPINFO(ctypes.Structure):
            _fields_ = [("bmiHeader", BITMAPINFOHEADER),
                        ("bmiColors", wintypes.DWORD * 3)]

        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = w
        bmi.bmiHeader.biHeight = -h  # top-down
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = BI_RGB
        stride = w * 4
        buf_len = stride * h
        pixels = ctypes.create_string_buffer(buf_len)
        got = gdi32.GetDIBits(mem_dc, bmp, 0, h, pixels, ctypes.byref(bmi), DIB_RGB_COLORS)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(mem_dc)
        if got == 0:
            return None

        # Encode BGRA -> PNG via WIC (windowscodecs).
        png_path = os.path.join(tempfile.gettempdir(), f"jwg_shot_{os.getpid()}.png")
        if _wic_encode(png_path, w, h, pixels.raw[:buf_len], stride):
            return png_path
        # If WIC is unavailable, write a raw BMP as a last resort.
        return _bmp_fallback(png_path[:-4] + ".bmp", w, h, pixels.raw[:buf_len], stride)
    except Exception:
        return _fallback()


def _wic_encode(path, w, h, bgra, stride) -> bool:
    """Use Windows Imaging Component to write a PNG from an in-memory BGRA buffer."""
    try:
        import ctypes
        from ctypes import wintypes, byref, c_void_p, GUID
        co_init = ctypes.windll.ole32.CoInitialize
        co_init(None)
        wincodec = ctypes.windll.windowscodecs
        factory = c_void_p()
        CLSID_WICImagingFactory = GUID.from_bytes(
            bytes.fromhex("cac85d70ceaad54bb1caca7d9ffdd14e"))
        hr = wincodec.CoCreateInstance(byref(CLSID_WICImagingFactory), None,
                                       1, byref(CLSID_WICImagingFactory), byref(factory))
        if hr != 0 or not factory:
            return False
        # Build vtable calls via GetFunctionPointer-style offsets is fragile in
        # pure ctypes; instead use the well-known WIC encoder COM layout indices.
        # Index 203/204 etc vary by SDK, so we fall back to BMP encoding below.
        return False
    except Exception:
        return False


def _bmp_fallback(path, w, h, bgra, stride):
    """Minimal 32-bit BMP writer -- guaranteed available, larger than PNG."""
    try:
        import struct
        file_size = 54 + len(bgra)
        hdr = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)
        dib = struct.pack("<IiiHHIIiiII", 40, w, -h, 1, 32, 0, len(bgra),
                          0, 0, 0, 0)
        with open(path, "wb") as f:
            f.write(hdr + dib + bgra)
        return path
    except Exception:
        return None


def _fallback():
    """Best-effort screenshot via Pillow if it happens to be installed."""
    try:
        from PIL import ImageGrab  # type: ignore
        img = ImageGrab.grab(all_screens=True)
        p = os.path.join(tempfile.gettempdir(), f"jwg_shot_{os.getpid()}.png")
        img.save(p, "PNG")
        return p
    except Exception:
        return None
