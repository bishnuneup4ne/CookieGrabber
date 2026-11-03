"""System fingerprint - all of it readable without elevation.

Every field here comes from the user's own session: getpwuid, uname, /proc,
WMI-free on Linux. Nothing needs admin because none of it is protected; the
reason these are available is ownership, not privilege.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import platform
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone

IS_WINDOWS = sys.platform == "win32"


def _ram_gb() -> float | None:
    try:
        import psutil  # type: ignore
        return round(psutil.virtual_memory().total / 1024**3, 2)
    except Exception:
        pass
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    return round(int(line.split()[1]) / 1024 / 1024, 2)
    except OSError:
        pass
    return None


def _gpu() -> str:
    if IS_WINDOWS:
        try:
            out = subprocess.run(["wmic", "path", "videocontroller", "get", "name"],
                                 capture_output=True, text=True, timeout=8).stdout
            lines = [l.strip() for l in out.splitlines()[1:] if l.strip()]
            return ", ".join(lines)[:200]
        except Exception:
            return ""
    try:
        out = subprocess.run(["lspci"], capture_output=True, text=True, timeout=8).stdout
        vga = [l.split(":", 2)[-1].strip() for l in out.splitlines()
               if "VGA compatible controller" in l or "3D controller" in l]
        return "; ".join(vga)[:200]
    except Exception:
        return ""


def _screen() -> str:
    if IS_WINDOWS:
        try:
            u = ctypes.windll.user32
            return f"{u.GetSystemMetrics(0)}x{u.GetSystemMetrics(1)}"
        except Exception:
            return ""
    try:
        out = subprocess.run(["xrandr", "--current"], capture_output=True, text=True, timeout=6).stdout
        cur = ""
        for l in out.splitlines():
            if " connected" in l:
                cur = l.strip()[:60]
            elif cur and l.startswith(" ") and "*" in l:
                return cur.split(" connected")[0] + " " + l.strip().split()[0]
        return cur
    except Exception:
        return ""


def _public_ip() -> tuple[str, str]:
    """(ip, country). Needs no privileges - it is a normal outbound HTTPS call."""
    for url in ("https://api.ipify.org?format=json", "https://httpbin.org/ip"):
        try:
            import requests  # type: ignore
            r = requests.get(url, timeout=5)
            ip = r.json().get("origin") or r.json().get("ip")
            if ip:
                country = ""
                try:
                    j = requests.get(f"https://ipapi.co/{ip}/country_name/", timeout=5)
                    # ipapi returns a JSON error object on rate limit, not a name.
                    if j.ok and not str(j.text).lstrip().startswith("{"):
                        country = j.text.strip()[:60]
                except Exception:
                    pass
                return str(ip), country
        except Exception:
            continue
    return "", ""


def gather() -> dict:
    info: dict = {
        "hostname": socket.gethostname(),
        "username": os.environ.get("USERNAME") or os.environ.get("USER") or "",
        "platform": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "elevation": "not-required(user-context)",
    }
    if not info["username"]:
        try:
            import pwd  # type: ignore
            info["username"] = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            pass
    info["ram_gb"] = _ram_gb()
    info["gpu"] = _gpu()
    info["screen"] = _screen()
    ip, cc = _public_ip()
    info["ip"], info["country"] = ip, cc
    # Stable machine id: DMI product_uuid on Linux (world-readable), MachineGuid on
    # Windows (HKCU-visible only for the current user, so fall back to MAC-derived).
    mid = ""
    for p in ("/sys/class/dmi/id/product_uuid", "/var/lib/dbus/machine-id",
              "/etc/machine-id"):
        try:
            mid = open(p).read().strip()
            if mid:
                break
        except OSError:
            continue
    if not mid and IS_WINDOWS:
        mid = str(uuid.getnode())
    info["hwid"] = hashlib.sha256(mid.encode()).hexdigest()[:32] if mid else ""
    return info
