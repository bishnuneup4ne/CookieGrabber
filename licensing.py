"""Licensing: access-key gate for sold builds.

Two deployment modes:
  * self-hosted (you keep full source) -> cfg has no licence_url; check() is a no-op
  * reseller/customer build             -> cfg carries licence_key + licence_url;
                                          every launch validates against the server

The server is a dead-simple HTTP endpoint (netlify/functions/license.js) that
answers {ok, reason} for a key. Validation fails CLOSED: if the server is
unreachable we do NOT run -- an unlicensed build must not beacon on a network blip.
That's deliberate for a product you sell: offline grace would let a revoked key
keep working forever.

check(cfg):
  - no licence_url configured      -> allowed (self-hosted mode)
  - empty licence_key but url set  -> LicenceError("no key")
  - server ok:true                 -> allowed
  - anything else / unreachable    -> LicenceError(reason)
"""
from __future__ import annotations

import time

import requests


class LicenceError(RuntimeError):
    pass


def check(cfg: dict, retries: int = 3) -> None:
    url = str(cfg.get("licence_url", "")).strip()
    key = str(cfg.get("licence_key", "")).strip()
    if not url:
        return  # self-hosted; nothing to validate against
    if not key:
        raise LicenceError("build requires an access key but none is baked in")

    last = "unknown"
    for attempt in range(retries):
        try:
            r = requests.post(url, json={"action": "validate", "key": key}, timeout=15)
            data = r.json()
            if data.get("ok"):
                return
            raise LicenceError(f"denied: {data.get('reason', 'invalid key')}")
        except LicenceError:
            raise  # explicit denial is final; do not retry a revocation
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
            time.sleep(2 * (attempt + 1))
    # Fail closed after retries -- unreachable server does not grant free runs.
    raise LicenceError(f"licence server unreachable ({last}); refusing to run")
