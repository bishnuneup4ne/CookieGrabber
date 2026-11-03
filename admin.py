"""Admin: manage reseller access keys against the Netlify licence server.

Talks to the same /api/license endpoint the implant hits, using ADMIN_TOKEN for
the privileged actions. Use it from a terminal or wire these verbs into a panel.

  python admin.py --url https://you.netlify.app/api/license issue "customer x" 30
  python admin.py --url ... revoke JWG-XXXX==
  python admin.py --url ... list
  python admin.py --url ... info JWG-XXXX==

ADMIN_TOKEN comes from env JWG_ADMIN_TOKEN (never a CLI arg -- argv leaks via ps).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import requests


def _post(url: str, payload: dict) -> dict:
    tok = os.environ.get("JWG_ADMIN_TOKEN", "").strip()
    body = dict(payload)
    if tok:
        body["token"] = tok
    r = requests.post(url, json=body, timeout=20)
    return r.json()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="JohnWick licence admin")
    ap.add_argument("--url", required=True, help="licence validate/issue endpoint")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_issue = sub.add_parser("issue"); p_issue.add_argument("label"); p_issue.add_argument("days", nargs="?", default="0")
    p_rev = sub.add_parser("revoke"); p_rev.add_argument("key")
    p_unrev = sub.add_parser("unrevoke"); p_unrev.add_argument("key")
    p_list = sub.add_parser("list")
    p_info = sub.add_parser("info"); p_info.add_argument("key")
    a = ap.parse_args(argv)

    if not os.environ.get("JWG_ADMIN_TOKEN"):
        print("warning: JWG_ADMIN_TOKEN not set; admin actions will be denied", file=sys.stderr)

    if a.cmd == "issue":
        res = _post(a.url, {"action": "issue", "label": a.label, "days": a.days})
    elif a.cmd in ("revoke", "unrevoke"):
        res = _post(a.url, {"action": a.cmd, "key": a.key})
    elif a.cmd == "info":
        res = _post(a.url, {"action": "info", "key": a.key})
    elif a.cmd == "list":
        res = _post(a.url, {"action": "list"})
    else:
        return 2
    print(json.dumps(res, indent=2))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
