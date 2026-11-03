// Netlify Function: licence server for JohnWick reseller builds.
// Free tier, no paid services. Keys live in a Netlify Blobs store (or an env
// JSON map if you prefer zero storage). Admin actions are gated by ADMIN_TOKEN;
// the implant only ever calls `validate`, which needs no admin secret.
//
// Deploy:
//   1. drop this file at netlify/functions/license.js in a repo/site
//   2. netlify.toml already routes /api/license -> /.netlify/functions/license
//   3. set env ADMIN_TOKEN (long random string) in Netlify site settings
//   4. give customers builds whose cfg.json points licence_url to
//      https://your-site.netlify.app/api/license and carries their key
//
// Endpoints (all POST, JSON body):
//   {action:"validate", key}                       -> {ok:true|false, reason}
//   {action:"issue",  label, days, token:ADMIN}    -> {ok, key}
//   {action:"revoke", key, token:ADMIN}            -> {ok}
//   {action:"list",   token:ADMIN}                 -> {ok, keys:[...]}
//   {action:"info",   key, token:ADMIN}            -> {ok, record}

const { getStore } = require("@netlify/blobs");

const ADMIN = process.env.ADMIN_TOKEN || "";

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function newKey() {
  const a = new Uint8Array(18);
  crypto.getRandomValues(a);
  return "JWG-" + b64url(a).toUpperCase();
}

async function store() {
  // Netlify Blobs: named store, service default binding.
  return getStore({ name: "licenses" });
}

async function readKey(s, key) {
  try {
    const raw = await s.get(key);
    return raw ? JSON.parse(raw) : null;
  } catch (_) {
    return null;
  }
}

function json(status, obj) {
  return { statusCode: status, headers: { "content-type": "application/json" }, body: JSON.stringify(obj) };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { ok: false, reason: "method" });
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (_) {
    return json(400, { ok: false, reason: "bad json" });
  }
  const action = (body.action || "").toLowerCase();
  const s = await store();

  // ---- public: validate (what the implant calls on every launch) ----------
  if (action === "validate") {
    const rec = await readKey(s, body.key);
    if (!rec) return json(200, { ok: false, reason: "unknown key" });
    if (rec.revoked) return json(200, { ok: false, reason: "revoked" });
    if (rec.expires && Date.now() > rec.expires) return json(200, { ok: false, reason: "expired" });
    return json(200, { ok: true });
  }

  // ---- admin: everything below requires the admin token -------------------
  if (body.token !== ADMIN || !ADMIN) return json(401, { ok: false, reason: "admin auth" });

  if (action === "issue") {
    const key = newKey();
    const days = parseInt(body.days || "0", 10);
    const rec = {
      key,
      label: String(body.label || "").slice(0, 120),
      created: Date.now(),
      expires: days > 0 ? Date.now() + days * 86400000 : 0,
      revoked: false,
    };
    await s.set(key, JSON.stringify(rec));
    return json(200, { ok: true, key, expires: rec.expires });
  }

  if (action === "revoke") {
    const rec = await readKey(s, body.key);
    if (!rec) return json(404, { ok: false, reason: "no such key" });
    rec.revoked = true;
    await s.set(rec.key, JSON.stringify(rec));
    return json(200, { ok: true });
  }

  if (action === "unrevoke") {
    const rec = await readKey(s, body.key);
    if (!rec) return json(404, { ok: false, reason: "no such key" });
    rec.revoked = false;
    await s.set(rec.key, JSON.stringify(rec));
    return json(200, { ok: true });
  }

  if (action === "info") {
    const rec = await readKey(s, body.key);
    return rec ? json(200, { ok: true, record: rec }) : json(404, { ok: false, reason: "no such key" });
  }

  if (action === "list") {
    const keys = [];
    for await (const k of s.list()) {
      const rec = await readKey(s, typeof k === "string" ? k : k.key);
      if (rec) keys.push({ key: rec.key, label: rec.label, revoked: rec.revoked, expires: rec.expires });
    }
    return json(200, { ok: true, keys });
  }

  return json(400, { ok: false, reason: "unknown action" });
};
