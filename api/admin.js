const https = require('https');
const crypto = require('crypto');

const KV_URL   = process.env.KV_REST_API_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN;
const ADMIN_USER    = process.env.ADMIN_USER;
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH;

function kv(m, p, b) {
  return new Promise((ok) => {
    const u = new URL(KV_URL);
    const path = u.pathname.replace(/\/?$/, '') + '/' + p.replace(/^\//, '');
    const o = { hostname: u.hostname, port: 443, path, method: m, timeout: 5000,
      headers: { 'Authorization': 'Bearer ' + KV_TOKEN, 'Content-Type': 'application/json' } };
    const r = https.request(o, (res) => { let d = ''; res.on('data', c => d += c);
      res.on('end', () => { try { ok({ s: res.statusCode, b: JSON.parse(d) }); } catch { ok({ s: res.statusCode, b: null }); } }); });
    r.on('error', () => ok(null)); r.on('timeout', () => { r.destroy(); ok(null); });
    if (b) r.write(JSON.stringify(b)); r.end();
  });
}

function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

module.exports = async (req, res) => {
  if (!KV_URL || !KV_TOKEN || !ADMIN_USER || !ADMIN_PASS_HASH)
    return res.status(500).end('Server configuration error');

  // Parse body
  let body = {};
  if (req.body && typeof req.body === 'object' && !Array.isArray(req.body)) body = req.body;
  else if (typeof req.body === 'string')
    req.body.replace(/([^&=]+)=([^&]*)/g, (_, k, v) => { body[decodeURIComponent(k)] = decodeURIComponent(v.replace(/\+/g, ' ')); return ''; });
  req.body = body;

  // Session check
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => { const [k, ...v] = c.trim().split('='); if (k) cookies[k.trim()] = decodeURIComponent(v.join('=')).trim(); });
  let authed = false;
  if (cookies.vs) {
    const s = await kv('GET', '/sess:' + cookies.vs);
    if (s && s.s >= 200 && s.s < 300 && s.b && s.b.result)
      authed = Date.now() - new Date(s.b.result.at).getTime() < 7200000;
  }

  const action = body.action || '';
  let err = '', msg = '', gen = '';

  // Login
  if (req.method === 'POST' && action === 'login') {
    const user = (body.user || '').trim(), pass = body.pass || '';
    const uB = Buffer.from(user), aB = Buffer.from(ADMIN_USER);
    const pH = crypto.createHash('sha256').update(pass).digest('hex'), sH = ADMIN_PASS_HASH;
    if (uB.length === aB.length && crypto.timingSafeEqual(uB, aB) && pH.length === sH.length && crypto.timingSafeEqual(Buffer.from(pH), Buffer.from(sH))) {
      const t = crypto.randomBytes(32).toString('hex');
      await kv('POST', '/set/sess:' + t, { at: new Date().toISOString() });
      res.writeHead(302, { Location: '/api/admin', 'Set-Cookie': 'vs=' + t + '; HttpOnly; Secure; SameSite=Strict; Path=/api/admin; Max-Age=7200' });
      return res.end();
    }
    err = 'Invalid credentials.';
  }

  // Logout
  if (req.method === 'POST' && action === 'logout') {
    if (cookies.vs) await kv('DELETE', '/del/sess:' + cookies.vs);
    res.writeHead(302, { Location: '/api/admin', 'Set-Cookie': 'vs=; HttpOnly; Secure; SameSite=Strict; Path=/api/admin; Max-Age=0' });
    return res.end();
  }

  // Authenticated actions
  if (authed && req.method === 'POST') {
    const c = await kv('GET', '/csrf:' + cookies.vs);
    if (!c || !c.b || !c.b.result || c.b.result.t !== body._csrf) err = 'Invalid CSRF token.';
    else {
      try {
        if (action === 'generate') {
          const raw = crypto.randomBytes(32).toString('hex');
          const hash = crypto.createHash('sha256').update(raw).digest('hex');
          await kv('POST', '/set/key:' + hash, { key_hash: hash, prefix: raw.slice(0, 8), revoked: false, created_at: new Date().toISOString() });
          gen = raw;
        }
        if (action === 'revoke' && body.key_hash) {
          const e = await kv('GET', '/get/key:' + body.key_hash);
          if (e && e.b && e.b.result) { e.b.result.revoked = true; await kv('POST', '/set/key:' + body.key_hash, e.b.result); msg = 'Key revoked.'; }
        }
        if (action === 'delete' && body.key_hash) { await kv('DELETE', '/del/key:' + body.key_hash); msg = 'Key deleted.'; }
      } catch { err = 'Operation failed.'; }
    }
  }

  // CSRF
  let csrf = '';
  if (authed && cookies.vs) { csrf = crypto.randomBytes(32).toString('hex'); await kv('POST', '/set/csrf:' + cookies.vs, { t: csrf }); }

  // Fetch keys
  let keys = [];
  if (authed) {
    const sc = await kv('POST', '/scan/0', { match: 'key:*', count: 1000 });
    if (sc && sc.b && Array.isArray(sc.b.result)) {
      for (const rk of sc.b.result) {
        const rec = await kv('GET', '/get/' + rk);
        if (rec && rec.b && rec.b.result) keys.push(rec.b.result);
      }
      keys.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
    }
  }

  const HEAD = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Vanbreak Admin</title><style>';
  const CSS = 'body{font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;background:#0d0d0d;color:#e0e0e0;margin:0;padding:2rem}.container{max-width:960px;margin:0 auto}h1{color:#c8aaff;font-weight:300;border-bottom:1px solid #2a2a2a;padding-bottom:.5rem;display:inline-block}h2{color:#c8aaff;font-weight:300;margin:0}.card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}.flex{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;justify-content:space-between}.btn{display:inline-block;padding:.55rem 1.2rem;border:none;border-radius:4px;font-size:.9rem;cursor:pointer;text-decoration:none}.btn-primary{background:#7c5cbf;color:#fff}.btn-primary:hover{background:#6a4dab}.btn-danger{background:#b33;color:#fff}.btn-danger:hover{background:#922}.btn-ghost{background:transparent;color:#999;border:1px solid #333}.btn-ghost:hover{background:#222}table{width:100%;border-collapse:collapse;font-size:.85rem}th{text-align:left;padding:.6rem .4rem;border-bottom:1px solid #333;color:#888;font-weight:500}td{padding:.6rem .4rem;border-bottom:1px solid #222;vertical-align:middle;word-break:break-all}.badge{display:inline-block;padding:.15rem .5rem;border-radius:3px;font-size:.75rem}.badge-ok{background:#1f4a2a;color:#6f6}.badge-revoked{background:#4a1f1f;color:#f66}.msg{padding:.75rem 1rem;border-radius:4px;margin-bottom:1rem}.msg-ok{background:#1a2e1a;border:1px solid #2a4a2a;color:#6f6}.msg-err{background:#2e1a1a;border:1px solid #4a2a2a;color:#f66}.gen-key{background:#111;border:1px solid #333;border-radius:4px;padding:.75rem;margin:.75rem 0;font-family:\'SF Mono\',Consolas,monospace;font-size:.8rem;word-break:break-all;color:#c8aaff;user-select:all}footer{margin-top:2rem;font-size:.8rem;color:#555;text-align:center}label{display:block;margin-bottom:.25rem;color:#aaa;font-size:.85rem}input{width:100%;padding:.6rem .8rem;background:#111;border:1px solid #333;border-radius:4px;color:#e0e0e0;font-size:.95rem;margin-bottom:1rem;box-sizing:border-box}';
  const TAIL = '</div></body></html>';

  if (!authed) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.end(HEAD + CSS + '</style></head><body><div class="container" style="max-width:400px;margin:4rem auto"><h1 style="border:none">Vanbreak Admin</h1>' +
      (err ? '<div class="msg msg-err">' + esc(err) + '</div>' : '') +
      '<form method="post" class="card" action="/api/admin"><input type="hidden" name="action" value="login">' +
      '<label>Username</label><input type="text" name="user" autocomplete="username" required>' +
      '<label>Password</label><input type="password" name="pass" autocomplete="current-password" required>' +
      '<button class="btn btn-primary" style="width:100%">Sign In</button></form>' + TAIL);
  }

  let rows = keys.map(k => {
    const p = k.prefix || (k.key_hash || '').slice(0, 8) || '';
    const r = k.revoked === true || k.revoked === 'true';
    return '<tr><td><code>' + esc(p) + '...</code></td><td>' + esc(k.created_at || '—') + '</td><td>' +
      (r ? '<span class="badge badge-revoked">Revoked</span>' : '<span class="badge badge-ok">Active</span>') + '</td><td>' +
      '<form method="post" style="display:inline" onsubmit="return confirm(\'Are you sure?\')">' +
      '<input type="hidden" name="_csrf" value="' + esc(csrf) + '"><input type="hidden" name="key_hash" value="' + esc(k.key_hash || '') + '">' +
      (r ? '' : '<button name="action" value="revoke" class="btn btn-danger" style="padding:.3rem .6rem;font-size:.75rem">Revoke</button> ') +
      '<button name="action" value="delete" class="btn btn-ghost" style="padding:.3rem .6rem;font-size:.75rem">Delete</button></form></td></tr>';
  }).join('');

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(HEAD + CSS + '</style></head><body><div class="container"><div class="flex"><h1 style="border:none;margin:0">Vanbreak Admin</h1>' +
    '<form method="post"><input type="hidden" name="action" value="logout"><button class="btn btn-ghost">Logout</button></form></div>' +
    (err ? '<div class="msg msg-err">' + esc(err) + '</div>' : '') +
    (msg ? '<div class="msg msg-ok">' + esc(msg) + '</div>' : '') +
    (gen ? '<div class="card"><h2>Key Generated</h2><p style="color:#888;font-size:.85rem">Copy this key now.</p><div class="gen-key">' + esc(gen) + '</div></div>' : '') +
    '<div class="card"><div class="flex"><h2>License Keys</h2>' +
    '<form method="post"><input type="hidden" name="_csrf" value="' + esc(csrf) + '"><input type="hidden" name="action" value="generate"><button class="btn btn-primary">Generate New Key</button></form></div></div>' +
    '<div class="card">' + (keys.length === 0 ? '<p style="color:#666">No keys yet.</p>' : '<table><thead><tr><th>Prefix</th><th>Created</th><th>Status</th><th>Actions</th></tr></thead><tbody>' + rows + '</tbody></table>') + '</div>' +
    '<footer>Vanbreak License Server</footer>' + TAIL);
};
