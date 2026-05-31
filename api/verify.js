const https = require('https');
const crypto = require('crypto');

const KV_URL   = process.env.KV_REST_API_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN;

function kv(method, path, body) {
  return new Promise((resolve) => {
    const u = new URL(KV_URL);
    const p = u.pathname.replace(/\/?$/, '') + '/' + path.replace(/^\//, '');
    const opts = { hostname: u.hostname, port: 443, path: p, method, timeout: 5000, headers: { 'Authorization': 'Bearer ' + KV_TOKEN, 'Content-Type': 'application/json' } };
    const r = https.request(opts, (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => { try { resolve({ s: res.statusCode, b: JSON.parse(d) }); } catch { resolve({ s: res.statusCode, b: null }); } }); });
    r.on('error', () => resolve(null));
    r.on('timeout', () => { r.destroy(); resolve(null); });
    if (body) r.write(JSON.stringify(body));
    r.end();
  });
}

module.exports = async (req, res) => {
  if (!KV_URL || !KV_TOKEN) {
    return res.status(500).json({ error: 'server configuration error' });
  }

  let key = null;
  const auth = req.headers['authorization'];
  if (auth && auth.startsWith('Bearer ')) {
    key = auth.slice(7).trim();
  }
  if (!key && req.method === 'POST') {
    const raw = typeof req.body === 'string' ? req.body : '';
    const m = raw.match(/key=([^&]*)/);
    if (m) key = decodeURIComponent(m[1].replace(/\+/g, ' ')).trim();
  }
  if (!key) {
    return res.status(401).json({ error: 'missing authorization key' });
  }

  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  const result = await kv('GET', '/get/key:' + keyHash);

  if (!result || result.s < 200 || result.s >= 300 || !result.b || !result.b.result) {
    return res.status(403).json({ error: 'invalid license key' });
  }

  const stored = result.b.result;
  if (!stored.key_hash || stored.key_hash.length !== keyHash.length ||
      !crypto.timingSafeEqual(Buffer.from(stored.key_hash), Buffer.from(keyHash))) {
    return res.status(403).json({ error: 'invalid license key' });
  }
  if (stored.revoked === true || stored.revoked === 'true') {
    return res.status(403).json({ error: 'license key revoked' });
  }

  res.status(200).json({ status: 'ok', message: 'authenticated', key: key.slice(0, 8) + '...' });
};
