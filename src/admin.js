// RallyForge licensing - admin worker (admin.rallyforge.workers.dev), owner only.
// Protected by Cloudflare Access on its workers.dev address, and this code also checks the Access token
// itself (team domain + AUD + allowed email), so a misconfigured Access app can't open it.
import { hashPassword, randomToken, randomId, randomCode, sha256, normCode, b64urlDecode } from './shared/crypto.js';
import { cfg, now, planStatus, logStmt, log, endAllLeases, accountSummary, DAY_MS } from './shared/core.js';
import PAGE from './admin_page.html';

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });

class AdminError extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (status, message) => { throw new AdminError(status, message); };

// ---- Cloudflare Access token check ---------------------------------------------------------
let certCache = { at: 0, keys: [] };
async function accessKeys(team) {
  if (Date.now() - certCache.at < 3600 * 1000 && certCache.keys.length) return certCache.keys;
  const r = await fetch(`https://${team}/cdn-cgi/access/certs`);
  const j = await r.json();
  certCache = { at: Date.now(), keys: j.keys || [] };
  return certCache.keys;
}

async function checkAccess(req, env) {
  const host = new URL(req.url).hostname;
  if (env.ADMIN_LOCAL_DEV === 'on' && (host === 'localhost' || host === '127.0.0.1')) return 'local-dev';
  const team = env.ACCESS_TEAM_DOMAIN, aud = env.ACCESS_AUD;
  const allowed = String(env.ADMIN_EMAILS || '').toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);
  if (!team || !aud || !allowed.length) fail(403, 'Admin is not set up (ACCESS_TEAM_DOMAIN / ACCESS_AUD / ADMIN_EMAILS).');
  const jwt = req.headers.get('cf-access-jwt-assertion');
  if (!jwt) fail(403, 'No Cloudflare Access sign-in.');
  const [h, p, s] = jwt.split('.');
  if (!h || !p || !s) fail(403, 'Bad Access token.');
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(h)));
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
  const jwk = (await accessKeys(team)).find((k) => k.kid === header.kid);
  if (!jwk) fail(403, 'Unknown Access key.');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlDecode(s), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) fail(403, 'Bad Access signature.');
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(aud)) fail(403, 'Access token is for another app.');
  if (!payload.exp || payload.exp * 1000 < Date.now()) fail(403, 'Access sign-in expired - reload.');
  const email = String(payload.email || '').toLowerCase();
  if (!allowed.includes(email)) fail(403, 'This email is not an admin.');
  return email;
}

// ---- helpers -------------------------------------------------------------------------------
const getAcc = async (env, id) => {
  const a = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(String(id || '')).first();
  if (!a) fail(404, 'Account not found.');
  return a;
};
const pub = (a, c) => {
  const st = planStatus(a, c);
  const { password_hash, ...rest } = a;
  return { ...rest, status: st.status, grace_until: st.grace_until, days_left: st.days_left };
};
const int = (v, name, min = 0) => {
  const n = parseInt(v, 10);
  if (!(n >= min)) fail(400, `${name} must be a number ${min} or more.`);
  return n;
};

async function makeResetCode(env, c, accountId, admin) {
  const code = randomCode();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO reset_codes (code_hash, account_id, expires_at) VALUES (?, ?, ?)').bind(await sha256(normCode(code)), accountId, now() + c.resetCodeMs),
    logStmt(env, accountId, 'reset_code_made', { by: admin, minutes: c.resetCodeMs / 60000 }),
  ]);
  return { code, valid_minutes: c.resetCodeMs / 60000 };
}

// ---- admin API -----------------------------------------------------------------------------
const API = {
  async 'GET overview'(env, c) {
    const t = now();
    const cols = 'id, email, plan, instance_limit, device_limit, expires_at, created_at, notes, flagged';
    const expiring = (await env.DB.prepare(`SELECT ${cols} FROM accounts WHERE expires_at BETWEEN ? AND ? ORDER BY expires_at`).bind(t - c.paidGraceMs, t + 7 * DAY_MS).all()).results;
    const flagged = (await env.DB.prepare(`SELECT ${cols} FROM accounts WHERE flagged != '' ORDER BY created_at DESC`).all()).results;
    const recent = (await env.DB.prepare(`SELECT ${cols} FROM accounts ORDER BY created_at DESC LIMIT 25`).all()).results;
    const atLimit = (await env.DB.prepare(
      `SELECT a.id, a.email, a.instance_limit, COUNT(l.emulator) AS in_use FROM accounts a JOIN leases l ON l.account_id = a.id
       WHERE l.last_seen >= ? GROUP BY a.id HAVING in_use >= a.instance_limit`
    ).bind(t - c.leaseTtlMs).all()).results;
    const totals = await env.DB.prepare(
      `SELECT (SELECT COUNT(*) FROM accounts) AS accounts,
              (SELECT COUNT(*) FROM accounts WHERE expires_at > ?1) AS active,
              (SELECT COUNT(*) FROM leases WHERE last_seen >= ?2) AS running,
              (SELECT COUNT(*) FROM devices WHERE last_seen >= ?2) AS pcs_online`
    ).bind(t, t - c.leaseTtlMs).first();
    return { server_time: t, totals, expiring: expiring.map((a) => pub(a, c)), flagged: flagged.map((a) => pub(a, c)), recent: recent.map((a) => pub(a, c)), at_limit: atLimit };
  },

  async 'GET account'(env, c, q) {
    const email = String(q.get('email') || '').trim().toLowerCase();
    const id = q.get('id');
    const a = id ? await getAcc(env, id)
      : await env.DB.prepare('SELECT * FROM accounts WHERE email = ?').bind(email).first();
    if (!a) {
      const like = (await env.DB.prepare('SELECT id, email FROM accounts WHERE email LIKE ? LIMIT 10').bind(`%${email}%`).all()).results;
      return { found: false, matches: like };
    }
    const payments = (await env.DB.prepare('SELECT * FROM payments WHERE account_id = ? ORDER BY date DESC LIMIT 50').bind(a.id).all()).results;
    const events = (await env.DB.prepare('SELECT ts, kind, detail FROM events WHERE account_id = ? ORDER BY id DESC LIMIT 60').bind(a.id).all()).results;
    return { found: true, account: pub(a, c), card: await accountSummary(env, c, a, null), payments, events };
  },

  // Key-user migration / hand-made accounts: account + a reset code the user turns into a password.
  async 'POST create'(env, c, b, admin) {
    const email = String(b.email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail(400, 'Enter a valid email.');
    if (await env.DB.prepare('SELECT 1 FROM accounts WHERE email = ?').bind(email).first()) fail(409, 'That email already has an account.');
    const instances = int(b.instances, 'Instances', 1);
    const days = int(b.days, 'Days', 0);
    const plan = b.plan === 'trial' ? 'trial' : 'paid';
    const t = now();
    const id = randomId();
    await env.DB.batch([
      env.DB.prepare('INSERT INTO accounts (id, email, password_hash, plan, instance_limit, device_limit, expires_at, created_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(id, email, await hashPassword(randomToken(24)), plan, instances, c.deviceLimitDefault, t + days * DAY_MS, t, String(b.notes || '').slice(0, 500)),
      logStmt(env, id, 'admin_created', { by: admin, plan, instances, days }),
    ]);
    return { id, reset: await makeResetCode(env, c, id, admin) };
  },

  async 'POST update'(env, c, b, admin) {
    const a = await getAcc(env, b.id);
    const changes = {};
    if (b.plan !== undefined) { if (!['trial', 'paid'].includes(b.plan)) fail(400, 'Plan must be trial or paid.'); changes.plan = b.plan; }
    if (b.instance_limit !== undefined) changes.instance_limit = int(b.instance_limit, 'Instances', 0);
    if (b.device_limit !== undefined) changes.device_limit = int(b.device_limit, 'PC limit', 1);
    if (b.expires_at !== undefined) changes.expires_at = int(b.expires_at, 'Expiry', 0);
    if (b.notes !== undefined) changes.notes = String(b.notes).slice(0, 2000);
    if (b.flagged !== undefined) changes.flagged = String(b.flagged).slice(0, 300);
    if (b.email !== undefined) {
      const e = String(b.email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) fail(400, 'Enter a valid email.');
      if (e !== a.email && (await env.DB.prepare('SELECT 1 FROM accounts WHERE email = ?').bind(e).first())) fail(409, 'That email already has an account.');
      changes.email = e;
    }
    const keys = Object.keys(changes);
    if (!keys.length) return { ok: true };
    const before = Object.fromEntries(keys.filter((k) => k !== 'notes').map((k) => [k, a[k]]));
    const after = Object.fromEntries(keys.filter((k) => k !== 'notes').map((k) => [k, changes[k]]));
    await env.DB.batch([
      env.DB.prepare(`UPDATE accounts SET ${keys.map((k) => `${k} = ?`).join(', ')} WHERE id = ?`).bind(...keys.map((k) => changes[k]), a.id),
      logStmt(env, a.id, 'admin_update', { by: admin, before, after }),
    ]);
    return { ok: true };
  },

  // "Add 30 days": extends from the later of today or the current expiry (unused days are never lost).
  async 'POST add_days'(env, c, b, admin) {
    const a = await getAcc(env, b.id);
    const days = int(b.days, 'Days', 1);
    const instances = b.instances === undefined || b.instances === '' ? a.instance_limit : int(b.instances, 'Instances', 1);
    const t = now();
    const newExp = Math.max(t, a.expires_at) + days * DAY_MS;
    await env.DB.batch([
      env.DB.prepare("UPDATE accounts SET plan = 'paid', instance_limit = ?, expires_at = ? WHERE id = ?").bind(instances, newExp, a.id),
      env.DB.prepare('INSERT INTO payments (account_id, date, amount, currency, method, days_added, instances, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(a.id, t, Number(b.amount) || 0, String(b.currency || '').slice(0, 10), String(b.method || '').slice(0, 40), days, instances, String(b.note || '').slice(0, 300)),
      logStmt(env, a.id, 'admin_add_days', { by: admin, days, instances, old_expiry: a.expires_at, new_expiry: newExp }),
    ]);
    return { ok: true, expires_at: newExp };
  },

  async 'POST signout_all'(env, c, b, admin) {
    const a = await getAcc(env, b.id);
    const ended = await endAllLeases(env, a.id, 'admin_end_leases');
    const n = (await env.DB.prepare('SELECT COUNT(*) AS n FROM devices WHERE account_id = ?').bind(a.id).first()).n;
    await env.DB.batch([
      env.DB.prepare('DELETE FROM devices WHERE account_id = ?').bind(a.id),
      logStmt(env, a.id, 'admin_signout_all', { by: admin, devices: n, instances: ended.length }),
    ]);
    return { ok: true, devices: n };
  },

  async 'POST reset_code'(env, c, b, admin) {
    const a = await getAcc(env, b.id);
    return await makeResetCode(env, c, a.id, admin);
  },

  async 'POST free_pc'(env, c, b, admin) {
    const a = await getAcc(env, b.id);
    await env.DB.batch([
      env.DB.prepare('DELETE FROM leases WHERE account_id = ? AND device_id = ?').bind(a.id, String(b.device_id || '')),
      logStmt(env, a.id, 'leases_freed', { by: admin, device: b.device_id }),
    ]);
    return { ok: true };
  },

  async 'POST allow_trial_again'(env, c, b, admin) {
    // Remove the "one trial per PC" mark for every PC this account used (e.g. owner testing sign-ups).
    const a = await getAcc(env, b.id);
    const r = await env.DB.prepare('DELETE FROM trial_pcs WHERE hw_id IN (SELECT hw_id FROM devices WHERE account_id = ?) OR account_id = ?').bind(a.id, a.id).run();
    await log(env, a.id, 'admin_trial_reset', { by: admin, pcs: r.meta.changes });
    return { ok: true, pcs: r.meta.changes };
  },

  // Daily backup: everything except password hashes.
  async 'GET export'(env) {
    const accounts = (await env.DB.prepare('SELECT id, email, plan, instance_limit, device_limit, expires_at, created_at, notes, flagged FROM accounts').all()).results;
    const payments = (await env.DB.prepare('SELECT * FROM payments').all()).results;
    const devices = (await env.DB.prepare('SELECT id, account_id, name, app_version, created_at, last_seen FROM devices').all()).results;
    return { exported_at: now(), accounts, payments, devices };
  },
};

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      const admin = await checkAccess(req, env);
      if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/admin')) {
        return new Response(PAGE, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY' } });
      }
      const m = url.pathname.match(/^\/api\/([a-z_]+)$/);
      const fn = m && API[`${req.method} ${m[1]}`];
      if (!fn) return json({ ok: false, message: 'Not found.' }, 404);
      let body = {};
      if (req.method === 'POST') {
        // Custom header forces a CORS preflight, so other sites can't post with the owner's Access cookie.
        if (req.headers.get('x-admin') !== '1') fail(403, 'Missing admin header.');
        body = await req.json().catch(() => fail(400, 'Bad JSON.'));
      }
      const out = await fn(env, cfg(env), req.method === 'GET' ? url.searchParams : body, admin);
      return json({ ok: true, ...out });
    } catch (e) {
      if (e instanceof AdminError) return json({ ok: false, message: e.message }, e.status);
      console.error(e);
      return json({ ok: false, message: 'Server error: ' + String(e.message || e) }, 500);
    }
  },
};
