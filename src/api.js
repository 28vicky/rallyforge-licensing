// RallyForge licensing - public API worker (license.rallyforge.workers.dev).
// Every request and response is JSON. Errors: { ok:false, error:"<code>", message:"<text to show the user>" }.
import { hashPassword, verifyPassword, randomToken, randomId, sha256, normCode } from './shared/crypto.js';
import {
  cfg, now, planStatus, log, logStmt, expireStaleLeases, grantLease, trimToLimit, endAllLeases,
  accountSummary, limitMessage, statusMessage, makeLicence, rateLimited, DAY_MS,
} from './shared/core.js';

class ApiError extends Error {
  constructor(status, code, message, extra) { super(message); this.status = status; this.code = code; this.extra = extra; }
}
const fail = (status, code, message, extra) => { throw new ApiError(status, code, message, extra); };

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const cleanEmail = (e) => String(e || '').trim().toLowerCase();
const str = (v, max = 100) => String(v ?? '').slice(0, max);

function checkPassword(p) {
  if (typeof p !== 'string' || p.length < 8) fail(400, 'weak_password', 'Password must be at least 8 characters.');
  if (p.length > 200) fail(400, 'weak_password', 'Password is too long.');
}

function readDevice(body) {
  const d = body.device || {};
  const hw = str(d.hw_id, 128);
  if (!hw) fail(400, 'bad_request', 'Missing device information. Update the app.');
  return { hw_id: hw, name: str(d.name, 60) || 'PC', app_version: str(d.app_version, 30) };
}

async function ipLimit(env, req, route, max, windowMs) {
  const ip = req.headers.get('cf-connecting-ip') || 'local';
  if (await rateLimited(env, `${route}:ip:${ip}`, max, windowMs))
    fail(429, 'rate_limited', 'Too many tries. Wait 15 minutes and try again.');
}

// Create a device session (or refresh the existing one for the same PC, which keeps its leases).
async function openSession(env, c, acc, dev, replaceDeviceId) {
  const t = now();
  const token = randomToken();
  const tokenHash = await sha256(token);
  const same = await env.DB.prepare('SELECT id FROM devices WHERE account_id = ? AND hw_id = ?').bind(acc.id, dev.hw_id).first();
  if (same) {
    await env.DB.prepare('UPDATE devices SET token_hash = ?, name = ?, app_version = ?, last_seen = ? WHERE id = ?')
      .bind(tokenHash, dev.name, dev.app_version, t, same.id).run();
    await log(env, acc.id, 'signin', { device: same.id, name: dev.name, same_pc: true });
    return { token, device_id: same.id };
  }
  if (replaceDeviceId) {
    const old = await env.DB.prepare('SELECT id, name FROM devices WHERE id = ? AND account_id = ?').bind(replaceDeviceId, acc.id).first();
    if (old) await removeDevices(env, acc.id, [old.id], 'device_replaced');
  }
  const count = (await env.DB.prepare('SELECT COUNT(*) AS n FROM devices WHERE account_id = ?').bind(acc.id).first()).n;
  if (count >= acc.device_limit) {
    const devices = (await env.DB.prepare('SELECT id, name, last_seen FROM devices WHERE account_id = ? ORDER BY last_seen ASC').bind(acc.id).all()).results;
    fail(409, 'device_limit', `You are signed in on ${count} PCs (the most allowed). Sign one out to use this PC.`, { devices });
  }
  const id = randomId();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO devices (id, account_id, token_hash, hw_id, name, app_version, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, acc.id, tokenHash, dev.hw_id, dev.name, dev.app_version, t, t),
    logStmt(env, acc.id, 'signin', { device: id, name: dev.name }),
  ]);
  return { token, device_id: id };
}

async function removeDevices(env, accountId, ids, kind) {
  if (!ids.length) return;
  const stmts = [];
  for (const id of ids) {
    stmts.push(env.DB.prepare('DELETE FROM leases WHERE device_id = ?').bind(id));
    stmts.push(env.DB.prepare('DELETE FROM devices WHERE id = ? AND account_id = ?').bind(id, accountId));
  }
  stmts.push(logStmt(env, accountId, kind, { devices: ids }));
  await env.DB.batch(stmts);
}

async function sessionReply(env, c, acc, deviceId, extra = {}) {
  const st = planStatus(acc, c);
  return json({
    ok: true,
    server_time: now(),
    licence: await makeLicence(env, c, acc, deviceId),
    message: statusMessage(st),
    account: await accountSummary(env, c, acc, deviceId),
    next_checkin_sec: c.heartbeatSec,
    ...extra,
  });
}

// Authenticated device from "Authorization: Bearer <token>".
async function auth(env, req) {
  const h = req.headers.get('authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  if (!token) fail(401, 'signed_out', 'You are signed out. Sign in again.');
  const dev = await env.DB.prepare('SELECT * FROM devices WHERE token_hash = ?').bind(await sha256(token)).first();
  if (!dev) fail(401, 'signed_out', 'This PC was signed out (password changed or signed out from another PC). Sign in again.');
  const acc = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(dev.account_id).first();
  if (!acc) fail(401, 'signed_out', 'Account not found. Sign in again.');
  return { dev, acc };
}

// ---- routes ----------------------------------------------------------------

async function signup(env, c, req, body) {
  await ipLimit(env, req, 'signup', 10, 60 * 60 * 1000);
  const email = cleanEmail(body.email);
  if (!EMAIL_RE.test(email) || email.length > 200) fail(400, 'bad_email', 'Enter a valid email address.');
  checkPassword(body.password);
  const dev = readDevice(body);
  let wanted = parseInt(body.instances, 10);
  if (!(wanted >= 1)) fail(400, 'bad_instances', 'Choose how many instances you want to run (1 or more).');
  wanted = Math.min(wanted, c.trialMaxInstances);

  if (await env.DB.prepare('SELECT 1 FROM accounts WHERE email = ?').bind(email).first())
    fail(409, 'email_taken', 'An account with this email already exists. Sign in instead, or use Forgot password.');

  const t = now();
  const usedPc = c.trialOnePerPc && (await env.DB.prepare('SELECT account_id FROM trial_pcs WHERE hw_id = ?').bind(dev.hw_id).first());
  const trialGiven = !usedPc;
  const id = randomId();
  const stmts = [
    env.DB.prepare('INSERT INTO accounts (id, email, password_hash, plan, instance_limit, device_limit, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, email, await hashPassword(body.password), 'trial', wanted, c.deviceLimitDefault, trialGiven ? t + c.trialDays * DAY_MS : t, t),
    logStmt(env, id, 'signup', { email, instances: wanted, trial: trialGiven, days: trialGiven ? c.trialDays : 0 }),
  ];
  if (trialGiven) stmts.push(env.DB.prepare('INSERT OR IGNORE INTO trial_pcs (hw_id, account_id, created_at) VALUES (?, ?, ?)').bind(dev.hw_id, id, t));
  try {
    await env.DB.batch(stmts);
  } catch (e) {
    if (String(e).includes('UNIQUE')) fail(409, 'email_taken', 'An account with this email already exists. Sign in instead.');
    throw e;
  }
  const acc = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(id).first();
  const s = await openSession(env, c, acc, dev);
  return sessionReply(env, c, acc, s.device_id, {
    token: s.token,
    device_id: s.device_id,
    trial_given: trialGiven,
    message: trialGiven
      ? `Account created. Your free trial runs ${c.trialDays} days with ${wanted} instance${wanted === 1 ? '' : 's'}.`
      : 'Account created. This PC already had a free trial, so no trial was added - message us on Discord to get started.',
  });
}

async function signin(env, c, req, body) {
  await ipLimit(env, req, 'signin', 20, 15 * 60 * 1000);
  const email = cleanEmail(body.email);
  if (await rateLimited(env, `signin:email:${email}`, 10, 15 * 60 * 1000))
    fail(429, 'rate_limited', 'Too many tries for this email. Wait 15 minutes and try again.');
  const dev = readDevice(body);
  const acc = await env.DB.prepare('SELECT * FROM accounts WHERE email = ?').bind(email).first();
  if (!acc || !(await verifyPassword(String(body.password || ''), acc.password_hash))) {
    await log(env, acc ? acc.id : '', 'signin_failed', { email });
    fail(401, 'bad_login', 'Wrong email or password.');
  }
  const s = await openSession(env, c, acc, dev, str(body.replace_device_id, 64));
  return sessionReply(env, c, acc, s.device_id, { token: s.token, device_id: s.device_id });
}

async function resetRequest(env, c, req, body) {
  await ipLimit(env, req, 'reset', 10, 15 * 60 * 1000);
  // Email codes are off in the beta (no domain yet). The owner makes the code in admin and gives it on Discord.
  return json({
    ok: true,
    method: c.emailCodes ? 'email' : 'discord',
    message: 'Ask for a reset code in our Discord. Then enter it here with your new password.',
  });
}

async function resetConfirm(env, c, req, body) {
  await ipLimit(env, req, 'reset', 30, 15 * 60 * 1000);
  const email = cleanEmail(body.email);
  if (await rateLimited(env, `reset:email:${email}`, 10, 15 * 60 * 1000))
    fail(429, 'rate_limited', 'Too many tries. Wait 15 minutes and try again.');
  checkPassword(body.new_password);
  const acc = await env.DB.prepare('SELECT * FROM accounts WHERE email = ?').bind(email).first();
  const codeHash = await sha256(normCode(body.code));
  const rc = acc && (await env.DB.prepare('SELECT * FROM reset_codes WHERE code_hash = ? AND account_id = ?').bind(codeHash, acc.id).first());
  if (!rc || rc.used || rc.expires_at < now()) {
    if (acc) await log(env, acc.id, 'reset_failed', {});
    fail(400, 'bad_code', 'This code is wrong or has expired. Ask for a new one.');
  }
  // New password signs out every PC (and stops their instances).
  const devs = (await env.DB.prepare('SELECT id FROM devices WHERE account_id = ?').bind(acc.id).all()).results.map((d) => d.id);
  await env.DB.batch([
    env.DB.prepare('UPDATE reset_codes SET used = 1 WHERE code_hash = ?').bind(codeHash),
    env.DB.prepare('UPDATE accounts SET password_hash = ? WHERE id = ?').bind(await hashPassword(body.new_password), acc.id),
    logStmt(env, acc.id, 'password_reset', { signed_out: devs.length }),
  ]);
  await removeDevices(env, acc.id, devs, 'signed_out_password');
  const dev = body.device ? readDevice(body) : null;
  if (!dev) return json({ ok: true, message: 'Password changed. All PCs were signed out - sign in again.' });
  const fresh = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(acc.id).first();
  const s = await openSession(env, c, fresh, dev);
  return sessionReply(env, c, fresh, s.device_id, {
    token: s.token, device_id: s.device_id,
    message: 'Password changed. Your other PCs were signed out and their instances stopped.',
  });
}

async function passwordChange(env, c, req, body) {
  const { dev, acc } = await auth(env, req);
  if (!(await verifyPassword(String(body.old_password || ''), acc.password_hash))) fail(401, 'bad_login', 'Current password is wrong.');
  checkPassword(body.new_password);
  await env.DB.prepare('UPDATE accounts SET password_hash = ? WHERE id = ?').bind(await hashPassword(body.new_password), acc.id).run();
  const others = (await env.DB.prepare('SELECT id FROM devices WHERE account_id = ? AND id != ?').bind(acc.id, dev.id).all()).results.map((d) => d.id);
  await removeDevices(env, acc.id, others, 'signed_out_password');
  return sessionReply(env, c, acc, dev.id, { message: 'Password changed. Your other PCs were signed out and their instances stopped.' });
}

// Heartbeat: "this PC is running these instances". Renews/reclaims leases, ends the ones no longer listed,
// tells the app which ones it must stop, and returns a fresh signed licence.
async function heartbeat(env, c, req, body) {
  let { dev, acc } = await auth(env, req);
  const t = now();
  let rekey;

  // Cloned Windows image: same device token, different hardware -> give this copy its own device.
  const hw = str(body.device?.hw_id, 128);
  if (hw && dev.hw_id && hw !== dev.hw_id) {
    const token = randomToken();
    const id = randomId();
    await env.DB.batch([
      env.DB.prepare('INSERT INTO devices (id, account_id, token_hash, hw_id, name, app_version, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(id, acc.id, await sha256(token), hw, str(body.device?.name, 60) || dev.name + ' (copy)', str(body.device?.app_version, 30), t, t),
      env.DB.prepare("UPDATE accounts SET flagged = ? WHERE id = ?").bind(`cloned PC seen ${new Date(t).toISOString()}`, acc.id),
      logStmt(env, acc.id, 'device_cloned', { from: dev.id, new_device: id }),
    ]);
    dev = await env.DB.prepare('SELECT * FROM devices WHERE id = ?').bind(id).first();
    rekey = { token, device_id: id };
  }

  await env.DB.prepare('UPDATE devices SET last_seen = ?, app_version = COALESCE(NULLIF(?, \'\'), app_version) WHERE id = ?')
    .bind(t, str(body.device?.app_version ?? body.app_version, 30), dev.id).run();

  const listed = Array.isArray(body.instances) ? body.instances.slice(0, 200) : [];
  const want = new Map();
  for (const i of listed) {
    const emu = str(i?.emulator, 80);
    if (emu) want.set(emu, str(i?.name, 60));
  }

  const st = planStatus(acc, c, t);
  const stop = [];
  if (st.status === 'expired') {
    await endAllLeases(env, acc.id, 'expired_stop');
    for (const [emu, name] of want) stop.push({ emulator: emu, name, reason: 'expired' });
  } else {
    await expireStaleLeases(env, c, acc.id);
    const trimmed = await trimToLimit(env, acc);
    const trimmedHere = new Set(trimmed.filter((l) => l.device_id === dev.id).map((l) => l.emulator));
    const held = new Set((await env.DB.prepare('SELECT emulator FROM leases WHERE device_id = ?').bind(dev.id).all()).results.map((r) => r.emulator));

    // Instances this PC no longer runs -> free them (normal Stop that the app didn't report).
    const gone = [...held].filter((e) => !want.has(e));
    if (gone.length) {
      const stmts = gone.map((e) => env.DB.prepare('DELETE FROM leases WHERE device_id = ? AND emulator = ?').bind(dev.id, e));
      stmts.push(logStmt(env, acc.id, 'lease_released', { device: dev.id, emulators: gone, via: 'heartbeat' }));
      await env.DB.batch(stmts);
    }

    for (const [emu, name] of want) {
      if (trimmedHere.has(emu)) { stop.push({ emulator: emu, name, reason: 'plan_lowered' }); continue; }
      const had = held.has(emu);
      if (await grantLease(env, acc, dev.id, emu, name)) {
        if (!had) await log(env, acc.id, 'lease_reclaimed', { device: dev.id, emulator: emu, name });
      } else {
        stop.push({ emulator: emu, name, reason: 'limit' });
        // It ran without a lease (lost contact with us) and the instances are used elsewhere now.
        await env.DB.batch([
          logStmt(env, acc.id, 'rejoined_over_limit', { device: dev.id, emulator: emu, name }),
          env.DB.prepare("UPDATE accounts SET flagged = ? WHERE id = ? AND flagged = ''").bind(`ran over the limit while offline ${new Date(t).toISOString()}`, acc.id),
        ]);
      }
    }
  }

  const summary = await accountSummary(env, c, acc, dev.id);
  for (const s of stop) {
    s.message = s.reason === 'expired' ? 'Plan expired - renew to continue.'
      : s.reason === 'plan_lowered' ? `Your plan now allows ${acc.instance_limit} instance${acc.instance_limit === 1 ? '' : 's'}; the newest ones were stopped.`
      : limitMessage(summary);
  }
  return sessionReply(env, c, acc, dev.id, { stop, ...(rekey ? { rekey } : {}) });
}

// Start button: ask for one instance.
async function start(env, c, req, body) {
  const { dev, acc } = await auth(env, req);
  const emu = str(body.emulator, 80);
  const name = str(body.name, 60);
  if (!emu) fail(400, 'bad_request', 'Missing emulator.');
  const st = planStatus(acc, c);
  if (st.status === 'expired') {
    await log(env, acc.id, 'lease_denied', { device: dev.id, emulator: emu, name, reason: 'expired' });
    fail(403, 'expired', 'Plan expired - renew to continue.');
  }
  await expireStaleLeases(env, c, acc.id);
  await env.DB.prepare('UPDATE devices SET last_seen = ? WHERE id = ?').bind(now(), dev.id).run();
  if (await grantLease(env, acc, dev.id, emu, name)) {
    await log(env, acc.id, 'lease_granted', { device: dev.id, emulator: emu, name });
    return sessionReply(env, c, acc, dev.id, { granted: true });
  }
  await log(env, acc.id, 'lease_denied', { device: dev.id, emulator: emu, name, reason: 'limit' });
  const summary = await accountSummary(env, c, acc, dev.id);
  fail(409, 'limit', limitMessage(summary), { account: summary });
}

// Stop button: free one instance, or all of this PC's (app closing).
async function stopRoute(env, c, req, body) {
  const { dev, acc } = await auth(env, req);
  if (body.all) {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM leases WHERE device_id = ?').bind(dev.id),
      logStmt(env, acc.id, 'lease_released', { device: dev.id, all: true }),
    ]);
  } else {
    const emu = str(body.emulator, 80);
    if (!emu) fail(400, 'bad_request', 'Missing emulator.');
    await env.DB.batch([
      env.DB.prepare('DELETE FROM leases WHERE device_id = ? AND emulator = ?').bind(dev.id, emu),
      logStmt(env, acc.id, 'lease_released', { device: dev.id, emulator: emu }),
    ]);
  }
  return sessionReply(env, c, acc, dev.id);
}

// Account card: "Free" on another PC's row, "Sign out other devices", or sign out this PC.
async function devicesSignout(env, c, req, body) {
  const { dev, acc } = await auth(env, req);
  let ids = [];
  if (body.others) {
    ids = (await env.DB.prepare('SELECT id FROM devices WHERE account_id = ? AND id != ?').bind(acc.id, dev.id).all()).results.map((d) => d.id);
  } else if (body.device_id) {
    const d = await env.DB.prepare('SELECT id FROM devices WHERE id = ? AND account_id = ?').bind(str(body.device_id, 64), acc.id).first();
    if (!d) fail(404, 'not_found', 'That PC is not on this account any more.');
    ids = [d.id];
  } else if (body.free_device_id) {
    // "Free" = end that PC's instances but keep it signed in.
    const d = await env.DB.prepare('SELECT id FROM devices WHERE id = ? AND account_id = ?').bind(str(body.free_device_id, 64), acc.id).first();
    if (!d) fail(404, 'not_found', 'That PC is not on this account any more.');
    await env.DB.batch([
      env.DB.prepare('DELETE FROM leases WHERE device_id = ?').bind(d.id),
      logStmt(env, acc.id, 'leases_freed', { device: d.id, by: dev.id }),
    ]);
    return sessionReply(env, c, acc, dev.id);
  } else {
    fail(400, 'bad_request', 'Nothing to sign out.');
  }
  await removeDevices(env, acc.id, ids, 'signed_out_by_user');
  if (ids.includes(dev.id)) return json({ ok: true, message: 'Signed out.' });
  return sessionReply(env, c, acc, dev.id);
}

async function signoutSelf(env, c, req) {
  const { dev, acc } = await auth(env, req);
  await removeDevices(env, acc.id, [dev.id], 'signed_out_self');
  return json({ ok: true, message: 'Signed out.' });
}

const ROUTES = {
  'POST /v1/signup': signup,
  'POST /v1/signin': signin,
  'POST /v1/reset/request': resetRequest,
  'POST /v1/reset/confirm': resetConfirm,
  'POST /v1/password/change': passwordChange,
  'POST /v1/heartbeat': heartbeat,
  'POST /v1/start': start,
  'POST /v1/stop': stopRoute,
  'POST /v1/devices/signout': devicesSignout,
  'POST /v1/signout': signoutSelf,
};

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === 'GET' && url.pathname === '/v1/time') return json({ ok: true, server_time: now() });
    if (req.method === 'GET' && url.pathname === '/') return json({ ok: true, service: 'rallyforge-license' });
    const handler = ROUTES[`${req.method} ${url.pathname}`];
    if (!handler) return json({ ok: false, error: 'not_found', message: 'Not found.' }, 404);
    try {
      let body = {};
      if (req.method === 'POST') {
        const text = await req.text();
        if (text.length > 64 * 1024) fail(413, 'too_large', 'Request too large.');
        try { body = text ? JSON.parse(text) : {}; } catch { fail(400, 'bad_json', 'Bad request.'); }
        if (typeof body !== 'object' || body === null) fail(400, 'bad_json', 'Bad request.');
      }
      return await handler(env, cfg(env), req, body);
    } catch (e) {
      if (e instanceof ApiError) return json({ ok: false, error: e.code, message: e.message, ...(e.extra || {}) }, e.status);
      console.error(e);
      return json({ ok: false, error: 'server_error', message: 'Server problem - your bots keep running. Try again in a few minutes.' }, 500);
    }
  },
};
