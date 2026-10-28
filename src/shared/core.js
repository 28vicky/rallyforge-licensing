// Shared licensing logic used by the public API worker and the admin worker.
import { signLicence } from './crypto.js';

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
const MIN = 60 * 1000;

export function cfg(env) {
  const n = (v, d) => (v === undefined || v === '' || isNaN(Number(v)) ? d : Number(v));
  return {
    trialDays: n(env.TRIAL_DAYS, 30),
    trialMaxInstances: n(env.TRIAL_MAX_INSTANCES, 30),
    trialOnePerPc: String(env.TRIAL_ONE_PER_PC ?? 'on') !== 'off',
    paidGraceMs: n(env.PAID_GRACE_HOURS, 24) * HOUR,
    offlineGraceMs: n(env.OFFLINE_GRACE_HOURS, 72) * HOUR,
    leaseTtlMs: n(env.LEASE_TTL_MIN, 20) * MIN,
    heartbeatSec: n(env.HEARTBEAT_SEC, 300),
    deviceLimitDefault: n(env.DEVICE_LIMIT_DEFAULT, 5),
    resetCodeMs: n(env.RESET_CODE_MINUTES, 60) * MIN,
    warnDays: n(env.WARN_DAYS, 3),
    emailCodes: String(env.EMAIL_CODES ?? 'off') === 'on',
  };
}

export const now = () => Date.now();

// ---- plan status ---------------------------------------------------------
export function planStatus(acc, c, t = now()) {
  const graceUntil = acc.plan === 'paid' ? acc.expires_at + c.paidGraceMs : acc.expires_at;
  let status = 'active';
  if (t >= acc.expires_at) status = t < graceUntil ? 'grace' : 'expired';
  const msLeft = acc.expires_at - t;
  const warn = status === 'active' && msLeft <= c.warnDays * DAY;
  return { status, grace_until: graceUntil, warn, days_left: Math.max(0, Math.ceil(msLeft / DAY)) };
}

// ---- events (audit log) --------------------------------------------------
export function logStmt(env, accountId, kind, detail) {
  return env.DB.prepare('INSERT INTO events (ts, account_id, kind, detail) VALUES (?, ?, ?, ?)')
    .bind(now(), accountId || '', kind, typeof detail === 'string' ? detail : JSON.stringify(detail ?? ''));
}
export async function log(env, accountId, kind, detail) {
  await logStmt(env, accountId, kind, detail).run();
}

// ---- leases --------------------------------------------------------------
// Remove leases that had no heartbeat for LEASE_TTL; log each one.
export async function expireStaleLeases(env, c, accountId) {
  const cutoff = now() - c.leaseTtlMs;
  const stale = await env.DB.prepare(
    'SELECT device_id, emulator, name FROM leases WHERE account_id = ? AND last_seen < ?'
  ).bind(accountId, cutoff).all();
  if (!stale.results.length) return;
  const stmts = [env.DB.prepare('DELETE FROM leases WHERE account_id = ? AND last_seen < ?').bind(accountId, cutoff)];
  for (const l of stale.results) stmts.push(logStmt(env, accountId, 'lease_expired', { device: l.device_id, emulator: l.emulator, name: l.name }));
  await env.DB.batch(stmts);
}

// Atomic grant / renew / reclaim. One SQL statement: inserts (or refreshes) the lease only if the
// account's OTHER live leases are below the limit. D1 runs writes one at a time, so two PCs asking
// for the last instance at the same moment can't both get it.
export async function grantLease(env, acc, deviceId, emulator, name) {
  const t = now();
  const r = await env.DB.prepare(
    `INSERT INTO leases (device_id, emulator, account_id, name, started_at, last_seen)
     SELECT ?1, ?2, ?3, ?4, ?5, ?5
     WHERE (SELECT COUNT(*) FROM leases WHERE account_id = ?3 AND NOT (device_id = ?1 AND emulator = ?2)) < ?6
     ON CONFLICT(device_id, emulator) DO UPDATE SET last_seen = excluded.last_seen, name = excluded.name`
  ).bind(deviceId, emulator, acc.id, name || '', t, acc.instance_limit).run();
  return r.meta.changes > 0;
}

// Plan lowered while more instances run: keep the oldest N, end the newest ones.
export async function trimToLimit(env, acc) {
  const rows = (await env.DB.prepare(
    'SELECT device_id, emulator, name FROM leases WHERE account_id = ? ORDER BY started_at ASC, rowid ASC'
  ).bind(acc.id).all()).results;
  const extra = rows.slice(Math.max(0, acc.instance_limit));
  if (!extra.length) return [];
  const stmts = [];
  for (const l of extra) {
    stmts.push(env.DB.prepare('DELETE FROM leases WHERE device_id = ? AND emulator = ?').bind(l.device_id, l.emulator));
    stmts.push(logStmt(env, acc.id, 'lease_trimmed', { device: l.device_id, emulator: l.emulator, name: l.name, limit: acc.instance_limit }));
  }
  await env.DB.batch(stmts);
  return extra;
}

export async function endAllLeases(env, accountId, kind) {
  const rows = (await env.DB.prepare('SELECT device_id, emulator, name FROM leases WHERE account_id = ?').bind(accountId).all()).results;
  if (!rows.length) return [];
  await env.DB.batch([
    env.DB.prepare('DELETE FROM leases WHERE account_id = ?').bind(accountId),
    logStmt(env, accountId, kind, { ended: rows.map((l) => l.name || l.emulator) }),
  ]);
  return rows;
}

// ---- account card --------------------------------------------------------
export async function accountSummary(env, c, acc, thisDeviceId) {
  const devices = (await env.DB.prepare(
    'SELECT id, name, app_version, last_seen FROM devices WHERE account_id = ? ORDER BY created_at ASC'
  ).bind(acc.id).all()).results;
  const leases = (await env.DB.prepare(
    'SELECT device_id, emulator, name FROM leases WHERE account_id = ? AND last_seen >= ? ORDER BY started_at ASC'
  ).bind(acc.id, now() - c.leaseTtlMs).all()).results;
  const st = planStatus(acc, c);
  return {
    email: acc.email,
    plan: acc.plan,
    status: st.status,
    expires_at: acc.expires_at,
    grace_until: st.grace_until,
    warn: st.warn,
    days_left: st.days_left,
    instances: { in_use: leases.length, limit: acc.instance_limit, free: Math.max(0, acc.instance_limit - leases.length) },
    device_limit: acc.device_limit,
    devices: devices.map((d) => {
      const mine = leases.filter((l) => l.device_id === d.id);
      return {
        id: d.id,
        name: d.name,
        this_device: d.id === thisDeviceId,
        app_version: d.app_version,
        last_seen: d.last_seen,
        running: mine.map((l) => ({ emulator: l.emulator, name: l.name })),
      };
    }),
  };
}

// "All 20 instances are in use (12 on PC-A, 8 on PC-B). Stop one to start this."
export function limitMessage(summary) {
  const where = summary.devices
    .filter((d) => d.running.length)
    .map((d) => `${d.running.length} on ${d.name || 'another PC'}`)
    .join(', ');
  const n = summary.instances.limit;
  return `All ${n} instance${n === 1 ? '' : 's'} are in use${where ? ` (${where})` : ''}. Stop one to start this.`;
}

export function statusMessage(st) {
  if (st.status === 'expired') return 'Plan expired - renew to continue.';
  if (st.status === 'grace') return 'Plan expired - your bots keep running for up to 24 h. Renew to continue.';
  if (st.warn) return `Plan ends in ${st.days_left} day${st.days_left === 1 ? '' : 's'}.`;
  return '';
}

// ---- licence -------------------------------------------------------------
export async function makeLicence(env, c, acc, deviceId) {
  const t = now();
  const st = planStatus(acc, c, t);
  const payload = {
    v: 1,
    account_id: acc.id,
    email: acc.email,
    device_id: deviceId,
    plan: acc.plan,
    status: st.status,
    instances: acc.instance_limit,
    expires_at: acc.expires_at,
    grace_until: st.grace_until,
    issued_at: t,
    valid_until: t + c.offlineGraceMs,
  };
  if (!env.LICENCE_PRIVATE_KEY) throw new Error('LICENCE_PRIVATE_KEY secret is not set');
  return await signLicence(payload, env.LICENCE_PRIVATE_KEY);
}

// ---- rate limiting (fixed window, stored in D1) ----------------------------
export async function rateLimited(env, key, max, windowMs) {
  const t = now();
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (key, window_start, count) VALUES (?1, ?2, 1)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN rate_limits.window_start < ?3 THEN 1 ELSE rate_limits.count + 1 END,
       window_start = CASE WHEN rate_limits.window_start < ?3 THEN ?2 ELSE rate_limits.window_start END
     RETURNING count`
  ).bind(key, t, t - windowMs).first();
  return row.count > max;
}

export const DAY_MS = DAY;
