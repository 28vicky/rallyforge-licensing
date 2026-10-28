// Local end-to-end tests: both workers in Miniflare sharing one D1 database.
// Run: npm test   (bundles with wrangler --dry-run first)
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { execSync } from 'node:child_process';
import { readFileSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { generateKeyPairSync, verify as edVerify, createPublicKey } from 'node:crypto';

rmSync('.wrangler/test', { recursive: true, force: true });
mkdirSync('.wrangler/test', { recursive: true });
execSync('npx wrangler deploy --dry-run --outdir .wrangler/test/api', { stdio: 'ignore' });
execSync('npx wrangler deploy --dry-run -c wrangler.admin.toml --outdir .wrangler/test/admin', { stdio: 'ignore' });

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const PRIV = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');

const vars = {
  TRIAL_DAYS: '30', TRIAL_MAX_INSTANCES: '30', TRIAL_ONE_PER_PC: 'on', PAID_GRACE_HOURS: '24', OFFLINE_GRACE_HOURS: '72',
  LEASE_TTL_MIN: '20', HEARTBEAT_SEC: '300', DEVICE_LIMIT_DEFAULT: '5', WARN_DAYS: '3', EMAIL_CODES: 'off', RESET_CODE_MINUTES: '60',
};
const mf = new Miniflare(convertV4MiniflareOptions({
  d1Persist: false,
  workers: [
    { name: 'api', modules: true, scriptPath: '.wrangler/test/api/api.js', compatibilityDate: '2026-10-01', d1Databases: { DB: 'lic' }, bindings: { ...vars, LICENCE_PRIVATE_KEY: PRIV } },
    { name: 'admin', modulesRoot: '.wrangler/test/admin', modules: [{ type: 'ESModule', path: '.wrangler/test/admin/admin.js' }, ...readdirSync('.wrangler/test/admin').filter((f) => f.endsWith('.html')).map((f) => ({ type: 'Text', path: '.wrangler/test/admin/' + f }))], compatibilityDate: '2026-10-01', d1Databases: { DB: 'lic' }, bindings: { ...vars, ADMIN_LOCAL_DEV: 'on' } },
  ],
}));
const DB = await mf.getD1Database('DB', 'api');
const sql = readFileSync('migrations/0001_init.sql', 'utf8').replace(/--.*$/gm, '');
for (const s of sql.split(';').map((x) => x.trim()).filter(Boolean)) await DB.prepare(s).run();
const api = await mf.getWorker('api');
const adm = await mf.getWorker('admin');

let passed = 0, failed = 0;
function check(name, cond, info) {
  if (cond) { passed++; console.log('  ok  ' + name); }
  else { failed++; console.log('  FAIL ' + name + (info !== undefined ? '  -> ' + JSON.stringify(info).slice(0, 400) : '')); }
}
let ipN = 0;
async function call(path, body, token, ip) {
  const headers = { 'content-type': 'application/json', 'cf-connecting-ip': ip || `10.0.0.${(ipN++ % 250) + 1}` };
  if (token) headers.authorization = 'Bearer ' + token;
  const r = await api.fetch('http://localhost' + path, { method: 'POST', headers, body: JSON.stringify(body || {}) });
  return { status: r.status, ...(await r.json()) };
}
async function admin(path, body, opts = {}) {
  const headers = body ? { 'content-type': 'application/json', 'x-admin': opts.noHeader ? '0' : '1' } : {};
  const r = await adm.fetch((opts.host || 'http://localhost') + '/api/' + path, body ? { method: 'POST', headers, body: JSON.stringify(body) } : {});
  return { status: r.status, ...(await r.json()) };
}
const dev = (hw, name) => ({ hw_id: hw, name, app_version: '2.6.0' });
const MIN = 60000, HOUR = 60 * MIN, DAY = 24 * HOUR;
const accId = async (email) => (await DB.prepare('SELECT id FROM accounts WHERE email = ?').bind(email).first()).id;

function verifyLicence(lic) {
  const [body, sig] = lic.split('.');
  const pub = createPublicKey({ key: publicKey.export({ type: 'spki', format: 'der' }), format: 'der', type: 'spki' });
  const ok = edVerify(null, Buffer.from(body), pub, Buffer.from(sig, 'base64url'));
  return { ok, payload: JSON.parse(Buffer.from(body, 'base64url').toString()) };
}

console.log('\n# Sign up / trial');
let r = await call('/v1/signup', { email: 'Friend@Example.com', password: 'secret123', instances: 50, device: dev('hwA', 'PC-HOME') });
check('signup ok', r.ok && r.token, r);
check('trial given, 30 days', r.trial_given && Math.abs(r.account.expires_at - Date.now() - 30 * DAY) < MIN, r.account);
check('instances capped at 30', r.account.instances.limit === 30, r.account.instances);
check('email stored lower-case', r.account.email === 'friend@example.com');
const lic = verifyLicence(r.licence);
check('licence signature valid', lic.ok);
check('licence valid 72 h', Math.abs(lic.payload.valid_until - Date.now() - 72 * HOUR) < MIN, lic.payload);
const [lb, ls] = r.licence.split('.');
const forged = Buffer.from(JSON.stringify({ ...lic.payload, instances: 999 })).toString('base64url') + '.' + ls;
check('edited licence fails signature', !verifyLicence(forged).ok);

r = await call('/v1/signup', { email: 'friend@example.com', password: 'secret123', instances: 2, device: dev('hwZ', 'X') });
check('duplicate email refused', r.status === 409 && r.error === 'email_taken', r);
r = await call('/v1/signup', { email: 'second@example.com', password: 'secret123', instances: 2, device: dev('hwA', 'PC-HOME') });
check('second account on same PC: created, no trial', r.ok && r.trial_given === false && r.account.status === 'expired', r);
r = await call('/v1/signup', { email: 'bad', password: 'secret123', instances: 2, device: dev('hwQ', 'X') });
check('bad email refused', r.status === 400);
r = await call('/v1/signup', { email: 'short@example.com', password: 'abc', instances: 2, device: dev('hwQ', 'X') });
check('short password refused', r.status === 400 && r.error === 'weak_password');

console.log('\n# Sign in');
r = await call('/v1/signin', { email: 'friend@example.com', password: 'wrong', device: dev('hwA', 'PC-HOME') });
check('wrong password', r.status === 401 && r.error === 'bad_login');
r = await call('/v1/signup', { email: 'boss@example.com', password: 'secret123', instances: 3, device: dev('hwB1', 'PC-HOME') });
const bossId = await accId('boss@example.com');
const A = r.token, devA = r.device_id;
r = await call('/v1/signin', { email: 'boss@example.com', password: 'secret123', device: dev('hwB2', 'PC-OFFICE') });
check('sign in on 2nd PC', r.ok && r.account.devices.length === 2, r);
const B = r.token, devB = r.device_id;

console.log('\n# Instances across 2 PCs (limit 3)');
r = await call('/v1/start', { emulator: '127.0.0.1:16416', name: 'Kiravik' }, A);
check('PC-HOME start 1', r.ok && r.granted && r.account.instances.in_use === 1, r);
r = await call('/v1/start', { emulator: '127.0.0.1:16448', name: 'Rob' }, A);
check('PC-HOME start 2', r.ok && r.account.instances.in_use === 2);
r = await call('/v1/start', { emulator: '127.0.0.1:16416', name: 'Farm1' }, B);
check('PC-OFFICE same emulator address works (3 of 3)', r.ok && r.account.instances.in_use === 3, r);
r = await call('/v1/start', { emulator: '127.0.0.1:16480', name: 'Farm2' }, B);
check('4th refused with where-used message', r.status === 409 && r.error === 'limit' && /2 on PC-HOME, 1 on PC-OFFICE/.test(r.message), r);
r = await call('/v1/start', { emulator: '127.0.0.1:16416', name: 'Kiravik' }, A);
check('restarting a running instance keeps its place (at limit)', r.ok, r);

console.log('\n# Same-second race for the last instance');
await call('/v1/stop', { emulator: '127.0.0.1:16416' }, B);
const race = await Promise.all([
  call('/v1/start', { emulator: '127.0.0.1:20000', name: 'RaceA' }, A),
  call('/v1/start', { emulator: '127.0.0.1:20001', name: 'RaceB' }, B),
  call('/v1/start', { emulator: '127.0.0.1:20002', name: 'RaceC' }, B),
]);
check('exactly one of three wins', race.filter((x) => x.ok).length === 1, race.map((x) => x.status));
const live = (await DB.prepare('SELECT COUNT(*) n FROM leases WHERE account_id = ?').bind(bossId).first()).n;
check('never over the limit', live === 3, live);

console.log('\n# Heartbeat: renew, release, reclaim after crash');
const winner = race.find((x) => x.ok);
const winTok = winner === race[0] ? A : B;
const winEmu = winner === race[0] ? '127.0.0.1:20000' : race[1].ok ? '127.0.0.1:20001' : '127.0.0.1:20002';
r = await call('/v1/heartbeat', { instances: [{ emulator: '127.0.0.1:16416', name: 'Kiravik' }, { emulator: '127.0.0.1:16448', name: 'Rob' }, ...(winTok === A ? [{ emulator: winEmu, name: 'Race' }] : [])], device: dev('hwB1', 'PC-HOME') }, A);
check('heartbeat ok, nothing to stop', r.ok && r.stop.length === 0, r.stop);
r = await call('/v1/heartbeat', { instances: [{ emulator: '127.0.0.1:16416', name: 'Kiravik' }], device: dev('hwB1', 'PC-HOME') }, A);
check('instance not listed any more is freed', r.ok && r.account.devices.find((d) => d.this_device).running.length === 1, r.account.devices);
// Crash: app restarts and signs in again on the same PC -> same device, leases kept.
r = await call('/v1/signin', { email: 'boss@example.com', password: 'secret123', device: dev('hwB1', 'PC-HOME') });
check('sign in again on same PC keeps device id', r.device_id === devA, r.device_id);
const A2 = r.token;
r = await call('/v1/heartbeat', { instances: [{ emulator: '127.0.0.1:16416', name: 'Kiravik' }] }, A);
check('old token dead after re-sign-in', r.status === 401);
r = await call('/v1/heartbeat', { instances: [{ emulator: '127.0.0.1:16416', name: 'Kiravik' }], device: dev('hwB1', 'PC-HOME') }, A2);
check('reclaimed after restart', r.ok && r.stop.length === 0, r);

console.log('\n# Dead PC: lease ends after 20 min; PC rejoins over the limit');
await DB.prepare('UPDATE leases SET last_seen = ? WHERE device_id = ?').bind(Date.now() - 25 * MIN, devB).run();
await call('/v1/start', { emulator: '127.0.0.1:16448', name: 'Rob' }, A2);
r = await call('/v1/start', { emulator: '127.0.0.1:16500', name: 'Rory' }, A2);
check('PC-OFFICE silent 25 min -> its instances freed for PC-HOME', r.ok && r.account.instances.in_use === 3, r);
r = await call('/v1/heartbeat', { instances: [{ emulator: winTok === B ? winEmu : '127.0.0.1:99999', name: 'Farm' }], device: dev('hwB2', 'PC-OFFICE') }, B);
check('PC-OFFICE comes back: told to stop (limit)', r.ok && r.stop.length === 1 && r.stop[0].reason === 'limit', r.stop);
let acc = await DB.prepare('SELECT flagged FROM accounts WHERE id = ?').bind(bossId).first();
check('account flagged for manual look', /over the limit/.test(acc.flagged), acc);

console.log('\n# Free seats of another PC from the account card');
r = await call('/v1/devices/signout', { free_device_id: devA }, B);
check('Free on PC-HOME row ends its instances', r.ok && r.account.instances.in_use === 0, r.account?.instances);

console.log('\n# Plan lowered while running (newest stop)');
await DB.prepare('UPDATE accounts SET instance_limit = 5 WHERE id = ?').bind(bossId).run();
for (const [e, n] of [['e1', 'One'], ['e2', 'Two'], ['e3', 'Three']]) { await call('/v1/start', { emulator: e, name: n }, A2); await new Promise((res) => setTimeout(res, 5)); }
for (const [e, n] of [['f1', 'Four'], ['f2', 'Five']]) { await call('/v1/start', { emulator: e, name: n }, B); await new Promise((res) => setTimeout(res, 5)); }
r = await admin('update', { id: bossId, instance_limit: 3 });
check('admin lowers limit to 3', r.ok, r);
r = await call('/v1/heartbeat', { instances: [{ emulator: 'f1', name: 'Four' }, { emulator: 'f2', name: 'Five' }], device: dev('hwB2', 'PC-OFFICE') }, B);
check('the 2 newest (Four, Five) told to stop', r.stop.length === 2 && r.stop.every((s) => s.reason === 'plan_lowered'), r.stop);
r = await call('/v1/heartbeat', { instances: [{ emulator: 'e1', name: 'One' }, { emulator: 'e2', name: 'Two' }, { emulator: 'e3', name: 'Three' }], device: dev('hwB1', 'PC-HOME') }, A2);
check('the 3 oldest keep running', r.stop.length === 0 && r.account.instances.in_use === 3, r);

console.log('\n# Expiry, grace, renewal');
await DB.prepare('UPDATE accounts SET plan = ?, expires_at = ? WHERE id = ?').bind('paid', Date.now() + 2 * DAY, bossId).run();
r = await call('/v1/heartbeat', { instances: [{ emulator: 'e1', name: 'One' }], device: dev('hwB1', 'PC-HOME') }, A2);
check('warning 2 days before', r.account.warn && /2 days/.test(r.message), r.message);
await DB.prepare('UPDATE accounts SET expires_at = ? WHERE id = ?').bind(Date.now() - 2 * HOUR, bossId).run();
r = await call('/v1/heartbeat', { instances: [{ emulator: 'e1', name: 'One' }], device: dev('hwB1', 'PC-HOME') }, A2);
check('paid: in 24 h grace, keeps running', r.account.status === 'grace' && r.stop.length === 0, r);
await DB.prepare('UPDATE accounts SET expires_at = ? WHERE id = ?').bind(Date.now() - 25 * HOUR, bossId).run();
r = await call('/v1/heartbeat', { instances: [{ emulator: 'e1', name: 'One' }], device: dev('hwB1', 'PC-HOME') }, A2);
check('after grace: stop everything', r.account.status === 'expired' && r.stop[0]?.reason === 'expired', r);
check('expired licence says expired', verifyLicence(r.licence).payload.status === 'expired');
r = await call('/v1/start', { emulator: 'e1', name: 'One' }, A2);
check('start refused when expired', r.status === 403 && r.error === 'expired');
r = await admin('add_days', { id: bossId, days: 30, instances: 4, amount: 10, currency: 'USD', method: 'PayPal' });
check('admin Add 30 days from today (expired)', r.ok && Math.abs(r.expires_at - Date.now() - 30 * DAY) < MIN, r);
r = await admin('add_days', { id: bossId, days: 30 });
check('second Add 30 days stacks on expiry (no lost days)', Math.abs(r.expires_at - Date.now() - 60 * DAY) < MIN, r);
r = await call('/v1/start', { emulator: 'e1', name: 'One' }, A2);
check('renewed: start works again (Check now)', r.ok && r.account.instances.limit === 4 && r.account.status === 'active', r);
const trialAcc = await accId('second@example.com');
await DB.prepare('UPDATE accounts SET expires_at = ? WHERE id = ?').bind(Date.now() - HOUR, trialAcc).run();
const t2 = (await call('/v1/signin', { email: 'second@example.com', password: 'secret123', device: dev('hwA', 'PC-HOME') }));
check('trial: no grace after expiry', t2.account.status === 'expired', t2.account);

console.log('\n# Cloned Windows image');
r = await call('/v1/heartbeat', { instances: [{ emulator: 'e1', name: 'One' }], device: dev('hwCLONE', 'PC-HOME') }, A2);
check('different hardware with same token -> new device + rekey', r.ok && r.rekey && r.rekey.device_id !== devA, r.rekey);
acc = await DB.prepare('SELECT flagged FROM accounts WHERE id = ?').bind(bossId).first();
check('clone flagged', /cloned/.test(acc.flagged));

console.log('\n# PC limit (5)');
const lim = [];
for (let i = 0; i < 6; i++) lim.push(await call('/v1/signin', { email: 'friend@example.com', password: 'secret123', device: dev('hwL' + i, 'L' + i) }));
check('6th PC refused with device list', lim[3].ok && lim[4].status === 409 && lim[4].error === 'device_limit' && lim[4].devices.length === 5, lim.map((x) => x.status));
r = await call('/v1/signin', { email: 'friend@example.com', password: 'secret123', device: dev('hwL5', 'L5'), replace_device_id: lim[4].devices[0].id });
check('sign one out in the same screen -> works', r.ok, r);

console.log('\n# Password reset via admin code (Discord)');
r = await call('/v1/reset/request', { email: 'boss@example.com' });
check('reset request says Discord', r.ok && r.method === 'discord');
const fid = await accId('friend@example.com');
const fdevs = (await DB.prepare('SELECT COUNT(*) n FROM devices WHERE account_id = ?').bind(fid).first()).n;
r = await admin('reset_code', { id: fid });
check('admin makes code XXXX-XXXX', /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(r.code), r);
const code = r.code;
let bad = await call('/v1/reset/confirm', { email: 'friend@example.com', code: 'AAAA-AAAA', new_password: 'newpass123' });
check('wrong code refused', bad.status === 400 && bad.error === 'bad_code');
r = await call('/v1/reset/confirm', { email: 'friend@example.com', code: code.toLowerCase().replace('-', ' '), new_password: 'newpass123', device: dev('hwNEW', 'Laptop') });
check('code works (any case/spacing), signs in this PC', r.ok && r.token, r);
check('all other PCs signed out', r.account.devices.length === 1, r.account.devices.length + ' of ' + fdevs);
bad = await call('/v1/reset/confirm', { email: 'friend@example.com', code, new_password: 'another123' });
check('code works once only', bad.status === 400);
r = await call('/v1/signin', { email: 'friend@example.com', password: 'newpass123', device: dev('hwNEW', 'Laptop') });
check('new password signs in', r.ok);

console.log('\n# Password change signs out other PCs');
const fr = await call('/v1/signin', { email: 'friend@example.com', password: 'newpass123', device: dev('hwOTHER', 'Other') });
r = await call('/v1/password/change', { old_password: 'newpass123', new_password: 'changed123' }, r.token);
check('password changed', r.ok && r.account.devices.length === 1, r);
r = await call('/v1/heartbeat', { instances: [] }, fr.token);
check('other PC now signed out (401)', r.status === 401 && r.error === 'signed_out');

console.log('\n# Rate limit');
let last;
for (let i = 0; i < 11; i++) last = await call('/v1/signin', { email: 'boss@example.com', password: 'nope', device: dev('hwB1', 'PC-HOME') });
check('11th wrong sign-in for one email is rate limited', last.status === 429, last.status);

console.log('\n# Admin page');
r = await admin('overview');
check('overview', r.ok && r.totals.accounts >= 3 && Array.isArray(r.expiring), r);
check('flagged list has boss', r.flagged.some((a) => a.email === 'boss@example.com'));
r = await admin('account?email=boss%40example.com');
check('find by email: card, payments, log', r.found && r.payments.length === 2 && r.events.length > 5 && !('password_hash' in r.account), Object.keys(r));
r = await admin('create', { email: 'keyuser@example.com', instances: 10, days: 12, plan: 'paid', notes: 'migrated test5' });
check('create account for key user + reset code', r.ok && r.reset.code, r);
r = await call('/v1/reset/confirm', { email: 'keyuser@example.com', code: r.reset.code, new_password: 'mypass1234', device: dev('hwK', 'KeyPC') });
check('key user sets password and is in, 10 instances 12 days', r.ok && r.account.instances.limit === 10 && r.account.plan === 'paid' && r.account.days_left === 12, r.account);
r = await admin('export');
check('export has no password hashes', r.ok && !JSON.stringify(r).includes('pbkdf2'));
r = await admin('update', { id: bossId, flagged: '' }, { noHeader: true });
check('POST without admin header refused', r.status === 403);
r = await admin('overview', null, { host: 'http://admin.rallyforge.workers.dev' });
check('no Access token -> 403 (non-local host)', r.status === 403, r);
r = await admin('allow_trial_again', { id: fid });
check('allow trial again', r.ok);

console.log(`\n${passed} passed, ${failed} failed`);
await mf.dispose();
process.exit(failed ? 1 : 0);
