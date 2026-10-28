// Small crypto helpers on WebCrypto (works in Workers and Node 20+).

const enc = new TextEncoder();

export function b64url(bytes) {
  let s = '';
  const a = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomToken(nBytes = 32) {
  return b64url(crypto.getRandomValues(new Uint8Array(nBytes)));
}

export function randomId() {
  return crypto.randomUUID();
}

// Human-friendly reset code: 8 chars, no look-alike letters, shown as XXXX-XXXX.
export function randomCode() {
  const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const b = crypto.getRandomValues(new Uint8Array(8));
  let s = '';
  for (let i = 0; i < 8; i++) s += abc[b[i] % abc.length];
  return s.slice(0, 4) + '-' + s.slice(4);
}

export function normCode(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export async function sha256(str) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return b64url(d);
}

// Passwords: PBKDF2-SHA256, 100k rounds (Workers' maximum), 16-byte salt.
const PBKDF2_ROUNDS = 100000;

async function pbkdf2(password, salt, rounds) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: rounds }, key, 256);
  return new Uint8Array(bits);
}

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const h = await pbkdf2(password, salt, PBKDF2_ROUNDS);
  return `pbkdf2$${PBKDF2_ROUNDS}$${b64url(salt)}$${b64url(h)}`;
}

export async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const h = await pbkdf2(password, b64urlDecode(parts[2]), parseInt(parts[1], 10));
  const want = b64urlDecode(parts[3]);
  if (h.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < h.length; i++) diff |= h[i] ^ want[i];
  return diff === 0;
}

// Licence signing: Ed25519. Private key = base64 PKCS#8 (Worker secret LICENCE_PRIVATE_KEY).
let cachedKey = null;
let cachedKeyB64 = null;

async function signingKey(pkcs8b64) {
  if (cachedKey && cachedKeyB64 === pkcs8b64) return cachedKey;
  const raw = Uint8Array.from(atob(pkcs8b64.trim()), (c) => c.charCodeAt(0));
  cachedKey = await crypto.subtle.importKey('pkcs8', raw, { name: 'Ed25519' }, false, ['sign']);
  cachedKeyB64 = pkcs8b64;
  return cachedKey;
}

// Licence string = base64url(JSON payload) + "." + base64url(Ed25519 signature over the first part).
export async function signLicence(payload, pkcs8b64) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const key = await signingKey(pkcs8b64);
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, key, enc.encode(body));
  return body + '.' + b64url(sig);
}
