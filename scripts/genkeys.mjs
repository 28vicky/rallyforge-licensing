// Makes the licence signing key pair. Run once on the owner's PC:  node scripts/genkeys.mjs
// - private key -> paste into: npx wrangler secret put LICENCE_PRIVATE_KEY   (never commit it, never share it)
// - public key  -> goes into the RallyForge app so it can check licences
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync, existsSync } from 'node:fs';
if (existsSync('licence_private_key.txt')) { console.error('licence_private_key.txt already exists - not overwriting.'); process.exit(1); }
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const priv = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const pubRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
writeFileSync('licence_private_key.txt', priv + '\n');
writeFileSync('licence_public_key.txt', pubRaw + '\n');
console.log('Wrote licence_private_key.txt (SECRET) and licence_public_key.txt (raw 32-byte Ed25519, base64).');
