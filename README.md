# rallyforge-licensing

Accounts + licensing server for RallyForge (beta). Two Cloudflare Workers sharing one D1 database:

| Worker | Address | What |
|---|---|---|
| `license` | https://license.rallyforge.workers.dev | Public API the app talks to - see [docs/API.md](docs/API.md) |
| `admin` | https://admin.rallyforge.workers.dev | Owner-only page (Cloudflare Access + token check in code) |

Design: project docs `claude/licensing_design_28oct.md` v2 and `claude/final_prelaunch_review_28oct.md` A-C.
Settings (trial days, trial instance cap, grace hours, lease timeout...) are the `[vars]` in `wrangler.toml` - change and redeploy, no code change.

## Test locally
```
npm install
npm test
```

## First deploy (owner, on the PC, PowerShell) - Claude never handles Cloudflare logins or keys
1. Node.js LTS installed (`node -v`). Then:
   ```
   cd C:\Users\vicky\Documents
   git clone https://github.com/28vicky/rallyforge-licensing
   cd rallyforge-licensing
   npm install
   npx wrangler login
   ```
2. Database: `npx wrangler d1 create rallyforge-licensing` -> copy the `database_id` it prints into **both** `wrangler.toml` and `wrangler.admin.toml` (or send it to Claude to commit). Then `npm run db:migrate`.
3. Signing key: `node scripts/genkeys.mjs` -> makes `licence_private_key.txt` (SECRET) and `licence_public_key.txt` (goes into the app).
   `npx wrangler secret put LICENCE_PRIVATE_KEY` -> paste the text of `licence_private_key.txt`.
   Back up `licence_private_key.txt` somewhere safe and private (password manager). Never commit or share it. If it is lost, every app needs a new public key.
4. API: `npm run deploy:api`. Check: open https://license.rallyforge.workers.dev/v1/time - it shows the server time.
5. Admin page:
   - Cloudflare dashboard -> Zero Trust -> pick a team name with no personal name in it (e.g. `rallyforge` -> `rallyforge.cloudflareaccess.com`), Free plan.
   - `npm run deploy:admin`
   - Workers & Pages -> `admin` -> Settings -> Domains & Routes -> workers.dev -> enable **Cloudflare Access**.
   - Zero Trust -> Access -> Applications -> that app -> policy: Allow, your email only. Copy its **Application Audience (AUD) tag**.
   - Put the AUD tag, the team domain and your email into `wrangler.admin.toml` (`ACCESS_AUD`, `ACCESS_TEAM_DOMAIN`, `ADMIN_EMAILS`), then `npm run deploy:admin` again.
   - Open https://admin.rallyforge.workers.dev - Cloudflare asks for your email code, then the admin page opens.

## Later updates
`git pull` then `npm run deploy:api` / `npm run deploy:admin`. New tables come as new files in `migrations/` -> `npm run db:migrate` first.

## Daily
Admin page -> "Download backup" (accounts, payments, PCs; no passwords).
