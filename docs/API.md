# RallyForge licensing API - contract for the app (WS LA)

Base URL: `https://license.rallyforge.workers.dev`
All calls are `POST` with a JSON body (except `GET /v1/time`). Signed-in calls send `Authorization: Bearer <token>`.

Every error is `{ "ok": false, "error": "<code>", "message": "<text to show the user as is>" }` with an HTTP status.
Show `message` to the user; branch on `error`.

## Words
- Customers only ever see **instance** ("Instances running 7 of 20"). "Seat"/"lease" are server words.
- **Instance id** = this PC (device) + emulator ADB address. The same address on two PCs is fine.
- Switched ON = uses an instance: running, **paused**, kicked (phone countdown), game/emulator restarting, mapping. Only **Stop** frees it.

## Device info (sent at sign-up / sign-in / reset, and in every heartbeat)
```json
"device": { "hw_id": "<sha256 hex of a hardware fingerprint>", "name": "PC-HOME", "app_version": "2.6.0" }
```
`hw_id`: hash of something that differs between physical PCs and survives app reinstall (e.g. MachineGuid + system disk serial + first MAC). It drives: same-PC re-sign-in keeps the device (and its running instances), one trial per PC, and cloned-Windows detection.
`name`: Windows computer name by default.

## Session reply (returned by sign-up, sign-in, reset/confirm with device, heartbeat, start, stop, devices/signout, password/change)
```json
{
  "ok": true,
  "server_time": 1793206242073,          // ms - use this, never the PC clock
  "licence": "<base64url payload>.<base64url Ed25519 signature>",
  "message": "Plan ends in 2 days.",     // "" when nothing to say; show as banner when not empty
  "account": {
    "email": "a@b.com", "plan": "trial|paid", "status": "active|grace|expired",
    "expires_at": 0, "grace_until": 0, "warn": false, "days_left": 12,
    "instances": { "in_use": 7, "limit": 20, "free": 13 },
    "device_limit": 5,
    "devices": [ { "id": "...", "name": "PC-HOME", "this_device": true, "app_version": "2.6.0",
                   "last_seen": 0, "running": [ { "emulator": "127.0.0.1:16416", "name": "Kiravik" } ] } ]
  },
  "next_checkin_sec": 300,
  "token": "...", "device_id": "..."     // only from sign-up / sign-in / reset: store token in Windows protected storage (DPAPI)
}
```

## Endpoints
| Call | Body | Notes |
|---|---|---|
| `POST /v1/signup` | `email, password (8+), instances (≥1), device` | Friends beta: user picks the instance count; trial = 30 days, count capped at 30 (server settings). `trial_given:false` when this PC already had a trial (account exists, plan expired; owner adds days). 409 `email_taken`. |
| `POST /v1/signin` | `email, password, device, [replace_device_id]` | 401 `bad_login`. 409 `device_limit` + `devices:[{id,name,last_seen}]` -> show the list, user picks one, call again with `replace_device_id`. Same PC (same hw_id) signing in again keeps its device id and running instances. |
| `POST /v1/reset/request` | `email` | Beta: returns `method:"discord"` + message. Reset codes come from the owner via Discord. |
| `POST /v1/reset/confirm` | `email, code, new_password, [device]` | Code `XXXX-XXXX`, any case/spacing, one use, 60 min. Signs out every PC (their bots must stop). With `device` it signs this PC in (returns token). 400 `bad_code`. |
| `POST /v1/password/change` | `old_password, new_password` (auth) | Other PCs signed out. |
| `POST /v1/heartbeat` | `instances:[{emulator,name}], device` (auth) | Every `next_checkin_sec` (5 min) and on "Check now". List EVERY instance that is switched ON on this PC (incl. paused/kicked/restarting). Server renews them, frees ones not listed, re-grants after a crash/restart. Reply has `stop:[{emulator,name,reason,message}]` - stop those NOW (reason `expired`, `plan_lowered`, `limit`). Reply may have `rekey:{token,device_id}` (cloned Windows) -> replace the stored token. |
| `POST /v1/start` | `emulator, name` (auth) | Call BEFORE starting an instance. `granted:true` -> start. 409 `limit` (message names where they run: "All 20 instances are in use (12 on PC-A, 8 on PC-B). Stop one to start this.") + `account`. 403 `expired`. Calling it for an instance already ON is a harmless renew. |
| `POST /v1/stop` | `emulator` or `all:true` (auth) | Only on the user's **Stop**. Don't call it on Pause, kick, restart, app update or app close - those keep the instance (the 20-min timeout / same-PC reclaim covers crashes). |
| `POST /v1/devices/signout` | one of `others:true` · `device_id` · `free_device_id` (auth) | Account card: "Sign out other devices", sign out one PC, or **Free** (end that PC's instances, keep it signed in). |
| `POST /v1/signout` | (auth) | This PC. |
| `GET /v1/time` | - | `{server_time}` for clock offset before sign-in. |

401 `signed_out` on any signed-in call = token revoked (password changed / signed out elsewhere): stop all instances, show sign-in, Telegram alert "Signed out because the password changed or this PC was signed out".

429 `rate_limited`: show message, don't retry in a loop.
5xx / network error: NOT a reason to stop anything - see offline rules.

## Licence (offline rules)
`licence` = `B.S`; `B` = base64url JSON, `S` = base64url Ed25519 signature over the ASCII string `B`.
Public key (raw 32 bytes, base64) to build into the app - also in `licence_public_key.txt` in this repo:
`nBPSFy3mon5jfW/O6E9aTtPRWyDs0swEzAX4DXve94Q=`
Python check:
```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64, json
def b64u(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
def check(lic, pub_b64):
    b, s = lic.split('.')
    Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(b64u(s), b.encode())  # raises if edited
    return json.loads(b64u(b))
```
Payload: `{v, account_id, email, device_id, plan, status, instances, expires_at, grace_until, issued_at, valid_until}`.
- Keep the last good licence on disk. Server time estimate = `server_time` at last check + time elapsed since (monotonic clock), not the Windows clock.
- Server unreachable: keep running while estimate < `valid_until` (72 h after the last check) AND estimate < `grace_until`. Starting NEW instances needs the server (show "Can't reach RallyForge - try again").
- Past `valid_until`: stop all, message "Can't reach RallyForge for 3 days - connect to continue."
- `status` `grace` (paid, ≤24 h after expiry): keep running, red banner. `expired`: stop all, "Plan expired - renew to continue", app stays open, all local data kept.
- `account.warn` true (≤3 days left): banner + one Telegram alert per day.
