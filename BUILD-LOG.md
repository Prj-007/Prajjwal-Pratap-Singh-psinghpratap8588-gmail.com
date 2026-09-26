# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

## Phase 0 — orientation

### 2026-09-26 · where the hand-out came from

The public `rhinostream/Hackathons` repo contains more than the hand-out: `q1-starter/` (its root
README calls it "the reference implementation, not a starter"), `DISCOVERY-RUBRIC.md` and
`HARDENING.md` (marked organiser-only). The root README was read before it was clear it was
organiser-facing. Those three were not opened. This repo was created empty and seeded from
`starter/` only (commit f4a6479), so none of it is in this history. To report to the organisers.

### 2026-09-26 · baseline against the untouched skeleton

Node 20.12.2 here; `.nvmrc` says 22. `npm install` fine on 20, no `engines` field.
Predicted `check-jwt.js` would be 0/43, not "rejections pass by accident": the stub throws a
plain `Error`, and the suite compares `${status} ${code}`. Observed: 0 passed, 43 failed. Right.
`check-permissions.js` does not report failures at all — it crashes on the first stub call.

### 2026-09-26 · db:reset broken on Windows

`npm run db:reset` → `ENOENT ... open 'C:\C:\Users\...\db\schema.sql'`. The doubled drive is
`new URL(p, import.meta.url).pathname` returning `/C:/...`, which `fs` resolves against the
current drive. `fileURLToPath` in `scripts/load-db.js` fixes it (9d6e4f0). Same pattern at
`server/index.js:22` (the `dist/` path for `npm start`) — left alone for now, see Open threads.
Reset now seeds 3 orgs and **20** permissions, not the documented 19: the overlay adds role
`reviewer` and permission `device:reboot` (allow on one device, deny on another).

### 2026-09-26 · the spec asks more of `verifyAccessToken` than its signature allows

`AUTH-DATA-MODEL.md §10` lists "a token whose `pv` is stale, as `401 TOKEN_STALE`" among the
things `verifyAccessToken` must refuse. But it is `verifyAccessToken(token, secret)` — no DB, no
membership, so it cannot know the current `perm_version`. `auth.js` already exports
`assertFresh(claims, membership)` for exactly this. Settled: the verifier does signature and claim
checks only; the `pv` check runs where the membership row is loaded (`context.js`).

## Phase 1 — token verification

### 2026-09-26 · predictions before writing it

1. `timingSafeEqual` throws on unequal lengths → a truncated signature would be a crash, not a 401.
2. A header of JSON `null` parses fine, then `header.alg` throws `TypeError`.
3. Node's base64url decoder is lenient, so decode-then-compare may accept a padded signature.
Checked all three in a one-off `node -e` before writing code. All true:
`ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH`; `TypeError`; and `sig+'!!'`, `sig+'.'`, `'!'+sig` each
decode to the same 32 bytes as `sig`. (3) decided the design: compare the *encoded* signature
string against the expected base64url string, length first, then `timingSafeEqual`.

### 2026-09-26 · 43/43, and a test the public suite can't fail

`check-jwt.js`: 43 passed. Predicted "header is not an object" would not actually exercise an
object check — its `b64()` passes strings through raw, so the header is `HS256`, not `"HS256"`,
and dies in `JSON.parse`. So the public suite never feeds valid-JSON-non-object segments.
Wrote `scripts/check-jwt-edges.js` (15 cases) for that and the lenient-decoder signatures.
Mutant A — swap in decoded-bytes comparison: edges 12/15 (all three padded signatures
**accepted**), public suite still **43/43**. The public suite cannot tell the two designs apart.

### 2026-09-26 · wrong about the object check — reversed

Had `isPlainObject` in `decodeSegment`, commented "each of those… breaks the first property read
with a TypeError". Mutant B — delete it: still 15/15 and 43/43. Wrong: only `null` throws on a
property read, and `!header` / `!claims` already reject `null`; arrays, strings and numbers have no
`.alg`/`.exp` and fall out as clean 401s. Removed the helper, rewrote the comment to say what
actually holds (fb34f13). The claim in the old comment was the kind a reviewer would ask me to
demonstrate, and it would not have survived.

### 2026-09-26 · left open by the documents

- `aud` as an array: RFC 7519 allows it; nothing here says to. Rejected — we only ever issue a
  string, so an array `aud` was not minted by us. Covered in `check-jwt-edges.js`.
- `iat`/`nbf` in the future: not listed in the TODO or §10, not checked. Only we can sign, so a
  future `iat` means a clock problem on our side, not a forgery.
- `sub`/`org` presence is not checked here; `context.js` needs them and should refuse there.

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

### 2026-09-26 · the engine (permissions.js), before context.js

Model going in: membership → suspended → any applicable deny → role or allow grant → implicit.
Deny is checked before the role, so an org-wide deny beats the baseline and a device allow.
Predicted `check-permissions.js` 35/35 and `npm run personalisation` 18/18. Both passed first run
(043db38) — so this phase has no wrong prediction yet, and the public suites were not where the
risk was.

### 2026-09-26 · the laundering hole the public suites cannot see

`resolve(deviceId = null)` is the org-level *union* (allowed if the org scope or any one device
allows). Reusing it for `assertMayGrant(…, deviceId = null)` would let a viewer with `device:control`
on one device grant `device:control` org-wide. Made the org-wide grant check use the org scope
only. Wrote `scripts/check-permissions-edges.js` (13 cases). Mutant — union in `assertMayGrant`:
edges 12/13 (`...may NOT grant it org-wide` → `ok`), `check-permissions` still 35/35,
personalisation still 18/18.

### 2026-09-26 · measured: queries per resolve

Wrapped `db.prepare` and counted. `resolveDevices` with 1, 3, 5 Acme devices: 4, 4, 4 queries
(catalogue, membership, baseline, grants). `resolve` org-level: 4. One device: 5 — the extra is
the "is this a live device of this org" check. Nothing scales with the number of rows.

### 2026-09-26 · left open by the documents — settled here

- **Provenance of an allow.** Tests only pin the grant form (`grant:<id>`). Chose `source: role:<key>,
  reason: role` and `source: grant:<id>, reason: grant`. When both allow, the role is reported.
- **Which deny is named** when several apply: the oldest (`ORDER BY created_at, id`), so the answer
  is stable between requests.
- **Org-level union with no devices.** The org scope itself counts as one candidate, so a role
  baseline still shows `device:list` in an org with zero devices.
- **Device not in this org, or soft-deleted:** everything denied with `scope_mismatch` (a reason
  listed in `PERMISSIONS.md §5` but not defined there). Grants on it stop counting in the union.
- **Grants reaching across orgs.** Schema allows `grants.org_id = A` with a device of org B. The
  grants query only counts a device-scoped grant whose device is live in the grant's own org.
- **Invited / removed membership** resolve as `not_a_member`; a soft-deleted org likewise.
- **Deny grants also need the permission held.** "Only grant authority you hold" applied to both
  effects — the conservative reading.
- `resolveDevices` trusts the caller's `deviceIds` (they come from the org's own device query) and
  does not re-check each one — keeps it at 4 queries. The list route must not pass foreign ids.

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._

- `server/index.js:22` — `DIST` uses `new URL(...).pathname`, the same bug fixed in `load-db.js`.
  Only hit by `npm start` (production static serving) on Windows. Not fixed yet.
- `package.json` scripts assume a POSIX shell: `db:reset` uses `rm -f`, `start` uses
  `NODE_ENV=production node ...`. `rm` worked here only because Git's `rm` is on PATH.
