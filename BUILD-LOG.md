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

### 2026-09-26 · context.js — token to caller

Order: bearer → `verifyAccessToken` → `sub`/`org` present → path `:org` must equal the token's
`org` (404, before any query) → membership active in a live org (401) → `assertFresh` → suspension.
No route exists yet, so `check-api.js` cannot reach it; wrote `scripts/check-context.js` (24 cases)
calling `authenticate()` with fake requests. 24/24.
Predicted: a token issued *before* a suspension comes back `401 TOKEN_STALE`, not `403 suspended`,
because suspending bumps `perm_version` and freshness runs first. Observed exactly that; only a
token minted after the suspension reaches the 403. So the client sees stale → refresh → 403.
Mutant — delete the path-org check: 22/24, and the failure reads `got ok u1@oa owner` for a
request to org B's URL. Without it a route reading `params.org` would serve B's rows under A's
authority. With it, "org B, where you are a member" and "an org that doesn't exist" are the same 404.

### 2026-09-26 · left open — what a suspended member can still reach

`AUTH-DATA-MODEL.md §10`: suspended → "`403` with an empty permission set". §7: "the token still
verifies". Neither says whether *every* route refuses. Refusing all of them means a user suspended
in org A cannot call `POST /v1/auth/token` to switch to org B, where they are fine. Settled: 403
`suspended` by default, open on `GET /v1/auth/me` (shows the empty set), `GET /v1/orgs`,
`POST /v1/auth/token`. Removed / invited / deleted org → 401, as §10 says for `removed`.

### 2026-09-26 · problems hit so far that are not above

- **A shell edit ate backslashes.** Adding the comment in `scripts/load-db.js` through `sed`, the
  string `'C:\\C:\\...'` came out as `'C:C:...'` — two layers of escaping (bash, then sed). Caught
  by reading the file back before committing; fixed with a plain edit. Rule since: no `sed` for
  anything containing backslashes.
- **Rewording an old commit broke this log.** Reworded one commit message with
  `git filter-branch --msg-filter` (unpushed, dates preserved — checked author and committer
  dates before/after). Every later commit got a new hash, and three hashes quoted in this file
  pointed at nothing. Fixed in 69a2627. Lesson: quoting hashes in a log ties it to history that
  must not be rewritten after that point.
- **"LF will be replaced by CRLF" on every commit.** `core.autocrlf=true` on this machine.
  `git ls-files --eol` shows `i/lf` for committed files, so the repository stores LF and the
  graders' checkout is unaffected. Noise, not a bug; left alone.
- **Three modules in, no public suite reaches them end to end.** `check-api.js` and the UI suite
  need routes, so `context.js` and the permission scope rules are covered only by the scripts
  written here (`check-context.js`, `check-permissions-edges.js`). Real HTTP behaviour (headers,
  body parsing, error shape on the wire) is still unverified.

## Phase 2c — audit.js and lifecycle.js (before any route)

### 2026-09-27 · the expired session that would hold a device forever

Reading `one_exclusive_session_per_device` (`WHERE state = 'active' AND mode IN ('control','terminal')`):
nothing flips `state` when `expires_at` passes. Predicted: an expired-but-`active` control row
blocks the next control session on that device indefinitely. Tested before writing the fix — the
insert fails with `UNIQUE constraint failed: sessions.device_id`. Added `expireStaleSessions()`
(marks them `session_expired`, `ended_at = expires_at`); after it the same insert succeeds. The
session route has to call it before inserting, or the TTL that makes grandfathering safe (§7)
never actually releases anything.

### 2026-09-27 · no role key in the code

`assertNotLastOwner` needs to know which role is "owner". Wrote it as the highest-ranked row in
`roles` rather than the string `'owner'`. `check-lifecycle.js` adds an undocumented `steward`
(rank 35) and the rank rules pick it up: operator (30) cannot modify it, admin (40) can assign it.
Noticed while writing the cases: operator → auditor passes the rank check (30 > 20). That is
right — rank is only the *second* gate; the route still needs `user:role:update`, which operator
does not hold. Rank never answers "may you", only "may you, over them".

### 2026-09-27 · left open — settled here

- **Admin assigning admin.** §6 forbids modifying an equal and assigning `owner` unless owner;
  silent on creating an equal. Refused: two admins could never act on each other afterwards.
  The top role may assign itself, or no org could ever gain a second owner.
- **Last owner counts active owners only.** A suspended owner cannot act for the org, so an org
  whose only *active* owner leaves is ownerless in practice.
- **What `auditDenials` records.** Only 403. A 404 is "invisible" — logging it writes a row about a
  resource the caller cannot see; a 400 is a malformed request, not a refusal.
- **`endActiveSessions` with no user and no device** throws instead of ending every session in the
  org. A missing argument should fail loudly, not widen the blast radius.
- **Snapshot shape** follows the seed's `authorizedBy` (`role`, `grantIds`, `snapshotAt`) plus
  `permissions`. `grantIds` comes from the `source` of the engine's own answers — not a second
  copy of the "which grants are active" query.

32/32 first run. No wrong prediction this round; the risk is in how the routes use these.

### 2026-09-27 · wrong: "the documents leave allow provenance open"

Phase 2 above says tests only pin the grant form, so `reason: role` / `reason: grant` was my
choice. Reading `BRIEF.md §5.2` for the auth routes: its example is
`{ "effect": "allow", "source": "role:operator", "reason": null }`. It was specified; I had read
`PERMISSIONS.md` and the tests, not the brief's response shapes. `reason` is for denies only.
Changed both allow branches in `decide` to `reason: null` and the one edge case that asserted
`'grant'`. All suites unchanged in count. Nothing public caught it — `check-api.js` never reads an
allow's reason — so it would have surfaced only in the hidden tier or the console's copy.
Lesson: before claiming "the documents are silent", grep every document for the field name.

## Phase 2d — auth routes

### 2026-09-27 · first contact with check-api.js

Predicted: login and switch-org pass; `no token -> 401` on `/orgs/org_acme/devices` fails, because
the router answers 404 for an unregistered path before `authenticate()` ever runs. Observed
exactly that, then the script aborted reading `members.map`. Caveat on the passes: the three
"cross-org is INVISIBLE" checks are green only because the devices route does not exist — the
404 comes from the router, not from `context.js`. They prove nothing until that route lands.

### 2026-09-27 · measured: the enumeration oracle a missing compare would open

Login returns the same 401 and message for a wrong password and an unknown email. Timed the two
paths (20 runs each): wrong password 98.1 ms, unknown email with the dummy scrypt compare
98.3 ms, unknown email with *no* compare 0.006 ms. Identical messages would not have helped: a
four-orders-of-magnitude gap tells anyone which emails exist.

### 2026-09-27 · refresh — what I had to decide

- **A refresh token has no org.** `refresh_tokens` is `(user_id, family_id, …)`, no `org_id`, and
  the test `a reload restores the session from the refresh cookie` expects Dana back in Acme.
  Refresh takes an optional `orgId`, else the default org: earliest-joined *active* membership
  (Acme for both Dana and Sam in the seed).
- **Reuse.** A rotated token presented again revokes every live token in its family and clears the
  cookie. `check-auth.js` proves the newest token of a family dies after an old one is replayed.
- **Concurrent refresh.** Rotation is `UPDATE … WHERE id = ? AND revoked_at IS NULL` inside a
  transaction; only the request that changes one row gets a new token.
- **Cookie** `rt`, `HttpOnly; Secure; SameSite=Strict; Path=/v1/auth`. `Secure` over plain
  `http://localhost` works because browsers treat localhost as a secure context — not verified in
  a browser yet (no console exists); the UI suite will be the check.
- **Suspended everywhere.** Login still issues a token for a suspended membership, so `/auth/me`
  can show the empty set; a user with no active or suspended membership at all gets 401.

`scripts/check-auth.js`: 24/24.

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

### 2026-09-27 · orgs and members routes — owner vs owner

Read ahead in `check-api.js` before writing: `demoting a NON-last owner is allowed` has Dana
(owner) demote another owner and expects 200. `assertCanModify` from Phase 2c refuses equal
ranks. Predicted that check would fail. `check-api.js` aborts before reaching it (no sessions
route yet), so wrote `scripts/check-orgs.js`; it failed exactly there:
`got "403 FORBIDDEN insufficient_rank" want 200`. Phase 2c's "strictly above" was right for admin →
admin and wrong for owner → owner — with it, a second owner could never be demoted by anyone.
Changed: equal rank refused except for the top role (same exception `assertCanAssign` already
had). The rule I wrote down in Phase 2c came from §6's table, which only shows admin → admin.

### 2026-09-27 · three wrong expectations in my own test

`check-orgs.js` first run: 33/38. One real bug (above) plus its pv follow-on; the other three
were the test being wrong, each for a reason worth keeping:
- `admin cannot modify admin` returned `SELF_ROLE_CHANGE` — the seed has one admin, so the test
  had him edit himself. Added a second admin (owner promotes the viewer) and asserted both.
- `a fresh token is refused as suspended` returned 404 — after Sam is suspended in Acme, a plain
  login's default org skips the suspended membership and lands in Globex, so the "fresh" token
  was for the wrong org. Correct behaviour; the test now logs in with `orgId: 'org_acme'` and
  separately asserts the Globex landing.
- `removed user's token` returned `401 UNAUTHENTICATED`, not `TOKEN_STALE` — `context.js` checks
  membership status before freshness, so removal wins. That is the order Phase 2b chose.
41/41 after. `check-api.js` unchanged at 16 passes; every remaining failure is a 404 from the
audit or sessions routes.

### 2026-09-27 · left open — settled here

- **Org-level actions use the strict org scope** (`assertCanOrgWide`, new in `permissions.js`),
  never the union: a device-scoped grant must not authorise managing people or the org.
  Known gap: `/auth/me` shows the union, so a device-scoped grant of a *non-device* permission
  (e.g. `audit:read` on one device) would light up nav that the API then refuses. Left open.
- **Suspend / remove yourself** → 403 reason `self`; leaving is `DELETE /members/me`.
- **Suspend and reinstate are idempotent** — suspending a suspended member is 200, not 409.
- **Org delete** is a soft delete and ends every live session in the org (`allInOrg: true`,
  reason `admin_terminated` — there is no org-deleted end reason in the schema).

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

### 2026-09-27 · devices routes

Predicted `check-api.js`: `no token -> 401` flips to pass (the route now exists, so
`authenticate()` runs instead of the router's 404), the three D6 checks and both row-inclusion
checks pass. All five did. The cross-org 404s are now produced by `context.js`, so they mean
something for the first time.

Decisions no document settles:
- **A device you cannot view is 404 on its detail, update, delete and transfer** — the same
  answer the list gives by leaving it out. A 403 would confirm it exists.
- **Creating a device needs `device:provision` org-wide**, not "on some device" — same laundering
  argument as `assertMayGrant`.
- **Kinds are not listed in the route.** Insert and translate `SQLITE_CONSTRAINT_CHECK` to 400; the
  schema's `CHECK (kind IN …)` stays the only list. `check-orgs.js` `bad kind -> 400`.
- **Names unique among an org's live devices** (409). No index in the schema, so the check runs
  in the same transaction as the insert; one process, one transaction at a time.
- **Transfer revokes the old org's grants on the device** and bumps each holder's `pv`; otherwise a
  grant would keep naming a device that is no longer in its org. Live sessions end
  `device_transferred`. Needs provision on the device here and org-wide in the target.

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
