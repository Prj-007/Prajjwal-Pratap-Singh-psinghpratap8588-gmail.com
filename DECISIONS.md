# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Evidence is a
commit, a test name, a measurement or a file and line; `BUILD-LOG.md` has the dated entries.

---

### The JWT signature is compared as a base64url string, not as decoded bytes

**What I chose:** compute the expected HMAC as a base64url string and compare it to the token's
third segment with `timingSafeEqual`, length checked first (`server/auth.js`, `verifyAccessToken`).
**Why:** before writing it, checked Node's decoder in a one-off `node -e`: `Buffer.from(s,
'base64url')` skips characters it does not recognise, so `sig+'!!'`, `sig+'.'` and `'!'+sig` all
decode to the same 32 bytes as `sig`. Mutant A (decoded-bytes comparison) in `check-jwt-edges.js`:
12/15 — `junk appended to a valid signature` and two siblings **accepted** — while
`check-jwt.js` still reported 43/43. Commit fb34f13.
**What I rejected:** decode then compare bytes, the common shape. It fails because the decoder is
lenient: tokens that are not the token we issued verify. Also rejected `===` on strings: it
returns at the first differing character, which leaks how much of a guess was right.
**What would change my mind:** a strict base64url decoder in the runtime that throws on
non-alphabet characters and non-canonical padding. Then bytes and strings are equivalent.

---

### An org-wide grant is checked against the org scope, not the org-level union

**What I chose:** `assertMayGrant(…, deviceId = null)` evaluates the caller at the strict `org`
scope — org-wide grants plus the role — while `resolve(deviceId = null)` (navigation) is the
union "the org scope or any one device allows" (`server/permissions.js`, `evaluate`).
**Why:** reusing the union lets a viewer holding `device:control` on one device grant
`device:control` to anyone org-wide: laundering. `check-permissions-edges.js` `...may NOT grant it
org-wide` fails under the union mutant (12/13) while `check-permissions.js` (35/35) and
`npm run personalisation` (18/18) stay green. Commit 043db38.
**What I rejected:** one "org-level" answer used for both nav and granting. It is simpler and
passes every public test, and it is a privilege-escalation path.
**What would change my mind:** a rule that org-wide grants may be issued by anyone holding the
permission on *every* device of the org. Then the check would be an intersection, still not a union.

---

### Deny is checked before the role baseline, at every scope

**What I chose:** in `decide`, any applicable deny (org-wide or on this device) wins before the
role or an allow grant is consulted.
**Why:** `check-permissions.js` `operator(sam): device:terminal on build-server-01` expects deny
although `device:terminal` is in the operator baseline; and `device-scoped ALLOW does NOT carve
out org-wide DENY`. Checking the role first returns allow for Sam. The personalised overlay's
device-scoped deny (`npm run personalisation`, `...reason is explicit_deny`) needs the same order.
**What I rejected:** "most specific wins" — a device-scoped allow overriding an org-wide deny. It
fails the carve-out case directly.
**What would change my mind:** a documented case where a narrower allow is meant to survive a
broader deny. The carve-out test says the opposite.

---

### The stale-token (`pv`) check lives in `context.js`, not in `verifyAccessToken`

**What I chose:** `verifyAccessToken(token, secret)` checks only the token; `authenticate()` loads
the membership and calls the existing `assertFresh(claims, membership)` after it.
**Why:** the verifier has no database handle, so it cannot know the current `perm_version`.
`check-context.js` `token from before a permission change` → `401 TOKEN_STALE`, and
`token from the future (pv + 1)` → `401 TOKEN_STALE` (`!==`, not `<`). Commit 0c4842a.
**What I rejected:** passing `db` into the verifier. It would make a pure crypto function do a
query, and every caller of it would need a database.
**What would change my mind:** a caller that verifies tokens where no membership is loaded and
still needs freshness — then a verifier variant taking the current `pv` as an argument.

---

### Another org in the URL is a 404, decided before any query

**What I chose:** if the route's `:org` differs from the token's `org` claim, `authenticate()`
throws `notFound()` before looking up anything (`server/context.js`, the `params.org` check).
**Why:** `check-context.js` `path org B, token A, user IS a member of B` and `path org that does not
exist` return the same 404. Mutant — delete the check: both fail with `got ok u1@oa owner`, i.e. a
request to org B's URL runs with org A's authority.
**What I rejected:** looking the org up and returning 403 when the caller is not a member. A 403
confirms the org exists; so does any difference in timing or body between the two cases.
**What would change my mind:** an endpoint meant to address several orgs with one token. None
exists; switching orgs mints a new token (`POST /v1/auth/token`).

---

### A suspended member is refused everywhere except three routes

**What I chose:** `403 FORBIDDEN` with reason `suspended` by default; `GET /v1/auth/me`,
`GET /v1/orgs` and `POST /v1/auth/token` stay open (`OPEN_WHILE_SUSPENDED` in `context.js`).
**Why:** the documents say "403 with an empty permission set" and "the token still verifies" but
not which routes. Refusing all of them strands a user suspended in org A who is fine in org B —
they could not switch. `check-context.js` covers both sides. Also observed: a token issued before
the suspension returns `TOKEN_STALE` first, because suspending bumps `perm_version`.
**What I rejected:** refusing every route (strands multi-org users) and refusing none (every route
would then have to remember to check status).
**What would change my mind:** a rule that suspension should also block switching orgs — e.g. a
suspension that is really account-wide.

---

### "Owner" is the highest-ranked role in the table, not the string `'owner'`

**What I chose:** `lifecycle.js` finds the owner role as `ORDER BY rank DESC LIMIT 1`; ranks and
the catalogue are read from the database on every call.
**Why:** grading uses a different fixture with at least one undocumented role.
`check-lifecycle.js` inserts `steward` (rank 35): `operator -> steward (35 > 30)` is refused,
`admin assigns steward` is allowed, with no code change. Commit 3fca4d5.
**What I rejected:** `role === 'owner'` and a copy of the 5-role matrix — both pass the public
suites and break on the grading fixture.
**What would change my mind:** a schema flag marking the owner role explicitly; then read that
flag instead of inferring it from rank.

---

### Login compares against a dummy hash when the email does not exist

**What I chose:** `verifyPassword(password, user ? user.password_hash : DUMMY_HASH)` in
`server/routes/auth.js`, and the same 401 and message for both failures.
**Why:** measured over 20 runs: wrong password 98.1 ms, unknown email with the dummy compare
98.3 ms, unknown email without it 0.006 ms. `check-auth.js` `unknown email -> same status and
message`. Commit 7fb5967.
**What I rejected:** identical messages alone. The timing gap is four orders of magnitude, so the
message does not matter — the clock answers "does this account exist".
**What would change my mind:** rate limiting and a fixed response delay in front of login, which
would make per-request timing unusable anyway (out of scope here per the README).

---

### Expired sessions are marked ended before a new one starts

**What I chose:** `expireStaleSessions()` sets `state = 'ended'`, `end_reason =
'session_expired'` for rows past `expires_at`; the session route calls it before inserting.
**Why:** the exclusive-session index is `WHERE state = 'active'`, and nothing changes `state` when
time passes. `check-lifecycle.js` `expired-but-active row blocks a new control session` fails with
`UNIQUE constraint failed: sessions.device_id`; after `expireStaleSessions` the insert succeeds.
**What I rejected:** comparing `expires_at` at read time only. Reads would look right while the
index still refused the insert — the device reads `DEVICE_BUSY` forever.
**What would change my mind:** a scheduled sweeper, or an index predicate that can reference the
current time (SQLite partial indexes cannot use non-deterministic functions).

---

### A refresh restores the org the client asks for, else the earliest-joined active one

**What I chose:** `POST /v1/auth/refresh` takes an optional `orgId`; without it, the default org
is the earliest-joined active membership.
**Why:** `refresh_tokens` has no `org_id`, and the UI test `a reload restores the session from the
refresh cookie` expects Dana in Acme. `check-auth.js` `refresh with orgId restores that org`.
**What I rejected:** adding `org_id` to `refresh_tokens` — a schema change to tie a user-level
credential to one org, when the org is already a per-token choice (`POST /v1/auth/token`).
**What would change my mind:** a requirement that a reload always returns to the last org even
with no client state; then the org belongs in the refresh row.

---

## Where this repo argues with itself

**1. The verifier is asked to check something it cannot see.**
`AUTH-DATA-MODEL.md §10` lists "a token whose `pv` is stale, as `401 TOKEN_STALE`" under what
`verifyAccessToken` must refuse, and `BRIEF.md §3` says it has to reject "a stale permission
version". `server/auth.js` gives it the signature `verifyAccessToken(token, secret)` and ships
`assertFresh(claims, membership)` separately. Built against the code: freshness is checked in
`context.js`. The documents describe the pipeline's behaviour; the stub describes the function.

**2. Grants are "org-scoped by construction", but the schema does not construct it.**
`AUTH-DATA-MODEL.md §4`: "A grant in one org cannot affect another, even if it names a device id
that happens to exist in both." `db/schema.sql`: `grants.org_id` and `grants.device_id` reference
their tables independently — nothing ties the device to the grant's org. Built against the
documented rule: the resolution query only counts a device-scoped grant whose device is live in
the grant's own org (`activeGrants` in `permissions.js`).

**3. "All nineteen" versus the table.**
`PERMISSIONS.md §4`: "`*` to all nineteen". The personalised database has 20 (`device:reboot`).
Built against the table: wildcards expand against `permissions` at runtime.

**4. My own wrong reading, corrected.**
Claimed in the Phase 2 log that allow provenance was unspecified and returned `reason: 'role'` /
`'grant'`. `BRIEF.md §5.2` shows `{ "effect": "allow", "source": "role:operator", "reason": null }`.
Not a contradiction in the repo — a miss on my side, fixed in d027675 and logged.

## Deliberately not built

- **Caching resolved permissions.** Every request resolves fresh: 4 queries regardless of device
  count (measured). A cache would need versioning to stay correct under `pv` bumps and expiring
  grants, for no measured need.
- **`iat` / `nbf` checks in the verifier.** Only this server can sign, so a future `iat` is our
  clock, not a forgery.
- **Logout endpoint.** Not in the endpoint list.
- **Windows portability of `npm start`** (`NODE_ENV=` syntax) and `server/index.js:22`'s `.pathname`
  path — only `load-db.js` was fixed, because it blocked development. Listed in Open threads.
- **Rate limiting**, per the README.
