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
`UNIQUE constraint failed: sessions.device_id`; after `expireStaleSessions` the insert succeeds. Through the API, `check-routes.js` `expired session no longer holds the device`; removing the call from session start makes it `409` (mutant, 34/37).
**What I rejected:** comparing `expires_at` at read time only. Reads would look right while the
index still refused the insert — the device reads `DEVICE_BUSY` forever.
**What would change my mind:** a scheduled sweeper, or an index predicate that can reference the
current time (SQLite partial indexes cannot use non-deterministic functions).

---

### A wildcard grant needs every permission it expands to — in the table, not the docs

**What I chose:** `assertMayGrant` expands each pattern against the `permissions` table and
requires the caller to hold every resulting permission at that scope (`server/permissions.js`).
**Why:** `check-routes.js` `...nor device:*` — predicted `explicit_deny` (the admin had an
org-wide deny on `device:terminal`), got `missing_permission`: the expansion includes the
undocumented `device:reboot`, which is in no role's baseline (checked: the owner holds 19 of 20).
So `even the owner cannot grant * on this database` — asserted, commit 7e067aa.
**What I rejected:** expanding wildcards against the documented 19, or treating `*` as "whatever
the caller holds". The first breaks on the grading fixture; the second silently narrows a grant
the caller asked for, so the grantee gets less than the request says.
**What would change my mind:** a rule that wildcard grants are dynamic — resolved at check time
against whatever the grantor held when granting. The schema stores patterns, not expansions, so it
would need a snapshot the schema does not have.

---

### Equal rank cannot modify equal rank — except owners, who can act on owners

**What I chose:** `assertCanModify` allows a strictly higher rank, and the top-ranked role acting
on itself; every other equal pair is `403 insufficient_rank` (`server/lifecycle.js`).
**Why:** first built as "strictly above" from `PERMISSIONS.md §6` (admin → admin is 403). Read
`check-api.js` `demoting a NON-last owner is allowed` — owner demotes owner, expects 200 — and
predicted a failure. `check-orgs.js` `owner demotes another owner (two owners)` failed with
`403 FORBIDDEN insufficient_rank`; passed after the change in eb6ad78. `admin cannot modify another
admin (equal)` still returns 403.
**What I rejected:** "strictly above" everywhere — with it a second owner can never be demoted by
anyone, only leave. Also rejected "equal is fine everywhere" — admins could then demote each other.
**What would change my mind:** a rule that demoting an owner needs the owner's own consent, or a
separate transfer-ownership flow; then owner → owner would be refused here and handled there.

---

### Org-level and people actions use the strict org scope, never the org-level union

**What I chose:** routes for members, invites-to-come and the org itself call
`assertCanOrgWide` (org-wide grants and the role only); the union is used only for navigation
(`/auth/me`) and `device:list`.
**Why:** same argument as `assertMayGrant`: under the union, a grant of `user:remove` scoped to a
single device would let someone suspend members of the whole org. `check-orgs.js` covers the
refusals (`viewer cannot change roles`, `admin cannot delete the org`, `operator cannot provision`).
**What I rejected:** `assertCan(…)` with no device, which resolves the union. Simpler, and it turns
any device-scoped grant into org authority.
**What would change my mind:** seeing that device-scoped grants of non-device permissions cannot
exist. They can today (`grant_permissions` accepts any pattern on any grant), and the known gap is
the reverse: `/auth/me` shows the union, so such a grant would light up navigation the API refuses.

---

### A device the caller cannot view is a 404 on every route, not a 403

**What I chose:** `visible()` in `server/routes/devices.js` returns 404 unless the device is live in
this org *and* `device:view` resolves to allow on it; detail, update, delete and transfer all go
through it before checking their own permission.
**Why:** the list already leaves such a device out (`check-api.js` `kiosk-lobby-01 is ABSENT (not
redacted)`). A 403 on the detail route would confirm what the list hides.
**What I rejected:** 403 when the device exists but `device:view` is denied — the reading of
`PERMISSIONS.md §5` "you can see it but lack the permission". Seeing it *is* `device:view` here.
**What would change my mind:** a requirement that denials on hidden devices appear in the audit
log — `auditDenials` records only 403s, so these 404s are not audited.

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

**4. "Equal role → 403" versus a test where an owner demotes an owner.**
`PERMISSIONS.md §6`: "modify a user of equal role (admin → admin) | `403`". `scripts/check-api.js`:
`demoting a NON-last owner is allowed` — Dana (owner) sets `usr_acme_owner` (owner) to viewer and
expects 200. Built against the test for the top role only: owners may act on owners, every other
equal pair is 403. The table's own example is admin → admin, and the last-owner rule (§6, same
table) only makes sense if an owner can demote an owner.

**5. My own wrong reading, corrected.**
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
