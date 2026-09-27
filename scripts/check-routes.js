// Grants, sessions, invites and audit over real HTTP — the cases check-api.js does not reach.
// Run: node scripts/check-routes.js

import { spawn, execFileSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';
import Database from 'better-sqlite3';

const PORT = 8127;
const BASE = `http://localhost:${PORT}/v1`;
const DB = 'check-routes.db';

for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s);
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });
const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: 'routes-secret' },
  stdio: ['ignore', 'ignore', 'inherit'],
});
await new Promise((r) => setTimeout(r, 1200));
const side = new Database(DB);              // a second connection, to age a session in place
side.pragma('busy_timeout = 5000');

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(62)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};
async function call(method, path, { token, body } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}
const tok = async (email, orgId, password = 'demo1234') => (await call('POST', '/auth/login', { body: { email, password, ...(orgId ? { orgId } : {}) } })).body.token;
const code = (r) => (r.status < 400 ? r.status : `${r.status} ${r.body.error.code}${r.body.error.reason ? ' ' + r.body.error.reason : ''}`);
const A = '/orgs/org_acme';

try {
  const dana = await tok('dana@example.test');
  const sam = await tok('sam@example.test');

  console.log('\n== grants ==');
  const list = (await call('GET', `${A}/grants`, { token: dana })).body.grants;
  check('Acme has 3 live grants, 2 of them deny', [list.length, list.filter((g) => g.effect === 'deny').length], [3, 2]);
  check('already-expired grant -> 400 GRANT_EXPIRED', code(await call('POST', `${A}/grants`, { token: dana, body: { userId: 'usr_sam', effect: 'allow', permissions: ['audit:read'], expiresAt: new Date(Date.now() - 1000).toISOString() } })), '400 GRANT_EXPIRED expired_grant');
  check('expiresAt with +00:00 offset is normalised, not mis-ordered', code(await call('POST', `${A}/grants`, { token: dana, body: { userId: 'usr_acme_admin', effect: 'allow', permissions: ['device:view'], expiresAt: new Date(Date.now() + 3600e3).toISOString().replace('Z', '+00:00') } })), 201);
  check('device in another org -> 404', code(await call('POST', `${A}/grants`, { token: dana, body: { userId: 'usr_sam', deviceId: 'dev_globex_desk_01', effect: 'allow', permissions: ['device:view'] } })), '404 NOT_FOUND');
  check('grantee not a member -> 404', code(await call('POST', `${A}/grants`, { token: dana, body: { userId: 'usr_globex_owner', effect: 'allow', permissions: ['device:view'] } })), '404 NOT_FOUND');
  check('wrong case is an unknown permission', code(await call('POST', `${A}/grants`, { token: dana, body: { userId: 'usr_sam', effect: 'allow', permissions: ['Device:View'] } })), '400 VALIDATION unknown_permission');

  // Laundering through the API: deny the admin device:terminal org-wide, then let them try to hand it out.
  const deny = await call('POST', `${A}/grants`, { token: dana, body: { userId: 'usr_acme_admin', effect: 'deny', permissions: ['device:terminal'] } });
  check('owner denies the admin device:terminal org-wide', deny.status, 201);
  const admin2 = await tok('admin@acme.test');
  check('...admin cannot grant device:terminal to Sam (laundering)', code(await call('POST', `${A}/grants`, { token: admin2, body: { userId: 'usr_sam', deviceId: 'dev_lab_win_01', effect: 'allow', permissions: ['device:terminal'] } })), '403 FORBIDDEN explicit_deny');
  // device:* expands against the table, which holds the undocumented device:reboot — in no
  // role's baseline — so it is refused as not held before device:terminal is even reached.
  check('...nor device:* (refused on device:reboot, which no role holds)', code(await call('POST', `${A}/grants`, { token: admin2, body: { userId: 'usr_sam', effect: 'allow', permissions: ['device:*'] } })), '403 FORBIDDEN missing_permission');
  check('even the owner cannot grant * on this database', code(await call('POST', `${A}/grants`, { token: dana, body: { userId: 'usr_sam', effect: 'allow', permissions: ['*'] } })), '403 FORBIDDEN missing_permission');
  check('revoke the deny', code(await call('DELETE', `${A}/grants/${deny.body.id}`, { token: dana })), 200);
  check('revoking again -> 404 (no longer visible)', code(await call('DELETE', `${A}/grants/${deny.body.id}`, { token: dana })), '404 NOT_FOUND');
  check('viewer lacks grant:create', code(await call('POST', `${A}/grants`, { token: await tok('viewer@acme.test'), body: { userId: 'usr_sam', effect: 'allow', permissions: ['device:view'] } })), '403 FORBIDDEN missing_permission');

  console.log('\n== sessions ==');
  const s1 = await call('POST', `${A}/sessions`, { token: sam, body: { deviceId: 'dev_lab_win_01', mode: 'control' } });
  check('Sam starts control on lab-win-01', s1.status, 201);
  check('...snapshot records his role', s1.body.authorized_by.role, 'operator');
  check('...expires after Acme\'s max_session_minutes', Math.round((Date.parse(s1.body.expires_at) - Date.parse(s1.body.started_at)) / 60000) > 0, true);
  const busy = await call('POST', `${A}/sessions`, { token: dana, body: { deviceId: 'dev_lab_win_01', mode: 'terminal' } });
  check('Dana terminal on the same device -> 409 naming the holder', [busy.status, busy.body.error.message.includes(s1.body.id)], [409, true]);
  check('unknown mode -> 400', code(await call('POST', `${A}/sessions`, { token: sam, body: { deviceId: 'dev_lab_win_01', mode: 'teleport' } })), '400 VALIDATION');
  check('viewer on the kiosk they cannot view -> 404', code(await call('POST', `${A}/sessions`, { token: await tok('viewer@acme.test'), body: { deviceId: 'dev_kiosk_lobby_01', mode: 'view' } })), '404 NOT_FOUND');

  // Age Sam's session past its expiry behind the server's back: the row still says 'active'.
  side.prepare("UPDATE sessions SET expires_at = ? WHERE id = ?").run(new Date(Date.now() - 1000).toISOString(), s1.body.id);
  const after = await call('POST', `${A}/sessions`, { token: dana, body: { deviceId: 'dev_lab_win_01', mode: 'terminal' } });
  check('expired session no longer holds the device', after.status, 201);
  check('...and it reads ended / session_expired', (await call('GET', `/sessions/${s1.body.id}`, { token: sam })).body.end_reason, 'session_expired');

  check('Sam cannot end Dana\'s session (no session:terminate)', code(await call('DELETE', `/sessions/${after.body.id}`, { token: sam })), '403 FORBIDDEN missing_permission');
  check('Dana ends her own -> user_stopped', (await call('DELETE', `/sessions/${after.body.id}`, { token: dana })).body.end_reason, 'user_stopped');
  const globexOwner = await tok('owner@globex.test');
  check('a session from another org -> 404', code(await call('GET', `/sessions/${after.body.id}`, { token: globexOwner })), '404 NOT_FOUND');

  console.log('\n== invites ==');
  const inv = await call('POST', `${A}/invites`, { token: dana, body: { email: 'Twice@Example.test', role: 'viewer' } });
  check('invite created, email lowercased', [inv.status, inv.body.email], [201, 'twice@example.test']);
  check('second live invite for the same email -> 409', code(await call('POST', `${A}/invites`, { token: dana, body: { email: 'twice@example.test', role: 'viewer' } })), '409 CONFLICT');
  check('inviting an existing member -> 409', code(await call('POST', `${A}/invites`, { token: dana, body: { email: 'sam@example.test', role: 'viewer' } })), '409 CONFLICT');
  // admin2 went stale when the deny on them was revoked (pv bump) — log in again.
  const admin3 = await tok('admin@acme.test');
  check('admin cannot invite an owner', code(await call('POST', `${A}/invites`, { token: admin3, body: { email: 'boss@example.test', role: 'owner' } })), '403 FORBIDDEN insufficient_rank');
  check('list shows it without the token', (await call('GET', `${A}/invites`, { token: dana })).body.invites.some((i) => i.id === inv.body.id && !('inviteToken' in i)), true);
  check('revoke it', code(await call('DELETE', `${A}/invites/${inv.body.id}`, { token: dana })), 200);
  check('...then the link is 410 GONE', code(await call('GET', `/invites/${inv.body.inviteToken}`)), '410 GONE');

  const forSam = await call('POST', '/orgs/org_globex/invites', { token: globexOwner, body: { email: 'viewer@acme.test', role: 'viewer' } });
  check('existing account must use its own password to accept', code(await call('POST', `/invites/${forSam.body.inviteToken}/accept`, { body: { name: 'x', password: 'not-theirs-1' } })), '401 UNAUTHENTICATED');
  const joined = await call('POST', `/invites/${forSam.body.inviteToken}/accept`, { body: { password: 'demo1234' } });
  check('...with it, they join and are signed in to that org', [joined.status, joined.body.orgId, joined.body.role], [200, 'org_globex', 'viewer']);

  console.log('\n== audit ==');
  check('limit=abc -> 400', code(await call('GET', `${A}/audit?limit=abc`, { token: dana })), '400 VALIDATION');
  const page = (await call('GET', `${A}/audit?limit=2`, { token: dana })).body;
  check('limit=2 returns 2 with a total', [page.events.length, page.total > 2], [2, true]);
  check('newest first', page.events[0].at >= page.events[1].at, true);
  check('the laundering attempt is in the log as one explicit_deny', side.prepare("SELECT count(*) AS n FROM audit_events WHERE action='grant.create' AND result='deny' AND reason_code='explicit_deny'").get().n, 1);
} catch (err) {
  console.log(`\n  aborted: ${err.stack}`);
  fail++;
} finally {
  server.kill();
  side.close();
  for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) try { rmSync(DB + s); } catch {}
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
