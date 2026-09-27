// Orgs, members, effective permissions and devices over real HTTP.
// Run: node scripts/check-orgs.js

import { spawn, execFileSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';
import Database from 'better-sqlite3';

const PORT = 8126;
const BASE = `http://localhost:${PORT}/v1`;
const DB = 'check-orgs.db';

for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s);
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });
const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: 'orgs-secret' },
  stdio: ['ignore', 'ignore', 'inherit'],
});
await new Promise((r) => setTimeout(r, 1200));
const peek = new Database(DB, { readonly: true });   // to look at rows the API does not return

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(60)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};
async function call(method, path, { token, body } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}
const tok = async (email, orgId) => (await call('POST', '/auth/login', { body: { email, password: 'demo1234', ...(orgId ? { orgId } : {}) } })).body.token;
const code = (r) => (r.status < 400 ? r.status : `${r.status} ${r.body.error.code}${r.body.error.reason ? ' ' + r.body.error.reason : ''}`);

try {
  const dana = await tok('dana@example.test');
  const admin = await tok('admin@acme.test');
  const viewer = await tok('viewer@acme.test');
  const A = '/orgs/org_acme';

  console.log('\n== members ==');
  const members = await call('GET', `${A}/members`, { token: dana });
  check('list members', [members.status, members.body.members.length], [200, 5]);
  check('ordered by rank, owners first', members.body.members[0].role, 'owner');
  check('viewer can list (user:read)', (await call('GET', `${A}/members`, { token: viewer })).status, 200);
  check('member in another org -> 404', code(await call('PATCH', `${A}/members/usr_globex_owner`, { token: dana, body: { role: 'viewer' } })), '404 NOT_FOUND');
  check('unknown role -> 400', code(await call('PATCH', `${A}/members/usr_acme_viewer`, { token: dana, body: { role: 'god' } })), '400 VALIDATION unknown_role');
  check('viewer cannot change roles', code(await call('PATCH', `${A}/members/usr_sam`, { token: viewer, body: { role: 'viewer' } })), '403 FORBIDDEN missing_permission');
  check('admin changing their own role -> SELF_ROLE_CHANGE', code(await call('PATCH', `${A}/members/usr_acme_admin`, { token: admin, body: { role: 'viewer' } })), '403 SELF_ROLE_CHANGE');
  check('owner promotes the viewer to admin', code(await call('PATCH', `${A}/members/usr_acme_viewer`, { token: dana, body: { role: 'admin' } })), 200);
  check('admin cannot modify another admin (equal)', code(await call('PATCH', `${A}/members/usr_acme_viewer`, { token: admin, body: { role: 'viewer' } })), '403 FORBIDDEN insufficient_rank');
  check('owner demotes another owner (two owners)', code(await call('PATCH', `${A}/members/usr_acme_owner`, { token: dana, body: { role: 'admin' } })), 200);
  check('...and the demoted owner\'s pv was bumped', peek.prepare("SELECT perm_version FROM memberships WHERE org_id='org_acme' AND user_id='usr_acme_owner'").get().perm_version, 2);

  console.log('\n== suspend / reinstate / remove ==');
  const sam = await tok('sam@example.test');
  check('suspend Sam', code(await call('POST', `${A}/members/usr_sam/suspend`, { token: dana })), 200);
  check('...Sam\'s live session ended user_suspended', peek.prepare("SELECT end_reason FROM sessions WHERE id='ses_live_build_server'").get().end_reason, 'user_suspended');
  check('...Sam\'s old token is stale', code(await call('GET', `${A}/devices`, { token: sam })), '401 TOKEN_STALE');
  // Sam's default org skips the suspended membership, so ask for Acme explicitly.
  check('...plain login now lands in Globex', (await call('POST', '/auth/login', { body: { email: 'sam@example.test', password: 'demo1234' } })).body.orgId, 'org_globex');
  const samFresh = await tok('sam@example.test', 'org_acme');
  check('...a fresh token is refused as suspended', code(await call('GET', `${A}/devices`, { token: samFresh })), '403 FORBIDDEN suspended');
  check('...but /auth/me still answers', (await call('GET', '/auth/me', { token: samFresh })).status, 200);
  check('reinstate Sam', code(await call('DELETE', `${A}/members/usr_sam/suspend`, { token: dana })), 200);
  check('cannot suspend yourself', code(await call('POST', `${A}/members/usr_dana/suspend`, { token: dana })), '403 FORBIDDEN self');
  check('remove the viewer', code(await call('DELETE', `${A}/members/usr_acme_viewer`, { token: dana })), 200);
  check('...removed user\'s token -> 401', code(await call('GET', `${A}/devices`, { token: viewer })), '401 UNAUTHENTICATED');
  check('...and they are gone from the list', (await call('GET', `${A}/members`, { token: dana })).body.members.some((m) => m.userId === 'usr_acme_viewer'), false);

  console.log('\n== effective ==');
  const eff = await call('GET', `${A}/users/usr_sam/effective`, { token: dana });
  check('Sam in Acme: operator, terminal denied org-wide', [eff.body.role, eff.body.permissions['device:terminal'].reason], ['operator', 'explicit_deny']);
  const samNow = await tok('sam@example.test');
  check('self may read own effective set', (await call('GET', `${A}/users/usr_sam/effective`, { token: samNow })).status, 200);
  check('...but not someone else\'s without user:read', code(await call('GET', `${A}/users/usr_dana/effective`, { token: samNow })), '403 FORBIDDEN missing_permission');
  check('?deviceId from another org -> 404', code(await call('GET', `${A}/users/usr_sam/effective?deviceId=dev_globex_desk_01`, { token: dana })), '404 NOT_FOUND');

  console.log('\n== devices ==');
  const created = await call('POST', `${A}/devices`, { token: dana, body: { name: 'new-box', kind: 'linux' } });
  check('create device -> 201 with permissions', [created.status, created.body.permissions['device:control'].effect], [201, 'allow']);
  check('duplicate name -> 409', code(await call('POST', `${A}/devices`, { token: dana, body: { name: 'new-box', kind: 'linux' } })), '409 CONFLICT');
  check('bad kind -> 400 from the schema CHECK', code(await call('POST', `${A}/devices`, { token: dana, body: { name: 'x', kind: 'toaster' } })), '400 VALIDATION');
  check('operator cannot provision', code(await call('POST', `${A}/devices`, { token: samNow, body: { name: 'y', kind: 'linux' } })), '403 FORBIDDEN missing_permission');
  check('rename', (await call('PATCH', `${A}/devices/${created.body.id}`, { token: dana, body: { name: 'renamed-box' } })).body.name, 'renamed-box');
  check('device in another org -> 404', code(await call('GET', `${A}/devices/dev_globex_desk_01`, { token: dana })), '404 NOT_FOUND');
  check('delete', code(await call('DELETE', `${A}/devices/${created.body.id}`, { token: dana })), 200);
  check('...then it is 404', code(await call('GET', `${A}/devices/${created.body.id}`, { token: dana })), '404 NOT_FOUND');

  console.log('\n== transfer ==');
  const moved = await call('POST', `${A}/devices/dev_qa_android_01/transfer`, { token: dana, body: { toOrgId: 'org_globex' } });
  check('owner in Acme, viewer in Globex: transfer refused', code(moved), '403 FORBIDDEN missing_permission');
  const solo = await call('POST', '/orgs', { token: dana, body: { name: 'Transfer Target' } });
  const t = await call('POST', `${A}/devices/dev_qa_android_01/transfer`, { token: dana, body: { toOrgId: solo.body.id } });
  check('transfer to an org where Dana owns', [t.status, t.body.orgId], [200, solo.body.id]);
  check('...gone from Acme', code(await call('GET', `${A}/devices/dev_qa_android_01`, { token: dana })), '404 NOT_FOUND');

  console.log('\n== orgs ==');
  check('GET /orgs lists the new org', (await call('GET', '/orgs', { token: dana })).body.orgs.some((o) => o.id === solo.body.id), true);
  check('admin cannot delete the org', code(await call('DELETE', A, { token: admin })), '403 FORBIDDEN missing_permission');
  check('rename org needs org:update', code(await call('PATCH', A, { token: samNow, body: { name: 'x' } })), '403 FORBIDDEN missing_permission');
  check('refusals are audited', peek.prepare("SELECT count(*) AS n FROM audit_events WHERE result='deny' AND action='org.delete'").get().n, 1);
} catch (err) {
  console.log(`\n  aborted: ${err.stack}`);
  fail++;
} finally {
  server.kill();
  peek.close();
  for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) try { rmSync(DB + s); } catch {}
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
