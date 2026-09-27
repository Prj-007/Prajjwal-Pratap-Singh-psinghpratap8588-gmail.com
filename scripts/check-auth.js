// The auth routes over real HTTP: login, refresh rotation and reuse, switch org, me.
// Spawns the server against a throwaway database, like check-api.js.
// Run: node scripts/check-auth.js

import { spawn, execFileSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';

const PORT = 8125;
const BASE = `http://localhost:${PORT}/v1`;
const DB = 'check-auth.db';

for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s);
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });
const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: 'auth-secret' },
  stdio: ['ignore', 'ignore', 'inherit'],
});
await new Promise((r) => setTimeout(r, 1200));

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(58)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};
async function call(method, path, { token, body, cookie } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  if (cookie) headers.cookie = cookie;
  const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, setCookie: res.headers.get('set-cookie') };
}
const rtOf = (setCookie) => /(?:^|;\s*)rt=([^;]*)/.exec(setCookie ?? '')?.[1] ?? null;
const login = (email, password = 'demo1234', extra = {}) => call('POST', '/auth/login', { body: { email, password, ...extra } });

try {
  console.log('\n== login ==');
  const dana = await login('dana@example.test');
  check('200', dana.status, 200);
  check('default org is the earliest joined (Acme)', dana.body.orgId, 'org_acme');
  check('response carries org-level permissions', dana.body.permissions['org:delete'], { effect: 'allow', source: 'role:owner', reason: null });
  check('user block, no password hash', Object.keys(dana.body.user).sort(), ['email', 'id', 'name']);
  const cookie = dana.setCookie ?? '';
  check('refresh cookie is HttpOnly', /HttpOnly/i.test(cookie), true);
  check('...SameSite=Strict and Secure', /SameSite=Strict/i.test(cookie) && /Secure/i.test(cookie), true);
  check('...scoped to /v1/auth', /Path=\/v1\/auth(;|$)/.test(cookie), true);
  check('login with orgId picks that org', (await login('dana@example.test', 'demo1234', { orgId: 'org_globex' })).body.role, 'viewer');

  const wrong = await login('dana@example.test', 'nope');
  const ghost = await login('nobody@example.test', 'nope');
  check('wrong password -> 401', wrong.status, 401);
  check('unknown email -> same status and message', [ghost.status, ghost.body.error.message], [wrong.status, wrong.body.error.message]);
  check('missing password -> 400', (await call('POST', '/auth/login', { body: { email: 'dana@example.test' } })).status, 400);

  console.log('\n== me ==');
  const me = await call('GET', '/auth/me', { token: dana.body.token });
  check('GET /auth/me', [me.status, me.body.role, me.body.orgs.length], [200, 'owner', 2]);
  check('no token -> 401', (await call('GET', '/auth/me')).status, 401);

  console.log('\n== refresh: rotation and reuse ==');
  const rt1 = rtOf(dana.setCookie);
  const r1 = await call('POST', '/auth/refresh', { cookie: `rt=${rt1}` });
  check('refresh -> 200 with a new access token', [r1.status, typeof r1.body.token], [200, 'string']);
  const rt2 = rtOf(r1.setCookie);
  check('...and a different refresh token', rt2 !== null && rt2 !== rt1, true);
  check('refresh with orgId restores that org', (await call('POST', '/auth/refresh', { cookie: `rt=${rt2}`, body: { orgId: 'org_globex' } })).body.orgId, 'org_globex');
  // rt2 is now rotated too. Replaying rt1 (rotated first) must revoke the whole family.
  const replay = await call('POST', '/auth/refresh', { cookie: `rt=${rt1}` });
  check('replaying a rotated token -> 401', replay.status, 401);
  check('...and clears the cookie', /Max-Age=0/.test(replay.setCookie ?? ''), true);

  const fresh = await login('sam@example.test');
  const s1 = rtOf(fresh.setCookie);
  const s2 = rtOf((await call('POST', '/auth/refresh', { cookie: `rt=${s1}` })).setCookie);
  await call('POST', '/auth/refresh', { cookie: `rt=${s1}` });            // reuse of s1
  check('after reuse, the newest token in the family is dead too', (await call('POST', '/auth/refresh', { cookie: `rt=${s2}` })).status, 401);

  check('an access token is not a refresh token', (await call('POST', '/auth/refresh', { cookie: `rt=${fresh.body.token}` })).status, 401);
  check('no cookie -> 401', (await call('POST', '/auth/refresh')).status, 401);

  console.log('\n== switch org ==');
  const sw = await call('POST', '/auth/token', { token: dana.body.token, body: { orgId: 'org_globex' } });
  check('switch to Globex', [sw.status, sw.body.role, sw.body.org.theme !== dana.body.org.theme], [200, 'viewer', true]);
  check('org you are not in -> 404', (await call('POST', '/auth/token', { token: dana.body.token, body: { orgId: 'org_p_nope' } })).status, 404);
  check('missing orgId -> 400', (await call('POST', '/auth/token', { token: dana.body.token, body: {} })).status, 400);
} catch (err) {
  console.log(`\n  aborted: ${err.message}`);
  fail++;
} finally {
  server.kill();
  for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) try { rmSync(DB + s); } catch {}
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
