// Exercises authenticate() in server/context.js directly, before any route exists.
// Run: node scripts/check-context.js

import { readFileSync } from 'node:fs';
import { openDatabase, bumpPermVersion } from '../server/db.js';
import { issueAccessToken, signToken } from '../server/auth.js';
import { authenticate } from '../server/context.js';
import { HttpError } from '../server/http.js';

const SECRET = 'ctx-secret';
const db = openDatabase(':memory:');
db.exec(readFileSync(new URL('../db/schema.sql', import.meta.url), 'utf8'));
db.exec(readFileSync(new URL('../db/reference.sql', import.meta.url), 'utf8'));

// One person in two orgs, plus a user who is only in org A.
db.exec(`
  INSERT INTO organizations (id,name,theme) VALUES ('oa','A','cobalt'), ('ob','B','ember'), ('oc','C','moss');
  INSERT INTO users (id,email,name,password_hash) VALUES ('u1','u1@x.test','U1','x'), ('u2','u2@x.test','U2','x');
  INSERT INTO memberships (id,org_id,user_id,role,status) VALUES
    ('m1a','oa','u1','owner','active'), ('m1b','ob','u1','viewer','active'),
    ('m2a','oa','u2','viewer','active'), ('m1c','oc','u1','admin','active');
`);

const pvOf = (org, user) => db.prepare('SELECT perm_version FROM memberships WHERE org_id=? AND user_id=?').get(org, user).perm_version;
const token = (user, org, over = {}) =>
  issueAccessToken({ userId: user, orgId: org, role: 'x', permVersion: pvOf(org, user), ...over }, SECRET);
const req = (tok, method = 'GET', url = '/v1/orgs/oa/devices') =>
  ({ method, url, headers: tok === undefined ? {} : { authorization: tok } });

const build = authenticate(db, SECRET);
const outcome = (r, params = {}) => {
  try { const c = build(r, params); return `ok ${c.userId}@${c.orgId} ${c.role}`; }
  catch (e) { return e instanceof HttpError ? `${e.status} ${e.code}${e.reason ? ' ' + e.reason : ''}` : `${e.constructor.name}: ${e.message}`; }
};

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = actual === expected;
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(56)} ${ok ? '' : `got ${actual} want ${expected}`}`);
};

console.log('\n== reading the credential ==');
check('no Authorization header', outcome(req(undefined)), '401 UNAUTHENTICATED');
check('Basic scheme', outcome(req('Basic abc')), '401 UNAUTHENTICATED');
check('Bearer with nothing after it', outcome(req('Bearer ')), '401 UNAUTHENTICATED');
check('lowercase "bearer" accepted', outcome(req(`bearer ${token('u1', 'oa')}`)), 'ok u1@oa owner');
check('garbage token', outcome(req('Bearer abc.def.ghi')), '401 UNAUTHENTICATED');

console.log('\n== the caller ==');
check('valid token, role from the membership row', outcome(req(`Bearer ${token('u1', 'oa')}`)), 'ok u1@oa owner');
check('same user, org B token, role is B\'s', outcome(req(`Bearer ${token('u1', 'ob')}`)), 'ok u1@ob viewer');
const noSub = signToken({ iss: 'remoteops', aud: 'remoteops-api', org: 'oa', pv: 1, jti: 'j', exp: Math.floor(Date.now() / 1000) + 60 }, SECRET);
check('signed token without sub', outcome(req(`Bearer ${noSub}`)), '401 UNAUTHENTICATED');

console.log('\n== isolation: the token names the only addressable org ==');
const t1a = `Bearer ${token('u1', 'oa')}`;
check('path org matches the token', outcome(req(t1a), { org: 'oa' }), 'ok u1@oa owner');
check('path org B, token A, user IS a member of B', outcome(req(t1a), { org: 'ob' }), '404 NOT_FOUND');
check('path org that does not exist', outcome(req(t1a), { org: 'org_nope' }), '404 NOT_FOUND');
check('...same answer for both', outcome(req(t1a), { org: 'ob' }) === outcome(req(t1a), { org: 'org_nope' }) ? 'same' : 'differ', 'same');

console.log('\n== freshness (pv) ==');
const old = `Bearer ${token('u2', 'oa')}`;
bumpPermVersion(db, { orgId: 'oa', userId: 'u2' });
check('token from before a permission change', outcome(req(old)), '401 TOKEN_STALE');
check('token from the future (pv + 1)', outcome(req(`Bearer ${token('u2', 'oa', { permVersion: pvOf('oa', 'u2') + 1 })}`)), '401 TOKEN_STALE');
check('fresh token after the change', outcome(req(`Bearer ${token('u2', 'oa')}`)), 'ok u2@oa viewer');

console.log('\n== suspension ==');
const beforeSuspend = `Bearer ${token('u2', 'oa')}`;
db.exec("UPDATE memberships SET status='suspended', perm_version = perm_version + 1 WHERE id='m2a'");
check('token issued before the suspension', outcome(req(beforeSuspend)), '401 TOKEN_STALE');
const suspended = `Bearer ${token('u2', 'oa')}`;
check('fresh token, ordinary route', outcome(req(suspended)), '403 FORBIDDEN suspended');
check('fresh token, GET /v1/auth/me', outcome(req(suspended, 'GET', '/v1/auth/me')), 'ok u2@oa viewer');
check('fresh token, POST /v1/auth/token', outcome(req(suspended, 'POST', '/v1/auth/token')), 'ok u2@oa viewer');
check('fresh token, DELETE /v1/auth/me is not open', outcome(req(suspended, 'DELETE', '/v1/auth/me')), '403 FORBIDDEN suspended');
check('query string does not change the route', outcome(req(suspended, 'GET', '/v1/auth/me?x=1')), 'ok u2@oa viewer');

console.log('\n== membership or org gone ==');
db.exec("UPDATE memberships SET status='removed', perm_version = perm_version + 1 WHERE id='m1b'");
check('removed membership', outcome(req(`Bearer ${token('u1', 'ob')}`)), '401 UNAUTHENTICATED');
const tc = `Bearer ${token('u1', 'oc')}`;
db.exec("UPDATE organizations SET deleted_at = '2026-01-01T00:00:00.000Z' WHERE id='oc'");
check('org soft-deleted', outcome(req(tc)), '401 UNAUTHENTICATED');
check('never a member at all', outcome(req(`Bearer ${issueAccessToken({ userId: 'u2', orgId: 'ob', role: 'x', permVersion: 1 }, SECRET)}`)), '401 UNAUTHENTICATED');

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
