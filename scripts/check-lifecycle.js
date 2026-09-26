// Exercises server/lifecycle.js and server/audit.js directly.
// Run: node scripts/check-lifecycle.js

import { readFileSync } from 'node:fs';
import { openDatabase } from '../server/db.js';
import {
  roleRanks, assertRoleExists, assertCanModify, assertCanAssign, assertNotLastOwner,
  endActiveSessions, expireStaleSessions, snapshotAuthority, sessionExpiry,
} from '../server/lifecycle.js';
import { audit, auditDenials } from '../server/audit.js';
import { HttpError, forbidden, notFound, badRequest } from '../server/http.js';

const db = openDatabase(':memory:');
db.exec(readFileSync(new URL('../db/schema.sql', import.meta.url), 'utf8'));
db.exec(readFileSync(new URL('../db/reference.sql', import.meta.url), 'utf8'));
// An undocumented role, as the grading fixture will have one.
db.exec("INSERT INTO roles (key, rank, label) VALUES ('steward', 35, 'Steward')");

db.exec(`
  INSERT INTO organizations (id,name,theme,max_session_minutes) VALUES ('oa','A','cobalt',45);
  INSERT INTO users (id,email,name,password_hash) VALUES
    ('o1','o1@x.test','O1','x'), ('o2','o2@x.test','O2','x'), ('op','op@x.test','Op','x');
  INSERT INTO memberships (id,org_id,user_id,role,status) VALUES
    ('m1','oa','o1','owner','active'), ('m2','oa','o2','owner','active'), ('m3','oa','op','operator','active');
  INSERT INTO devices (id,org_id,name,kind) VALUES ('d1','oa','d1','linux'), ('d2','oa','d2','linux');
`);

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(58)} ${ok ? '' : `got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};
const outcome = (fn) => {
  try { fn(); return 'ok'; }
  catch (e) { return e instanceof HttpError ? `${e.status} ${e.code}${e.reason ? ' ' + e.reason : ''}` : `${e.constructor.name}: ${e.message}`; }
};

console.log('\n== ranks come from the table ==');
check('six roles including the undocumented one', roleRanks(db).size, 6);
check('steward rank read, not assumed', roleRanks(db).get('steward'), 35);
check('unknown role rejected', outcome(() => assertRoleExists(db, 'superuser')), '400 VALIDATION unknown_role');

console.log('\n== who may modify whom ==');
check('owner -> admin', outcome(() => assertCanModify(db, 'owner', 'admin')), 'ok');
check('admin -> admin (equal)', outcome(() => assertCanModify(db, 'admin', 'admin')), '403 FORBIDDEN insufficient_rank');
check('operator -> auditor (lower rank)', outcome(() => assertCanModify(db, 'operator', 'auditor')), 'ok');
check('operator -> steward (35 > 30)', outcome(() => assertCanModify(db, 'operator', 'steward')), '403 FORBIDDEN insufficient_rank');

console.log('\n== who may assign which role ==');
check('owner assigns owner', outcome(() => assertCanAssign(db, 'owner', 'owner')), 'ok');
check('admin assigns owner', outcome(() => assertCanAssign(db, 'admin', 'owner')), '403 FORBIDDEN insufficient_rank');
check('admin assigns admin', outcome(() => assertCanAssign(db, 'admin', 'admin')), '403 FORBIDDEN insufficient_rank');
check('admin assigns steward', outcome(() => assertCanAssign(db, 'admin', 'steward')), 'ok');

console.log('\n== last owner ==');
check('two active owners: removing one is fine', outcome(() => assertNotLastOwner(db, 'oa', 'o1')), 'ok');
db.exec("UPDATE memberships SET status='suspended' WHERE id='m2'");
check('other owner suspended: o1 is the last active owner', outcome(() => assertNotLastOwner(db, 'oa', 'o1')), '409 LAST_OWNER');
check('non-owner is never the last owner', outcome(() => assertNotLastOwner(db, 'oa', 'op')), 'ok');
db.exec("UPDATE memberships SET status='active' WHERE id='m2'");

console.log('\n== sessions ==');
const insertSession = (id, user, device, mode, expiresAt) =>
  db.prepare(`INSERT INTO sessions (id,org_id,user_id,device_id,mode,state,authorized_by,expires_at)
              VALUES (?, 'oa', ?, ?, ?, 'active', '{}', ?)`).run(id, user, device, mode, expiresAt);
const future = new Date(Date.now() + 3600e3).toISOString();
const past = new Date(Date.now() - 60e3).toISOString();

insertSession('s_old', 'op', 'd1', 'control', past);
check('expired-but-active row blocks a new control session',
  outcome(() => insertSession('s_new', 'op', 'd1', 'control', future)), 'SqliteError: UNIQUE constraint failed: sessions.device_id');
check('expireStaleSessions ends it', expireStaleSessions(db, { orgId: 'oa', deviceId: 'd1' }), 1);
check('...end_reason session_expired', db.prepare("SELECT end_reason FROM sessions WHERE id='s_old'").get().end_reason, 'session_expired');
check('...and the device is free again', outcome(() => insertSession('s_new', 'op', 'd1', 'control', future)), 'ok');

insertSession('s_view', 'op', 'd2', 'view', future);
insertSession('s_o1', 'o1', 'd2', 'view', future);
check('end one user\'s sessions only', endActiveSessions(db, { orgId: 'oa', userId: 'op', reason: 'user_suspended' }), 2);
check('...the other user\'s session is untouched', db.prepare("SELECT state FROM sessions WHERE id='s_o1'").get().state, 'active');
check('refuses to run with no user or device', outcome(() => endActiveSessions(db, { orgId: 'oa', reason: 'admin_terminated' })).startsWith('Error'), true);

check('expiry uses the org\'s 45 minutes', sessionExpiry(db, 'oa', new Date('2026-01-01T00:00:00.000Z')), '2026-01-01T00:45:00.000Z');
const snap = snapshotAuthority(db, { userId: 'op', orgId: 'oa', deviceId: 'd1', now: new Date('2026-01-01T00:00:00.000Z') });
check('snapshot role', snap.role, 'operator');
check('snapshot holds device:control, not audit:read', [snap.permissions.includes('device:control'), snap.permissions.includes('audit:read')], [true, false]);

console.log('\n== audit ==');
const ctx = { orgId: 'oa', userId: 'op', requestId: 'req_1' };
const count = () => db.prepare('SELECT count(*) AS n FROM audit_events').get().n;
audit(db, { orgId: 'oa', actorId: 'o1', action: 'grant.create', result: 'allow' });
check('audit() writes one row', count(), 1);
check('rows cannot be edited', outcome(() => db.exec("UPDATE audit_events SET result='deny'")).includes('append-only'), true);

check('a 403 is recorded and rethrown', outcome(() => auditDenials(db, ctx, { action: 'grant.create' }, () => { throw forbidden('no', 'explicit_deny'); })), '403 FORBIDDEN explicit_deny');
check('...as a deny row with its reason', db.prepare("SELECT result, reason_code, request_id FROM audit_events WHERE action='grant.create' AND result='deny'").get(), { result: 'deny', reason_code: 'explicit_deny', request_id: 'req_1' });
const before = count();
outcome(() => auditDenials(db, ctx, { action: 'x' }, () => { throw notFound(); }));
outcome(() => auditDenials(db, ctx, { action: 'x' }, () => { throw badRequest('bad'); }));
check('404 and 400 are not recorded', count(), before);
check('success writes nothing from the wrapper', (auditDenials(db, ctx, { action: 'x' }, () => 7), count()), before);

const asyncDenied = await auditDenials(db, ctx, { action: 'async.x' }, async () => { throw forbidden('no'); }).catch((e) => e.reason);
check('async 403 rethrown', asyncDenied, 'missing_permission');
check('...and recorded', db.prepare("SELECT count(*) AS n FROM audit_events WHERE action='async.x'").get().n, 1);

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
