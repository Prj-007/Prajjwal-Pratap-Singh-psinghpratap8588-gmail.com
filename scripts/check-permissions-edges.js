// Cases check-permissions.js does not reach: which scope assertMayGrant checks, what the
// org-level union counts, and devices outside the caller's org.
// Run: node scripts/check-permissions-edges.js

import { readFileSync } from 'node:fs';
import { openDatabase } from '../server/db.js';
import { resolve, assertMayGrant } from '../server/permissions.js';

const db = openDatabase(':memory:');
db.exec(readFileSync(new URL('../db/schema.sql', import.meta.url), 'utf8'));
db.exec(readFileSync(new URL('../db/reference.sql', import.meta.url), 'utf8'));

// Two orgs, one device each, and a viewer in org A — the smallest world these cases need.
db.exec(`
  INSERT INTO organizations (id,name,theme) VALUES ('oa','A','cobalt'), ('ob','B','ember');
  INSERT INTO users (id,email,name,password_hash) VALUES
    ('u_own','own@a.test','Own','x'), ('u_view','view@a.test','View','x');
  INSERT INTO memberships (id,org_id,user_id,role,status) VALUES
    ('m1','oa','u_own','owner','active'), ('m2','oa','u_view','viewer','active');
  INSERT INTO devices (id,org_id,name,kind) VALUES
    ('d1','oa','d1','linux'), ('d2','oa','d2','linux'), ('dx','ob','dx','linux');
`);
const grant = (id, device, effect, perm) => {
  db.prepare('INSERT INTO grants (id,org_id,user_id,device_id,effect,created_by) VALUES (?,?,?,?,?,?)')
    .run(id, 'oa', 'u_view', device, effect, 'u_own');
  db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)').run(id, perm);
};

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(60)} ${ok ? '' : `got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};
const mayGrant = (deviceId, patterns) => {
  try { assertMayGrant(db, { userId: 'u_view', orgId: 'oa' }, patterns, deviceId); return 'ok'; }
  catch (e) { return `${e.status} ${e.reason}`; }
};
const at = (perm, deviceId = null) => resolve(db, { userId: 'u_view', orgId: 'oa', deviceId }).permissions[perm];

grant('g_d1_ctl', 'd1', 'allow', 'device:control');

console.log('\n== the org-level union counts a device-scoped allow ==');
check('org level: device:control allowed via the d1 grant', at('device:control'), { effect: 'allow', source: 'grant:g_d1_ctl', reason: null });
check('d2: device:control still implicit deny', at('device:control', 'd2').reason, 'implicit');

console.log('\n== no laundering: an org-wide grant is checked at the org scope, not the union ==');
check('holder on d1 may grant device:control on d1', mayGrant('d1', ['device:control']), 'ok');
check('...may NOT grant it on d2', mayGrant('d2', ['device:control']), '403 missing_permission');
check('...may NOT grant it org-wide', mayGrant(null, ['device:control']), '403 missing_permission');
check('viewer may not grant device:* (holds only some of it)', mayGrant(null, ['device:*']), '403 missing_permission');
check('viewer may grant what the role gives, org-wide', mayGrant(null, ['device:view', 'user:read']), 'ok');

console.log('\n== an org-wide deny is not carved out anywhere ==');
grant('g_deny_view', null, 'deny', 'device:view');
check('org level: explicit_deny', at('device:view').reason, 'explicit_deny');
check('d1: explicit_deny', at('device:view', 'd1').reason, 'explicit_deny');
check('may not grant a permission you are denied', mayGrant('d1', ['device:view']), '403 explicit_deny');

console.log('\n== devices outside the org ==');
check("another org's device: scope_mismatch", at('device:list', 'dx').reason, 'scope_mismatch');
db.exec("UPDATE devices SET deleted_at = '2026-01-01T00:00:00.000Z' WHERE id = 'd1'");
check('soft-deleted device: scope_mismatch', at('device:control', 'd1').reason, 'scope_mismatch');
check('its grant no longer lifts the org-level view', at('device:control').reason, 'implicit');

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
