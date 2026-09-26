// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// The rules more than one route needs live here, so "what ends a session" has exactly
// one implementation.
//
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. Nothing here answers a can() question.
//   - a permission change does NOT end a session in flight. Suspension, membership removal
//     and device transfer DO — the routes for those call endActiveSessions.
//
// No role key is written down here. "Owner" means the highest-ranked role in `roles`,
// so the rules follow whatever the database holds.

import { nowIso } from './db.js';
import { badRequest, forbidden, lastOwner } from './http.js';
import { resolve } from './permissions.js';

export function roleRanks(db) {
  return new Map(db.prepare('SELECT key, rank FROM roles').all().map((r) => [r.key, r.rank]));
}

const topRole = (db) => db.prepare('SELECT key FROM roles ORDER BY rank DESC LIMIT 1').get()?.key;

export function assertRoleExists(db, role) {
  if (typeof role !== 'string' || !roleRanks(db).has(role)) throw badRequest(`unknown role: ${role}`, 'unknown_role');
}

// You may act on a member only if your role ranks strictly above theirs. Equal is refused
// (admin cannot modify admin).
export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);
  if (!ranks.has(callerRole) || !ranks.has(targetRole) || ranks.get(callerRole) <= ranks.get(targetRole)) {
    throw forbidden(`a ${callerRole} cannot modify a ${targetRole}`, 'insufficient_rank');
  }
}

// You may hand out (by invite or role change) only roles below your own — except the top
// role, which may create more of itself. So owners can make owners; an admin cannot make
// an admin, because the two could then never act on each other.
export function assertCanAssign(db, callerRole, newRole) {
  assertRoleExists(db, newRole);
  const ranks = roleRanks(db);
  const mine = ranks.get(callerRole);
  if (mine === undefined) throw forbidden(`a ${callerRole} cannot assign roles`, 'insufficient_rank');
  if (ranks.get(newRole) < mine) return;
  if (newRole === callerRole && callerRole === topRole(db)) return;
  throw forbidden(`a ${callerRole} cannot assign ${newRole}`, 'insufficient_rank');
}

// Throws if removing, suspending or demoting userId would leave the org with no active
// owner. Only active owners count: a suspended owner cannot act for the org.
// Call it inside the same transaction as the change so the count cannot go stale.
export function assertNotLastOwner(db, orgId, userId) {
  const owner = topRole(db);
  const { others } = db.prepare(
    `SELECT count(*) AS others FROM memberships
      WHERE org_id = ? AND role = ? AND status = 'active' AND user_id <> ?`
  ).get(orgId, owner, userId);
  const target = db.prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);
  if (target && target.role === owner && target.status === 'active' && others === 0) throw lastOwner();
}

// End live sessions matching the filter. At least a user or a device is required, so a
// missing argument can never end every session in the org. Returns how many ended.
export function endActiveSessions(db, { orgId, userId = null, deviceId = null, reason, exceptSessionId = null }) {
  if (!orgId || (!userId && !deviceId)) throw new Error('endActiveSessions needs orgId and a userId or deviceId');
  const at = nowIso();
  return db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
      WHERE org_id = ? AND state IN ('connecting', 'active')
        AND (? IS NULL OR user_id = ?)
        AND (? IS NULL OR device_id = ?)
        AND (? IS NULL OR id <> ?)`
  ).run(reason, at, orgId, userId, userId, deviceId, deviceId, exceptSessionId, exceptSessionId).changes;
}

// A session past its expires_at is over even if nothing has marked it so. Until it is
// marked, its row still says 'active' and keeps holding one_exclusive_session_per_device,
// so the device would read DEVICE_BUSY forever. Run this before starting or listing sessions.
export function expireStaleSessions(db, { orgId, deviceId = null }) {
  const at = nowIso();
  return db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = 'session_expired', ended_at = expires_at
      WHERE org_id = ? AND state IN ('connecting', 'active') AND expires_at <= ?
        AND (? IS NULL OR device_id = ?)`
  ).run(orgId, at, deviceId, deviceId).changes;
}

// The authority a session starts with, frozen: the role, the grants that decided any
// answer on this device, and the permissions that were allowed. Same shape as the seed
// fixture's authorizedBy, plus `permissions`.
export function snapshotAuthority(db, { userId, orgId, deviceId, now = new Date() }) {
  const { role, permissions } = resolve(db, { userId, orgId, deviceId, now });
  const answers = Object.entries(permissions);
  const grantIds = [...new Set(answers.map(([, a]) => a.source).filter((s) => s?.startsWith('grant:')).map((s) => s.slice(6)))];
  return {
    role,
    grantIds,
    permissions: answers.filter(([, a]) => a.effect === 'allow').map(([k]) => k),
    snapshotAt: now.toISOString(),
  };
}

// expires_at for a session starting at `now`: now + the org's max_session_minutes.
export function sessionExpiry(db, orgId, now = new Date()) {
  const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  const minutes = org?.max_session_minutes ?? 60;
  return new Date(now.getTime() + minutes * 60_000).toISOString();
}
