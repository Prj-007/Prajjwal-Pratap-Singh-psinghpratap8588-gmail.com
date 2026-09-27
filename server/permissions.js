// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Everything is read from the database on every call: the catalogue (`permissions`),
// the role baseline (`role_permissions`), the membership and the grants. Nothing about
// the documented 5-role / 19-permission matrix is written down here.
//
// One function, `evaluate`, produces every answer. The exported functions are views of it.

import { forbidden, badRequest } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// --- reading the database ------------------------------------------------------

const catalogue = (db) => db.prepare('SELECT key FROM permissions ORDER BY key').all().map((r) => r.key);

// A soft-deleted org is as invisible as one you are not a member of.
function membership(db, userId, orgId) {
  return db.prepare(
    `SELECT m.role, m.status, m.perm_version
       FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.org_id = ? AND m.user_id = ? AND o.deleted_at IS NULL`
  ).get(orgId, userId);
}

const baseline = (db, role) =>
  new Set(db.prepare('SELECT permission FROM role_permissions WHERE role = ?').all(role).map((r) => r.permission));

// Grants in force right now: not revoked, inside [starts_at, expires_at), and — if
// device-scoped — on a live device of this same org. The schema does not tie
// grants.device_id to grants.org_id, so that join is what keeps a grant from reaching
// across orgs. Timestamps are canonical ISO-8601 'Z' strings, so text comparison is time order.
function activeGrants(db, userId, orgId, now) {
  const at = now.toISOString();
  return db.prepare(
    `SELECT g.id, g.device_id, g.effect, gp.permission
       FROM grants g
       JOIN grant_permissions gp ON gp.grant_id = g.id
       LEFT JOIN devices d ON d.id = g.device_id
      WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
        AND (g.starts_at  IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR g.expires_at > ?)
        AND (g.device_id IS NULL OR (d.org_id = g.org_id AND d.deleted_at IS NULL))
      ORDER BY g.created_at, g.id`
  ).all(userId, orgId, at, at);
}

const liveDevice = (db, orgId, deviceId) =>
  !!db.prepare('SELECT 1 FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, orgId);

// '*' covers the whole catalogue, 'device:*' every key under 'device:', anything else itself.
function expand(pattern, keys) {
  if (pattern === '*') return keys;
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1);
    return keys.filter((k) => k.startsWith(prefix));
  }
  return keys.includes(pattern) ? [pattern] : [];
}

// --- the engine ----------------------------------------------------------------

const answer = (effect, source, reason) => ({ effect, source, reason });
const everything = (keys, a) => Object.fromEntries(keys.map((k) => [k, a]));

// Decide one permission from the grants that apply to one scope.
// Deny first, and a deny from any applicable scope wins (D1): a device-scoped allow
// cannot carve a hole in an org-wide deny.
function decide(permission, grants, roleKey, roleSet) {
  const deny = grants.find((g) => g.effect === 'deny' && g.covers.has(permission));
  if (deny) return answer('deny', `grant:${deny.id}`, 'explicit_deny');
  if (roleSet.has(permission)) return answer('allow', `role:${roleKey}`, null);
  const allow = grants.find((g) => g.effect === 'allow' && g.covers.has(permission));
  if (allow) return answer('allow', `grant:${allow.id}`, null);
  return answer('deny', null, 'implicit');
}

// Load everything one user needs in one org, once. Returns null for "not a member".
function load(db, userId, orgId, now) {
  const keys = catalogue(db);
  const m = membership(db, userId, orgId);
  if (!m || m.status === 'removed' || m.status === 'invited') return { keys, m: null };
  if (m.status === 'suspended') return { keys, m };

  // Group rows (one per grant × permission) back into grants, with the patterns expanded.
  const byId = new Map();
  for (const row of activeGrants(db, userId, orgId, now)) {
    let g = byId.get(row.id);
    if (!g) byId.set(row.id, (g = { id: row.id, deviceId: row.device_id, effect: row.effect, covers: new Set() }));
    for (const k of expand(row.permission, keys)) g.covers.add(k);
  }
  return { keys, m, roleSet: baseline(db, m.role), grants: [...byId.values()] };
}

// scope: 'device' — exactly one device: org-wide grants plus that device's grants.
//        'org'    — the org itself: org-wide grants only. Used for granting org-wide.
//        'union'  — the org-level view for navigation: allowed if the org scope allows,
//                   or any one live device does.
function evaluate(ctx, scope, deviceId) {
  const { keys, m, roleSet, grants } = ctx;
  if (!m) return { role: null, permissions: everything(keys, answer('deny', null, 'not_a_member')) };
  if (m.status === 'suspended') return { role: m.role, permissions: everything(keys, answer('deny', null, 'suspended')) };

  const orgWide = grants.filter((g) => g.deviceId === null);
  const at = (id) => grants.filter((g) => g.deviceId === null || g.deviceId === id);

  const permissions = {};
  for (const k of keys) {
    if (scope === 'device') {
      permissions[k] = decide(k, at(deviceId), m.role, roleSet);
    } else if (scope === 'org') {
      permissions[k] = decide(k, orgWide, m.role, roleSet);
    } else {
      let result = decide(k, orgWide, m.role, roleSet);
      if (result.effect === 'deny' && result.reason === 'implicit') {
        // Only devices with a grant of their own can differ from the org scope.
        for (const id of new Set(grants.filter((g) => g.deviceId !== null).map((g) => g.deviceId))) {
          const onDevice = decide(k, at(id), m.role, roleSet);
          if (onDevice.effect === 'allow') { result = onDevice; break; }
        }
      }
      permissions[k] = result;
    }
  }
  return { role: m.role, permissions };
}

// --- public API ----------------------------------------------------------------

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const ctx = load(db, userId, orgId, now);
  if (deviceId === null) return evaluate(ctx, 'union');
  // A device that is not a live device of this org has no permissions on it at all.
  if (ctx.m && ctx.m.status === 'active' && !liveDevice(db, orgId, deviceId)) {
    return { role: ctx.m.role, permissions: everything(ctx.keys, answer('deny', null, 'scope_mismatch')) };
  }
  return evaluate(ctx, 'device', deviceId);
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
// Same queries as one resolve() regardless of how many devices — no per-row lookups.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const ctx = load(db, userId, orgId, now);
  const byDevice = {};
  let role = ctx.m ? ctx.m.role : null;
  for (const id of deviceIds) byDevice[id] = evaluate(ctx, 'device', id).permissions;
  return { role, byDevice };
}

const lookup = (db, ctx, permission, deviceId) =>
  resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: deviceId ?? null, now: ctx.now ?? new Date() })
    .permissions[permission] ?? answer('deny', null, 'implicit');

export function can(db, ctx, permission, deviceId) {
  return lookup(db, ctx, permission, deviceId).effect === 'allow';
}

// The API reports `missing_permission` for "nobody granted it"; every other reason passes through.
const refusal = (a) => (a.reason === 'implicit' ? 'missing_permission' : a.reason);

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId) {
  const a = lookup(db, ctx, permission, deviceId);
  if (a.effect !== 'allow') throw forbidden(`${permission} is not allowed`, refusal(a));
}

// The strict org scope: org-wide grants and the role only, never "some device allows".
// For actions that are not about one existing device (creating one, transferring into an
// org) — the union would let a single device-scoped grant act for the whole org.
export function assertCanOrgWide(db, ctx, permission) {
  const loaded = load(db, ctx.userId, ctx.orgId, ctx.now ?? new Date());
  const a = evaluate(loaded, 'org').permissions[permission] ?? answer('deny', null, 'implicit');
  if (a.effect !== 'allow') throw forbidden(`${permission} is not allowed org-wide`, refusal(a));
}

// No privilege laundering: you may only grant authority you hold at that scope.
// An org-wide grant is checked against the org scope ONLY — not the union — or a caller
// allowed on a single device could hand the same permission out across the whole org.
// Unknown patterns are not judged here; the grant_permissions foreign key rejects them.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const now = ctx.now ?? new Date();
  const loaded = load(db, ctx.userId, ctx.orgId, now);
  const held = deviceId === null ? evaluate(loaded, 'org') : evaluate(loaded, 'device', deviceId);
  for (const pattern of patterns) {
    for (const k of expand(pattern, loaded.keys)) {
      const a = held.permissions[k];
      if (a.effect !== 'allow') throw forbidden(`you cannot grant ${k} at this scope`, refusal(a));
    }
  }
}

// The compound check: session:start AND the permission for the requested mode, and a
// refusal must distinguish WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const needed = MODE_PERMISSION[mode];
  if (!needed) throw badRequest(`mode must be one of ${Object.keys(MODE_PERMISSION).join(', ')}`);
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId, now: ctx.now ?? new Date() });
  const start = permissions['session:start'];
  if (start.reason === 'suspended' || start.reason === 'not_a_member') throw forbidden('no access to this org', start.reason);
  if (start.effect !== 'allow') throw forbidden('you cannot start sessions', 'missing_permission');
  if (permissions[needed].effect !== 'allow') throw forbidden(`${needed} is not allowed on this device`, 'missing_device_permission');
}
