// Grants: create, list, revoke.
//
// Validation runs in the order of AUTH-DATA-MODEL.md §8. Creating or revoking a grant bumps
// the grantee's perm_version, so their next request re-resolves; sessions already running
// are not touched (grandfathered).

import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, forbidden, normalizeTs, HttpError } from '../http.js';
import { assertCan, assertCanOrgWide, assertMayGrant } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';

const grantExpired = () => new HttpError(400, 'GRANT_EXPIRED', 'the grant would already be expired', 'expired_grant');

function grantRows(db, orgId, where = '', args = []) {
  const rows = db.prepare(
    `SELECT g.id, g.user_id AS userId, g.device_id AS deviceId, g.effect, g.starts_at AS startsAt,
            g.expires_at AS expiresAt, g.created_by AS createdBy, g.created_at AS createdAt,
            group_concat(gp.permission, ' ') AS perms
       FROM grants g JOIN grant_permissions gp ON gp.grant_id = g.id
      WHERE g.org_id = ? AND g.revoked_at IS NULL ${where}
      GROUP BY g.id
      ORDER BY g.created_at, g.id`
  ).all(orgId, ...args);
  return rows.map(({ perms, ...g }) => ({ ...g, permissions: perms.split(' ').sort() }));
}

export function registerGrantRoutes(router, { db }) {
  const audited = (meta, handler) => (ctx, params, res) =>
    auditDenials(db, ctx, typeof meta === 'function' ? meta(params) : meta, () => handler(ctx, params, res));
  const record = (ctx, action, targetId) =>
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action, targetType: 'grant', targetId, result: 'allow', requestId: ctx.requestId });

  // Grant management on one device needs the permission on that device; org-wide needs it org-wide.
  const need = (ctx, permission, deviceId) =>
    (deviceId ? assertCan(db, ctx, permission, deviceId) : assertCanOrgWide(db, ctx, permission));

  router.post('/v1/orgs/:org/grants', audited({ action: 'grant.create', targetType: 'grant' }, (ctx, _p, res) => {
    const { userId, effect, permissions } = ctx.body;
    const deviceId = ctx.body.deviceId ?? null;
    if (deviceId !== null && typeof deviceId !== 'string') throw badRequest('deviceId must be a string');
    const device = deviceId === null ? null
      : db.prepare('SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, ctx.orgId);
    // A device outside this org is judged at the org scope here and then 404s below, so the
    // answer never depends on whether the id exists elsewhere.
    need(ctx, 'grant:create', device ? deviceId : null);

    if (!Array.isArray(permissions) || permissions.length === 0 || !permissions.every((p) => typeof p === 'string')) {
      throw badRequest('permissions must be a non-empty list of strings');
    }
    if (effect !== 'allow' && effect !== 'deny') throw badRequest("effect must be 'allow' or 'deny'");

    // Checked here so the answer is a clear 400 naming the pattern; the grant_permissions
    // foreign key still backs it up if this list and the table ever disagree.
    const unique = [...new Set(permissions)];
    const known = new Set(db.prepare(`SELECT pattern FROM permission_patterns WHERE pattern IN (${unique.map(() => '?').join(',')})`).all(...unique).map((r) => r.pattern));
    const unknown = unique.filter((p) => !known.has(p));
    if (unknown.length) throw badRequest(`unknown permission: ${unknown.join(', ')}`, 'unknown_permission');

    if (deviceId !== null && !device) throw notFound();
    if (typeof userId !== 'string' || !db.prepare(`SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`).get(ctx.orgId, userId)) throw notFound();
    if (userId === ctx.userId) throw forbidden('you cannot grant to yourself', 'self_grant');

    const startsAt = normalizeTs(ctx.body.startsAt, 'startsAt');
    const expiresAt = normalizeTs(ctx.body.expiresAt, 'expiresAt');
    if (expiresAt !== null && expiresAt <= nowIso()) throw grantExpired();
    if (startsAt !== null && expiresAt !== null && expiresAt <= startsAt) throw badRequest('expiresAt must be after startsAt');

    assertMayGrant(db, ctx, unique, deviceId);

    const id = newId('grt');
    db.transaction(() => {
      db.prepare(
        `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(id, ctx.orgId, userId, deviceId, effect, startsAt, expiresAt, ctx.userId);
      const add = db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)');
      for (const p of unique) add.run(id, p);
      bumpPermVersion(db, { orgId: ctx.orgId, userId });
      record(ctx, 'grant.create', id);
    })();
    send(res, 201, grantRows(db, ctx.orgId, 'AND g.id = ?', [id])[0]);
  }));

  router.get('/v1/orgs/:org/grants', audited({ action: 'grant.list' }, (ctx, _p, res) => {
    assertCanOrgWide(db, ctx, 'user:read');
    const userId = ctx.query.get('userId');
    const grants = userId === null ? grantRows(db, ctx.orgId) : grantRows(db, ctx.orgId, 'AND g.user_id = ?', [userId]);
    send(res, 200, { grants });
  }));

  router.delete('/v1/orgs/:org/grants/:id', audited((p) => ({ action: 'grant.revoke', targetType: 'grant', targetId: p.id }), (ctx, p, res) => {
    // Revoked, missing or another org's: all the same 404.
    const g = db.prepare('SELECT id, user_id, device_id FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL').get(p.id, ctx.orgId);
    if (!g) throw notFound();
    need(ctx, 'grant:revoke', g.device_id);
    db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), g.id);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: g.user_id });
      record(ctx, 'grant.revoke', g.id);
    })();
    send(res, 200, { id: g.id, revoked: true });
  }));
}
