// Orgs, members and effective permissions.
//
// Every org-level action is checked at the strict org scope (assertCanOrgWide): a grant on
// one device never authorises managing people or the org itself. Every change bumps the
// affected membership's perm_version and writes its audit row in the same transaction;
// refusals are audited by auditDenials.

import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, forbidden, selfRoleChange } from '../http.js';
import { assertCanOrgWide, resolve } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import {
  topRole, assertRoleExists, assertCanModify, assertCanAssign, assertNotLastOwner, endActiveSessions,
} from '../lifecycle.js';
import { myOrgs } from './auth.js';

const DEFAULT_THEME = 'slate';

function memberRow(db, orgId, userId) {
  return db.prepare(
    `SELECT m.user_id AS userId, u.email, u.name, m.role, m.status, m.joined_at AS joinedAt
       FROM memberships m JOIN users u ON u.id = m.user_id
      WHERE m.org_id = ? AND m.user_id = ? AND m.status IN ('active', 'suspended')`
  ).get(orgId, userId);
}

const orgRow = (db, orgId) =>
  db.prepare('SELECT id, name, theme, max_session_minutes AS maxSessionMinutes FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);

function text(value, field, max) {
  if (typeof value !== 'string' || value.trim() === '' || value.trim().length > max) {
    throw badRequest(`${field} must be 1–${max} characters`);
  }
  return value.trim();
}

export function registerOrgRoutes(router, { db }) {
  // Wrap a handler so a 403 inside it lands in the audit log.
  const audited = (meta, handler) => (ctx, params, res) =>
    auditDenials(db, ctx, typeof meta === 'function' ? meta(params) : meta, () => handler(ctx, params, res));

  const record = (ctx, action, targetType, targetId, orgId = ctx.orgId) =>
    audit(db, { orgId, actorId: ctx.userId, action, targetType, targetId, result: 'allow', requestId: ctx.requestId });

  // The member being acted on: visible (else 404), not yourself, and strictly below you.
  function actOn(ctx, userId, permission, selfError) {
    assertCanOrgWide(db, ctx, permission);
    const target = memberRow(db, ctx.orgId, userId);
    if (!target) throw notFound();
    if (target.userId === ctx.userId) throw selfError();
    return target;
  }
  const noSelf = () => forbidden('use DELETE /members/me to act on yourself', 'self');

  // --- orgs --------------------------------------------------------------------

  router.get('/v1/orgs', (ctx, _p, res) => {
    send(res, 200, { orgs: myOrgs(db, ctx.userId).map(({ id, name, theme, role, status }) => ({ id, name, theme, role, status })) });
  });

  router.post('/v1/orgs', (ctx, _p, res) => {
    const name = text(ctx.body.name, 'name', 100);
    const theme = ctx.body.theme === undefined ? DEFAULT_THEME : text(ctx.body.theme, 'theme', 32);
    const id = newId('org');
    const role = topRole(db);
    db.transaction(() => {
      db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)').run(id, name, theme);
      db.prepare(`INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?, ?, ?, ?, 'active', ?)`)
        .run(newId('mem'), id, ctx.userId, role, nowIso());
      record(ctx, 'org.create', 'org', id, id);
    })();
    send(res, 201, { id, name, theme, role });
  });

  router.patch('/v1/orgs/:org', audited({ action: 'org.update', targetType: 'org' }, (ctx, _p, res) => {
    assertCanOrgWide(db, ctx, 'org:update');
    const b = ctx.body;
    const sets = [];
    const args = [];
    if (b.name !== undefined) { sets.push('name = ?'); args.push(text(b.name, 'name', 100)); }
    if (b.theme !== undefined) { sets.push('theme = ?'); args.push(text(b.theme, 'theme', 32)); }
    if (b.maxSessionMinutes !== undefined) {
      if (!Number.isInteger(b.maxSessionMinutes) || b.maxSessionMinutes < 1 || b.maxSessionMinutes > 1440) {
        throw badRequest('maxSessionMinutes must be an integer from 1 to 1440');
      }
      sets.push('max_session_minutes = ?'); args.push(b.maxSessionMinutes);
    }
    if (sets.length === 0) throw badRequest('nothing to update');
    db.transaction(() => {
      db.prepare(`UPDATE organizations SET ${sets.join(', ')} WHERE id = ?`).run(...args, ctx.orgId);
      record(ctx, 'org.update', 'org', ctx.orgId);
    })();
    send(res, 200, orgRow(db, ctx.orgId));
  }));

  router.delete('/v1/orgs/:org', audited({ action: 'org.delete', targetType: 'org' }, (ctx, _p, res) => {
    assertCanOrgWide(db, ctx, 'org:delete');
    db.transaction(() => {
      db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), ctx.orgId);
      endActiveSessions(db, { orgId: ctx.orgId, reason: 'admin_terminated', allInOrg: true });
      record(ctx, 'org.delete', 'org', ctx.orgId);
    })();
    send(res, 200, { id: ctx.orgId, deleted: true });
  }));

  // --- members -----------------------------------------------------------------

  router.get('/v1/orgs/:org/members', audited({ action: 'member.list' }, (ctx, _p, res) => {
    assertCanOrgWide(db, ctx, 'user:read');
    const members = db.prepare(
      `SELECT m.user_id AS userId, u.email, u.name, m.role, m.status, m.joined_at AS joinedAt
         FROM memberships m JOIN users u ON u.id = m.user_id JOIN roles r ON r.key = m.role
        WHERE m.org_id = ? AND m.status IN ('active', 'suspended')
        ORDER BY r.rank DESC, u.name`
    ).all(ctx.orgId);
    send(res, 200, { members });
  }));

  // Registered before '/members/:userId' — first match wins.
  router.delete('/v1/orgs/:org/members/me', audited({ action: 'member.leave', targetType: 'user' }, (ctx, _p, res) => {
    db.transaction(() => {
      assertNotLastOwner(db, ctx.orgId, ctx.userId);
      db.prepare(`UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?`).run(ctx.orgId, ctx.userId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: ctx.userId });
      endActiveSessions(db, { orgId: ctx.orgId, userId: ctx.userId, reason: 'membership_removed' });
      record(ctx, 'member.leave', 'user', ctx.userId);
    })();
    send(res, 200, { userId: ctx.userId, status: 'removed' });
  }));

  router.patch('/v1/orgs/:org/members/:userId', audited((p) => ({ action: 'member.role.update', targetType: 'user', targetId: p.userId }), (ctx, p, res) => {
    const target = actOn(ctx, p.userId, 'user:role:update', selfRoleChange);
    const role = ctx.body.role;
    assertRoleExists(db, role);
    assertCanModify(db, ctx.role, target.role);
    assertCanAssign(db, ctx.role, role);
    db.transaction(() => {
      if (role !== target.role) assertNotLastOwner(db, ctx.orgId, target.userId);
      db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(role, ctx.orgId, target.userId);
      // A role change is a permission change: it blocks the next request, not the live session.
      bumpPermVersion(db, { orgId: ctx.orgId, userId: target.userId });
      record(ctx, 'member.role.update', 'user', target.userId);
    })();
    send(res, 200, memberRow(db, ctx.orgId, target.userId));
  }));

  router.post('/v1/orgs/:org/members/:userId/suspend', audited((p) => ({ action: 'member.suspend', targetType: 'user', targetId: p.userId }), (ctx, p, res) => {
    const target = actOn(ctx, p.userId, 'user:remove', noSelf);
    assertCanModify(db, ctx.role, target.role);
    db.transaction(() => {
      assertNotLastOwner(db, ctx.orgId, target.userId);
      db.prepare(`UPDATE memberships SET status = 'suspended' WHERE org_id = ? AND user_id = ?`).run(ctx.orgId, target.userId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: target.userId });
      // A tenancy event, not a permission tweak: live sessions end now.
      endActiveSessions(db, { orgId: ctx.orgId, userId: target.userId, reason: 'user_suspended' });
      record(ctx, 'member.suspend', 'user', target.userId);
    })();
    send(res, 200, memberRow(db, ctx.orgId, target.userId));
  }));

  router.delete('/v1/orgs/:org/members/:userId/suspend', audited((p) => ({ action: 'member.reinstate', targetType: 'user', targetId: p.userId }), (ctx, p, res) => {
    const target = actOn(ctx, p.userId, 'user:remove', noSelf);
    assertCanModify(db, ctx.role, target.role);
    db.transaction(() => {
      db.prepare(`UPDATE memberships SET status = 'active' WHERE org_id = ? AND user_id = ?`).run(ctx.orgId, target.userId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: target.userId });
      record(ctx, 'member.reinstate', 'user', target.userId);
    })();
    send(res, 200, memberRow(db, ctx.orgId, target.userId));
  }));

  router.delete('/v1/orgs/:org/members/:userId', audited((p) => ({ action: 'member.remove', targetType: 'user', targetId: p.userId }), (ctx, p, res) => {
    const target = actOn(ctx, p.userId, 'user:remove', noSelf);
    assertCanModify(db, ctx.role, target.role);
    db.transaction(() => {
      assertNotLastOwner(db, ctx.orgId, target.userId);
      db.prepare(`UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?`).run(ctx.orgId, target.userId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: target.userId });
      endActiveSessions(db, { orgId: ctx.orgId, userId: target.userId, reason: 'membership_removed' });
      record(ctx, 'member.remove', 'user', target.userId);
    })();
    send(res, 200, { userId: target.userId, status: 'removed' });
  }));

  // --- audit -----------------------------------------------------------------------

  // limit 1–500 (default 50), offset ≥ 0 (default 0). Out of range is a 400, not a silent
  // clamp; an offset past the end is simply an empty page.
  function pageParam(ctx, key, fallback, min, max) {
    const raw = ctx.query.get(key);
    if (raw === null) return fallback;
    if (!/^-?\d+$/.test(raw)) throw badRequest(`${key} must be an integer`);
    const n = Number(raw);
    if (n < min || n > max) throw badRequest(`${key} must be between ${min} and ${max}`);
    return n;
  }

  router.get('/v1/orgs/:org/audit', audited({ action: 'audit.read' }, (ctx, _p, res) => {
    assertCanOrgWide(db, ctx, 'audit:read');
    const limit = pageParam(ctx, 'limit', 50, 1, 500);
    const offset = pageParam(ctx, 'offset', 0, 0, Number.MAX_SAFE_INTEGER);
    const events = db.prepare(
      `SELECT id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at
         FROM audit_events WHERE org_id = ? ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`
    ).all(ctx.orgId, limit, offset);
    const { total } = db.prepare('SELECT count(*) AS total FROM audit_events WHERE org_id = ?').get(ctx.orgId);
    send(res, 200, { events, limit, offset, total });
  }));

  // --- effective permissions -----------------------------------------------------

  // Org-level by default; ?deviceId= gives the exact per-device set.
  router.get('/v1/orgs/:org/users/:userId/effective', audited((p) => ({ action: 'user.effective.read', targetType: 'user', targetId: p.userId }), (ctx, p, res) => {
    if (p.userId !== ctx.userId) assertCanOrgWide(db, ctx, 'user:read');
    const target = memberRow(db, ctx.orgId, p.userId);
    if (!target) throw notFound();
    const deviceId = ctx.query.get('deviceId');
    if (deviceId !== null && !db.prepare('SELECT 1 FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, ctx.orgId)) {
      throw notFound();
    }
    const { role, permissions } = resolve(db, { userId: p.userId, orgId: ctx.orgId, deviceId });
    send(res, 200, { userId: p.userId, role, permissions });
  }));
}
