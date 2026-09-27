// Devices.
//
// `device:list` gates the list; `device:view` decides whether a device is in it — and a
// device you cannot view is a 404 everywhere else too, never a 403 that confirms it exists.
// Each row carries the caller's resolved permissions for that device, so the console never
// asks per row and never re-derives anything.

import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, conflict } from '../http.js';
import { assertCan, assertCanOrgWide, resolve, resolveDevices } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { endActiveSessions } from '../lifecycle.js';

const shape = (d, permissions) => ({ id: d.id, name: d.name, kind: d.kind, online: d.online === 1, permissions });

const liveDevice = (db, orgId, id) =>
  db.prepare('SELECT id, name, kind, online FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(id, orgId);

function name(value) {
  if (typeof value !== 'string' || value.trim() === '' || value.trim().length > 64) throw badRequest('name must be 1–64 characters');
  return value.trim();
}

// Names are unique among an org's live devices. The schema has no index for it, so this
// check runs inside the same transaction as the write; better-sqlite3 runs one transaction
// at a time in this process, so it cannot race.
function assertNameFree(db, orgId, n, exceptId = null) {
  const clash = db.prepare(
    'SELECT 1 FROM devices WHERE org_id = ? AND name = ? AND deleted_at IS NULL AND (? IS NULL OR id <> ?)'
  ).get(orgId, n, exceptId, exceptId);
  if (clash) throw conflict(`a device named ${n} already exists`);
}

export function registerDeviceRoutes(router, { db }) {
  const audited = (meta, handler) => (ctx, params, res) =>
    auditDenials(db, ctx, typeof meta === 'function' ? meta(params) : meta, () => handler(ctx, params, res));
  const record = (ctx, action, targetId, orgId = ctx.orgId) =>
    audit(db, { orgId, actorId: ctx.userId, action, targetType: 'device', targetId, result: 'allow', requestId: ctx.requestId });

  // The device, if it exists in this org and the caller may view it; otherwise 404.
  function visible(ctx, id) {
    const d = liveDevice(db, ctx.orgId, id);
    if (!d) throw notFound();
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: id });
    if (permissions['device:view'].effect !== 'allow') throw notFound();
    return { device: d, permissions };
  }

  router.get('/v1/orgs/:org/devices', audited({ action: 'device.list' }, (ctx, _p, res) => {
    assertCan(db, ctx, 'device:list');
    const rows = db.prepare('SELECT id, name, kind, online FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name').all(ctx.orgId);
    const { byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: ctx.orgId, deviceIds: rows.map((d) => d.id) });
    const devices = rows
      .filter((d) => byDevice[d.id]['device:view'].effect === 'allow')
      .map((d) => shape(d, byDevice[d.id]));
    send(res, 200, { devices });
  }));

  router.get('/v1/orgs/:org/devices/:id', (ctx, p, res) => {
    const { device, permissions } = visible(ctx, p.id);
    send(res, 200, shape(device, permissions));
  });

  router.post('/v1/orgs/:org/devices', audited({ action: 'device.create', targetType: 'device' }, (ctx, _p, res) => {
    assertCanOrgWide(db, ctx, 'device:provision');
    const n = name(ctx.body.name);
    const id = newId('dev');
    db.transaction(() => {
      assertNameFree(db, ctx.orgId, n);
      try {
        db.prepare('INSERT INTO devices (id, org_id, name, kind, online) VALUES (?, ?, ?, ?, ?)')
          .run(id, ctx.orgId, n, ctx.body.kind, ctx.body.online ? 1 : 0);
      } catch (err) {
        // The schema's CHECK is the list of kinds; it is not repeated here.
        if (err.code === 'SQLITE_CONSTRAINT_CHECK' || err.code === 'SQLITE_CONSTRAINT_NOTNULL') throw badRequest('kind is not a supported device kind');
        throw err;
      }
      record(ctx, 'device.create', id);
    })();
    const { device, permissions } = visible(ctx, id);
    send(res, 201, shape(device, permissions));
  }));

  router.patch('/v1/orgs/:org/devices/:id', audited((p) => ({ action: 'device.update', targetType: 'device', targetId: p.id }), (ctx, p, res) => {
    visible(ctx, p.id);
    assertCan(db, ctx, 'device:update', p.id);
    const sets = [];
    const args = [];
    if (ctx.body.name !== undefined) { sets.push('name = ?'); args.push(name(ctx.body.name)); }
    if (ctx.body.online !== undefined) {
      if (typeof ctx.body.online !== 'boolean') throw badRequest('online must be true or false');
      sets.push('online = ?'); args.push(ctx.body.online ? 1 : 0);
    }
    if (sets.length === 0) throw badRequest('nothing to update');
    db.transaction(() => {
      if (ctx.body.name !== undefined) assertNameFree(db, ctx.orgId, args[0], p.id);
      db.prepare(`UPDATE devices SET ${sets.join(', ')} WHERE id = ?`).run(...args, p.id);
      record(ctx, 'device.update', p.id);
    })();
    const { device, permissions } = visible(ctx, p.id);
    send(res, 200, shape(device, permissions));
  }));

  // Decommission: soft delete, and live sessions on it end — a tenancy event, not a
  // permission change.
  router.delete('/v1/orgs/:org/devices/:id', audited((p) => ({ action: 'device.delete', targetType: 'device', targetId: p.id }), (ctx, p, res) => {
    visible(ctx, p.id);
    assertCan(db, ctx, 'device:provision', p.id);
    db.transaction(() => {
      db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), p.id);
      endActiveSessions(db, { orgId: ctx.orgId, deviceId: p.id, reason: 'device_transferred' });
      record(ctx, 'device.delete', p.id);
    })();
    send(res, 200, { id: p.id, deleted: true });
  }));

  // Transfer needs device:provision on this device here, and org-wide in the target org.
  // The caller's token is for this org only, so the target membership is looked up directly.
  router.post('/v1/orgs/:org/devices/:id/transfer', audited((p) => ({ action: 'device.transfer', targetType: 'device', targetId: p.id }), (ctx, p, res) => {
    visible(ctx, p.id);
    assertCan(db, ctx, 'device:provision', p.id);
    const to = ctx.body.toOrgId;
    if (typeof to !== 'string' || to === '') throw badRequest('toOrgId is required');
    if (to === ctx.orgId) throw badRequest('the device is already in that org');
    const there = db.prepare(
      `SELECT m.status FROM memberships m JOIN organizations o ON o.id = m.org_id
        WHERE m.org_id = ? AND m.user_id = ? AND o.deleted_at IS NULL`
    ).get(to, ctx.userId);
    if (!there || there.status !== 'active') throw notFound();
    assertCanOrgWide(db, { userId: ctx.userId, orgId: to }, 'device:provision');

    db.transaction(() => {
      const d = liveDevice(db, ctx.orgId, p.id);
      assertNameFree(db, to, d.name);
      endActiveSessions(db, { orgId: ctx.orgId, deviceId: p.id, reason: 'device_transferred' });
      // Grants in the old org that name this device must not follow it — revoke them and
      // bump the holders' versions so their next request re-resolves.
      const affected = db.prepare('SELECT DISTINCT user_id FROM grants WHERE org_id = ? AND device_id = ? AND revoked_at IS NULL').all(ctx.orgId, p.id);
      db.prepare('UPDATE grants SET revoked_at = ? WHERE org_id = ? AND device_id = ? AND revoked_at IS NULL').run(nowIso(), ctx.orgId, p.id);
      for (const { user_id } of affected) bumpPermVersion(db, { orgId: ctx.orgId, userId: user_id });
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(to, p.id);
      record(ctx, 'device.transfer', p.id);
      record(ctx, 'device.transfer', p.id, to);
    })();
    send(res, 200, { id: p.id, orgId: to });
  }));
}
