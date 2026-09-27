// Sessions: start, list, read, end.
//
// A session's authority is snapshotted when it starts (authorized_by) and never re-checked:
// permission changes do not end it; its expires_at does. Exclusivity for control/terminal is
// the partial unique index one_exclusive_session_per_device — the insert is the check.

import { newId, nowIso } from '../db.js';
import { send, badRequest, notFound, forbidden, deviceBusy } from '../http.js';
import { assertCan, assertCanStartSession, can, resolve } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { expireStaleSessions, snapshotAuthority, sessionExpiry } from '../lifecycle.js';

const shape = (row) => row && ({ ...row, authorized_by: JSON.parse(row.authorized_by) });

const SESSION_COLUMNS = 'id, org_id, user_id, device_id, mode, state, end_reason, authorized_by, started_at, expires_at, ended_at';

export function registerSessionRoutes(router, { db }) {
  const audited = (meta, handler) => (ctx, params, res) =>
    auditDenials(db, ctx, typeof meta === 'function' ? meta(params) : meta, () => handler(ctx, params, res));
  const record = (ctx, action, targetId) =>
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action, targetType: 'session', targetId, result: 'allow', requestId: ctx.requestId });

  const byId = (id) => db.prepare(`SELECT ${SESSION_COLUMNS} FROM sessions WHERE id = ?`).get(id);

  // A session is addressed without an org in the path, so it must belong to the token's org;
  // one from another org is the same 404 as one that does not exist.
  function inMyOrg(ctx, id) {
    const s = byId(id);
    if (!s || s.org_id !== ctx.orgId) throw notFound();
    if (expireStaleSessions(db, { orgId: ctx.orgId, deviceId: s.device_id })) return byId(id);
    return s;
  }

  router.post('/v1/orgs/:org/sessions', audited({ action: 'session.start', targetType: 'device' }, (ctx, _p, res) => {
    const { deviceId, mode } = ctx.body;
    if (typeof deviceId !== 'string' || deviceId === '') throw badRequest('deviceId is required');
    if (typeof mode !== 'string') throw badRequest('mode is required');
    const device = db.prepare('SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, ctx.orgId);
    if (!device) throw notFound();
    // A device you cannot view is invisible here too — same 404 as the device routes.
    if (resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions['device:view'].effect !== 'allow') throw notFound();

    assertCanStartSession(db, ctx, mode, deviceId);

    const id = newId('ses');
    const now = new Date();
    try {
      db.transaction(() => {
        // Expired rows still say 'active' and would hold the exclusive index forever.
        expireStaleSessions(db, { orgId: ctx.orgId, deviceId });
        db.prepare(
          `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
           VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`
        ).run(id, ctx.orgId, ctx.userId, deviceId, mode,
          JSON.stringify(snapshotAuthority(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId, now })),
          now.toISOString(), sessionExpiry(db, ctx.orgId, now));
        record(ctx, 'session.start', id);
      })();
    } catch (err) {
      if (err.code !== 'SQLITE_CONSTRAINT_UNIQUE') throw err;
      const holder = db.prepare(
        `SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control', 'terminal')`
      ).get(deviceId);
      throw deviceBusy(`device already has an exclusive session: ${holder?.id ?? 'unknown'}`);
    }
    send(res, 201, shape(byId(id)));
  }));

  router.get('/v1/orgs/:org/sessions', audited({ action: 'session.list' }, (ctx, _p, res) => {
    assertCan(db, ctx, 'session:view');
    expireStaleSessions(db, { orgId: ctx.orgId });
    const sessions = db.prepare(
      `SELECT ${SESSION_COLUMNS} FROM sessions WHERE org_id = ?
        ORDER BY state = 'active' DESC, started_at DESC LIMIT 200`
    ).all(ctx.orgId).map(shape);
    send(res, 200, { sessions });
  }));

  // Readable by its participant, or with session:view on its device.
  router.get('/v1/sessions/:id', audited((p) => ({ action: 'session.read', targetType: 'session', targetId: p.id }), (ctx, p, res) => {
    const s = inMyOrg(ctx, p.id);
    if (s.user_id !== ctx.userId && !can(db, ctx, 'session:view', s.device_id)) {
      throw forbidden('you cannot view this session', 'missing_permission');
    }
    send(res, 200, shape(s));
  }));

  // Your own session, or anyone's with session:terminate on its device.
  router.delete('/v1/sessions/:id', audited((p) => ({ action: 'session.end', targetType: 'session', targetId: p.id }), (ctx, p, res) => {
    const s = inMyOrg(ctx, p.id);
    const mine = s.user_id === ctx.userId;
    if (!mine) assertCan(db, ctx, 'session:terminate', s.device_id);
    if (s.state === 'ended') { send(res, 200, shape(s)); return; }
    db.transaction(() => {
      db.prepare(`UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ? AND state <> 'ended'`)
        .run(mine ? 'user_stopped' : 'admin_terminated', nowIso(), s.id);
      record(ctx, 'session.end', s.id);
    })();
    send(res, 200, shape(byId(s.id)));
  }));

}
