// Invites: create, list, revoke (org-scoped), and the two public routes a link opens.
//
// The raw token is returned once, at creation, and stored only as a hash. Single use is the
// database's job: accepting is `UPDATE … WHERE accepted_at IS NULL AND revoked_at IS NULL`,
// so two simultaneous accepts cannot both succeed; one live invite per email is a partial
// unique index.

import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, conflict, gone, unauthenticated } from '../http.js';
import { newInviteToken, hashInviteToken, hashPassword, verifyPassword } from '../auth.js';
import { assertCanOrgWide } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { assertCanAssign } from '../lifecycle.js';
import { startSession } from './auth.js';

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const shape = (i) => ({ id: i.id, email: i.email, role: i.role, invitedBy: i.invited_by, expiresAt: i.expires_at, createdAt: i.created_at });

// Resolve a raw token to its invite, or throw what the link-holder is allowed to learn:
// unknown → 404, revoked or expired → 410. Acceptance is decided by the caller.
function byToken(db, raw) {
  const inv = typeof raw === 'string' && raw.length > 0
    ? db.prepare(
      `SELECT i.*, o.name AS org_name FROM invites i JOIN organizations o ON o.id = i.org_id
        WHERE i.token_hash = ? AND o.deleted_at IS NULL`
    ).get(hashInviteToken(raw))
    : null;
  if (!inv) throw notFound();
  if (inv.revoked_at || inv.expires_at <= nowIso()) throw gone();
  return inv;
}

export function registerInviteRoutes(router, { db, secret }) {
  const audited = (meta, handler) => (ctx, params, res) =>
    auditDenials(db, ctx, typeof meta === 'function' ? meta(params) : meta, () => handler(ctx, params, res));

  router.post('/v1/orgs/:org/invites', audited({ action: 'invite.create', targetType: 'invite' }, (ctx, _p, res) => {
    assertCanOrgWide(db, ctx, 'user:invite');
    const email = typeof ctx.body.email === 'string' ? ctx.body.email.trim().toLowerCase() : '';
    if (!EMAIL.test(email) || email.length > 254) throw badRequest('a valid email is required');
    assertCanAssign(db, ctx.role, ctx.body.role);

    const existing = db.prepare(
      `SELECT m.status FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = ? AND u.email = ?`
    ).get(ctx.orgId, email);
    if (existing && existing.status !== 'removed') throw conflict('that person is already a member');

    const raw = newInviteToken();
    const id = newId('inv');
    try {
      db.transaction(() => {
        db.prepare(
          `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).run(id, ctx.orgId, email, ctx.body.role, hashInviteToken(raw), ctx.userId, new Date(Date.now() + INVITE_TTL_MS).toISOString());
        audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'invite.create', targetType: 'invite', targetId: id, result: 'allow', requestId: ctx.requestId });
      })();
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') throw conflict('there is already a live invite for that email');
      throw err;
    }
    const inv = db.prepare('SELECT * FROM invites WHERE id = ?').get(id);
    // The only time the raw token exists outside the link itself.
    send(res, 201, { ...shape(inv), inviteToken: raw });
  }));

  router.get('/v1/orgs/:org/invites', audited({ action: 'invite.list' }, (ctx, _p, res) => {
    assertCanOrgWide(db, ctx, 'user:invite');
    const invites = db.prepare(
      `SELECT * FROM invites WHERE org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?
        ORDER BY created_at DESC`
    ).all(ctx.orgId, nowIso()).map(shape);
    send(res, 200, { invites });
  }));

  router.delete('/v1/orgs/:org/invites/:id', audited((p) => ({ action: 'invite.revoke', targetType: 'invite', targetId: p.id }), (ctx, p, res) => {
    assertCanOrgWide(db, ctx, 'user:invite');
    db.transaction(() => {
      const { changes } = db.prepare(
        'UPDATE invites SET revoked_at = ? WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL'
      ).run(nowIso(), p.id, ctx.orgId);
      if (changes !== 1) throw notFound();
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'invite.revoke', targetType: 'invite', targetId: p.id, result: 'allow', requestId: ctx.requestId });
    })();
    send(res, 200, { id: p.id, revoked: true });
  }));

  // Public. What someone holding the link may see: the org's name, the email and the role.
  // No ids, no members, no devices.
  router.get('/v1/invites/:token', (ctx, p, res) => {
    const inv = byToken(db, p.token);
    if (inv.accepted_at) throw gone('this invite has already been used');
    send(res, 200, { orgName: inv.org_name, email: inv.email, role: inv.role, expiresAt: inv.expires_at });
  });

  // Public. Creates the account (or, for an existing account, requires its password), joins
  // the org, and signs in to it.
  router.post('/v1/invites/:token/accept', (ctx, p, res) => {
    const inv = byToken(db, p.token);
    if (inv.accepted_at) throw conflict('this invite has already been used');
    const { name, password } = ctx.body;
    if (typeof password !== 'string') throw badRequest('password is required');

    let user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(inv.email);
    if (user) {
      // Otherwise anyone holding the link could attach a membership to someone else's account.
      if (!verifyPassword(password, user.password_hash)) throw unauthenticated('that email already has an account; use its password');
    } else {
      if (typeof name !== 'string' || name.trim() === '' || name.trim().length > 100) throw badRequest('name must be 1–100 characters');
      if (password.length < 8) throw badRequest('password must be at least 8 characters');
    }

    db.transaction(() => {
      const { changes } = db.prepare(
        'UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL'
      ).run(nowIso(), user?.id ?? null, inv.id);
      if (changes !== 1) throw conflict('this invite has already been used');

      if (!user) {
        user = { id: newId('usr') };
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)')
          .run(user.id, inv.email, name.trim(), hashPassword(password));
        db.prepare('UPDATE invites SET accepted_by = ? WHERE id = ?').run(user.id, inv.id);
      }
      const prior = db.prepare('SELECT status FROM memberships WHERE org_id = ? AND user_id = ?').get(inv.org_id, user.id);
      if (prior) {
        // A removed member coming back: same row, new role, fresh version.
        db.prepare(`UPDATE memberships SET role = ?, status = 'active', joined_at = ?, invited_by = ? WHERE org_id = ? AND user_id = ?`)
          .run(inv.role, nowIso(), inv.invited_by, inv.org_id, user.id);
        bumpPermVersion(db, { orgId: inv.org_id, userId: user.id });
      } else {
        db.prepare(`INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at) VALUES (?, ?, ?, ?, 'active', ?, ?)`)
          .run(newId('mem'), inv.org_id, user.id, inv.role, inv.invited_by, nowIso());
      }
      audit(db, { orgId: inv.org_id, actorId: user.id, action: 'invite.accept', targetType: 'invite', targetId: inv.id, result: 'allow', requestId: ctx.requestId });
    })();

    send(res, 200, startSession(db, secret, res, user.id, inv.org_id));
  });
}
