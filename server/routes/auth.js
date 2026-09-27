// Auth routes: login, refresh, switch org, me.
//
// Access token: a JWT in the response body, held in memory by the console.
// Refresh token: opaque, stored only as a hash, sent as an httpOnly cookie scoped to
// /v1/auth, rotated on every use. Replaying a rotated token revokes its whole family.

import { randomUUID } from 'node:crypto';
import { newId, nowIso } from '../db.js';
import {
  issueAccessToken, verifyPassword, hashPassword,
  newRefreshToken, hashRefreshToken, REFRESH_TTL_SECONDS,
} from '../auth.js';
import { send, badRequest, unauthenticated, notFound, forbidden } from '../http.js';
import { resolve } from '../permissions.js';

const COOKIE = 'rt';
const COOKIE_PATH = '/v1/auth';

// Compared against when the email is unknown, so an unknown account costs the same scrypt
// work as a wrong password and the two cannot be told apart by timing.
const DUMMY_HASH = hashPassword(randomUUID());
const BAD_LOGIN = 'invalid email or password';

// Memberships the caller can see in the org switcher: active or suspended, in live orgs.
// Earliest joined first — that order also picks the default org.
function myOrgs(db, userId) {
  return db.prepare(
    `SELECT o.id, o.name, o.theme, m.role, m.status, m.perm_version
       FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status IN ('active', 'suspended') AND o.deleted_at IS NULL
      ORDER BY m.joined_at IS NULL, m.joined_at, m.created_at, o.name`
  ).all(userId);
}

// Which org a token should be for: the one asked for if the user belongs to it, else the
// earliest-joined active one, else a suspended one (so /auth/me can show why nothing works).
function pickOrg(orgs, wanted) {
  if (wanted !== undefined && wanted !== null) return orgs.find((o) => o.id === wanted) ?? null;
  return orgs.find((o) => o.status === 'active') ?? orgs[0] ?? null;
}

// The body the console builds itself from, minus the token.
function whoami(db, userId, org, orgs) {
  const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(userId);
  const { permissions } = resolve(db, { userId, orgId: org.id });
  return {
    user,
    orgId: org.id,
    org: { id: org.id, name: org.name, theme: org.theme },
    role: org.role,
    status: org.status,
    orgs: orgs.map(({ id, name, theme, role, status }) => ({ id, name, theme, role, status })),
    permissions,
  };
}

const withToken = (db, secret, userId, org, orgs) => ({
  token: issueAccessToken({ userId, orgId: org.id, role: org.role, permVersion: org.perm_version }, secret),
  ...whoami(db, userId, org, orgs),
});

function setRefreshCookie(res, raw) {
  res.setHeader('set-cookie',
    `${COOKIE}=${raw}; HttpOnly; Secure; SameSite=Strict; Path=${COOKIE_PATH}; Max-Age=${REFRESH_TTL_SECONDS}`);
}

function clearRefreshCookie(res) {
  res.setHeader('set-cookie', `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=${COOKIE_PATH}; Max-Age=0`);
}

function readCookie(req, name) {
  for (const part of String(req.headers.cookie ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function storeRefresh(db, userId, familyId) {
  const raw = newRefreshToken();
  db.prepare(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?)`
  ).run(newId('rt'), userId, hashRefreshToken(raw), familyId,
    new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString());
  return raw;
}

export function registerAuthRoutes(router, { db, secret }) {
  router.post('/v1/auth/login', (ctx, _params, res) => {
    const { email, password, orgId } = ctx.body;
    if (typeof email !== 'string' || typeof password !== 'string') throw badRequest('email and password are required');

    const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(email.trim().toLowerCase());
    const ok = verifyPassword(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) throw unauthenticated(BAD_LOGIN);

    const orgs = myOrgs(db, user.id);
    const org = pickOrg(orgs, orgId);
    if (!org) throw orgId ? notFound() : unauthenticated('you do not belong to any organization');

    setRefreshCookie(res, storeRefresh(db, user.id, newId('fam')));
    send(res, 200, withToken(db, secret, user.id, org, orgs));
  });

  router.post('/v1/auth/refresh', (ctx, _params, res) => {
    const raw = readCookie(ctx.req, COOKIE);
    if (!raw) throw unauthenticated('no refresh token');
    const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw));
    if (!row) { clearRefreshCookie(res); throw unauthenticated('invalid refresh token'); }

    const now = nowIso();
    if (row.revoked_at) {
      // A rotated token came back: someone holds a copy. Kill every token in its lineage.
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL').run(now, row.family_id);
      clearRefreshCookie(res);
      throw unauthenticated('refresh token reuse detected');
    }
    if (row.expires_at <= now) { clearRefreshCookie(res); throw unauthenticated('refresh token expired'); }

    const orgs = myOrgs(db, row.user_id);
    const org = pickOrg(orgs, ctx.body.orgId) ?? pickOrg(orgs);
    if (!org) { clearRefreshCookie(res); throw unauthenticated('you do not belong to any organization'); }

    const next = db.transaction(() => {
      // `revoked_at IS NULL` makes two concurrent refreshes race safely: only one rotates.
      const { changes } = db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').run(now, row.id);
      if (changes !== 1) throw unauthenticated('refresh token already used');
      return storeRefresh(db, row.user_id, row.family_id);
    })();

    setRefreshCookie(res, next);
    send(res, 200, withToken(db, secret, row.user_id, org, orgs));
  });

  // Switch org: mint a token for another org the caller belongs to.
  router.post('/v1/auth/token', (ctx, _params, res) => {
    const { orgId } = ctx.body;
    if (typeof orgId !== 'string' || orgId === '') throw badRequest('orgId is required');
    const orgs = myOrgs(db, ctx.userId);
    const org = orgs.find((o) => o.id === orgId);
    if (!org) throw notFound();
    if (org.status !== 'active') throw forbidden('your membership in that org is suspended', 'suspended');
    send(res, 200, withToken(db, secret, ctx.userId, org, orgs));
  });

  router.get('/v1/auth/me', (ctx, _params, res) => {
    const orgs = myOrgs(db, ctx.userId);
    const org = orgs.find((o) => o.id === ctx.orgId);
    if (!org) throw unauthenticated('not a member of this org');
    send(res, 200, whoami(db, ctx.userId, org, orgs));
  });
}
