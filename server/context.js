// Per-request context: turn a bearer token into an authenticated caller.
//
// The token's `org` claim is the only org the caller may address. A request that names
// any other org is a 404 — decided before the database is asked anything, so "that org
// does not exist" and "that org is not yours" cannot be told apart.
//
// Order: token → org in the path → membership → freshness (pv) → suspension.
//
// authenticate(db, secret) returns (req, params) => caller, where caller is
// { userId, orgId, role, membership, claims }.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound, forbidden } from './http.js';

// A suspended member still holds a valid token (AUTH-DATA-MODEL.md §7). These are the only
// routes it may reach: seeing its own (empty) permission set, listing its orgs, and
// switching to an org where it is not suspended. Everything else is a 403.
const OPEN_WHILE_SUSPENDED = new Set(['GET /v1/auth/me', 'GET /v1/orgs', 'POST /v1/auth/token']);

function bearer(req) {
  const header = req.headers?.authorization;
  if (typeof header !== 'string') throw unauthenticated('missing bearer token');
  const m = /^Bearer ([^\s]+)$/i.exec(header.trim());
  if (!m) throw unauthenticated('missing bearer token');
  return m[1];
}

export function authenticate(db, secret) {
  const findMembership = db.prepare(
    `SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version
       FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.org_id = ? AND m.user_id = ? AND o.deleted_at IS NULL`
  );

  return function buildContext(req, params = {}) {
    const claims = verifyAccessToken(bearer(req), secret);
    // verifyAccessToken checks the envelope; the two claims this module keys on are checked here.
    if (typeof claims.sub !== 'string' || claims.sub === '' || typeof claims.org !== 'string' || claims.org === '') {
      throw unauthenticated('token has no subject or org');
    }

    if (params.org !== undefined && params.org !== claims.org) throw notFound();

    const membership = findMembership.get(claims.org, claims.sub);
    if (!membership || membership.status === 'removed' || membership.status === 'invited') {
      throw unauthenticated('not a member of this org');
    }

    assertFresh(claims, membership);

    if (membership.status === 'suspended') {
      const path = new URL(req.url ?? '/', 'http://x').pathname;
      if (!OPEN_WHILE_SUSPENDED.has(`${req.method} ${path}`)) {
        throw forbidden('your membership in this org is suspended', 'suspended');
      }
    }

    return { userId: claims.sub, orgId: claims.org, role: membership.role, membership, claims };
  };
}
