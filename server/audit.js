// Append-only audit writes.
//
// audit_events has BEFORE UPDATE / BEFORE DELETE triggers, so this module only ever INSERTs.
//
//   - DENIED attempts are recorded, not just successes.
//   - one action, one row. The success row is written by the route inside the same
//     transaction as the change; auditDenials only ever writes the deny row.

import { newId, nowIso } from './db.js';
import { HttpError } from './http.js';

export function audit(db, { orgId, actorId = null, action, targetType = null, targetId = null, result, reasonCode = null, requestId = null }) {
  const id = newId('aud');
  db.prepare(
    `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(id, orgId, actorId, action, targetType, targetId, result, reasonCode, requestId, nowIso());
  return id;
}

// Only a 403 is a refused permission. A 404 is "not visible" (recording it would log a
// row about something the caller cannot see), and a 400 is a malformed request.
const isRefusal = (err) => err instanceof HttpError && err.status === 403;

// Run fn(); if it refuses with a permission error, record the denial before rethrowing.
// Works for a plain function and for one that returns a promise.
export function auditDenials(db, ctx, meta, fn) {
  const record = (err) => {
    if (isRefusal(err)) {
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId,
        action: meta.action, targetType: meta.targetType, targetId: meta.targetId,
        result: 'deny', reasonCode: err.reason ?? err.code,
      });
    }
    throw err;
  };

  let out;
  try {
    out = fn();
  } catch (err) {
    record(err);
  }
  return out && typeof out.then === 'function' ? out.catch(record) : out;
}
