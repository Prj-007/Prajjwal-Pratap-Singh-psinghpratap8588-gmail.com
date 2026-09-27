// The console's only door to the server.
//
// The access token lives in this module's memory and nowhere else — not localStorage, not
// sessionStorage. A reload loses it; the httpOnly refresh cookie (which this code never
// sees) gets a new one from POST /v1/auth/refresh.

let token = null;
let orgId = null;

export class ApiError extends Error {
  constructor(status, body) {
    const e = body?.error ?? {};
    super(e.message ?? `request failed (${status})`);
    this.status = status;
    this.code = e.code ?? 'NETWORK';
    this.reason = e.reason ?? null;
  }
}

function remember(session) {
  token = session.token;
  orgId = session.orgId;
  return session;
}

export function forget() {
  token = null;
  orgId = null;
}

async function raw(method, path, body) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const res = await fetch(`/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) throw new ApiError(res.status, json);
  return json;
}

// A permission change makes the token stale (401 TOKEN_STALE). Refresh once for the same
// org and retry, so the change shows up on this request instead of at token expiry.
export async function api(method, path, body) {
  try {
    return await raw(method, path, body);
  } catch (err) {
    if (err.code !== 'TOKEN_STALE') throw err;
    await refresh(orgId);
    return raw(method, path, body);
  }
}

export const login = async (email, password) => remember(await raw('POST', '/auth/login', { email, password }));
export const refresh = async (wanted) => remember(await raw('POST', '/auth/refresh', wanted ? { orgId: wanted } : {}));
export const switchOrg = async (id) => remember(await raw('POST', '/auth/token', { orgId: id }));
export const logout = async () => { try { await raw('POST', '/auth/logout', {}); } finally { forget(); } };
export const currentOrg = () => orgId;
