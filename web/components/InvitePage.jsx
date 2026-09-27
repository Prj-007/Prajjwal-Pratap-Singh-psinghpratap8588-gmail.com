// /invite/:token — what someone holding an invite link sees before signing in.
// A bad link says only that the link is not usable: no org name, no ids.

import React, { useEffect, useState } from 'react';
import { ApiError } from '../api.js';

async function call(method, path, body) {
  const res = await fetch(`/v1${path}`, {
    method,
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) throw new ApiError(res.status, json);
  return json;
}

const UNUSABLE = 'This invite link is not valid. It may have expired, been revoked or already been used.';

export function InvitePage({ token, onDone }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');

  useEffect(() => {
    call('GET', `/invites/${encodeURIComponent(token)}`).then(setInvite).catch(() => setError(UNUSABLE));
  }, [token]);

  async function accept(e) {
    e.preventDefault();
    setError(null);
    try {
      await call('POST', `/invites/${encodeURIComponent(token)}/accept`, { name, password });
      onDone(`You have joined ${invite.orgName}. Sign in to continue.`);
    } catch (err) {
      setError(err.status === 404 || err.status === 410 ? UNUSABLE : err.message);
    }
  }

  if (!invite) {
    return (
      <main className="login">
        <div className="login-card">
          <h1>RemoteOps</h1>
          {error ? <p data-testid="invite-error" role="alert" className="error">{error}</p> : <p className="muted">Checking your invite…</p>}
        </div>
      </main>
    );
  }

  return (
    <main className="login">
      <form data-testid="invite-form" onSubmit={accept}>
        <h1>Join {invite.orgName}</h1>
        <p className="muted">You have been invited as <strong data-testid="invite-role">{invite.role}</strong>.</p>
        <label>Email<input data-testid="invite-email" value={invite.email} readOnly /></label>
        <label>Your name<input data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label>Password<input data-testid="invite-password" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <p className="muted">Already have an account with this email? Use its password; your name is kept.</p>
        <button data-testid="invite-submit" type="submit">Accept invite</button>
        {error && <p data-testid="invite-error" role="alert" className="error">{error}</p>}
      </form>
    </main>
  );
}
