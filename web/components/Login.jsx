// Sign-in. A refused attempt stays on screen, in the server's words, until the next one —
// and never says more than the server did (a wrong password and an unknown account read the same).

import React, { useState } from 'react';
import * as client from '../api.js';

export function Login({ onSignedIn, notice }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    if (!email.trim() || !password) {
      setError({ code: 'VALIDATION', message: 'Enter your email and your password.' });
      return;
    }
    setBusy(true);
    try {
      onSignedIn(await client.login(email.trim(), password));
    } catch (err) {
      setError({ code: err.code, message: err.code === 'NETWORK' ? 'Could not reach the server.' : err.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form data-testid="login-form" onSubmit={submit} noValidate>
        <h1>RemoteOps</h1>
        {notice && <p className="muted">{notice}</p>}
        <label>Email<input data-testid="login-email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        <label>Password<input data-testid="login-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <button data-testid="login-submit" type="submit" disabled={busy}>Sign in</button>
        {error && (
          <p data-testid="login-error" data-error-code={error.code} role="alert" className="error">
            {error.message}
          </p>
        )}
      </form>
    </main>
  );
}
