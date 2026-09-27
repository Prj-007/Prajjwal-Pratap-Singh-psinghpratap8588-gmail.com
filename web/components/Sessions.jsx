// Sessions card. "Stop" appears on your own sessions, and on anyone's where the device row's
// resolved set allows session:terminate — both answers come from the server.

import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Gated, allows } from './Gated.jsx';

export function Sessions({ orgId, orgPerms, session, say }) {
  const [sessions, setSessions] = useState(null);
  const [devices, setDevices] = useState([]);
  const [starting, setStarting] = useState(false);

  const load = () => Promise.all([
    api('GET', `/orgs/${orgId}/sessions`).then((b) => setSessions(b.sessions)),
    api('GET', `/orgs/${orgId}/devices`).then((b) => setDevices(b.devices)).catch(() => setDevices([])),
  ]).catch((e) => say(e.message));
  useEffect(() => { load(); }, [orgId]);

  const device = (id) => devices.find((d) => d.id === id);
  const canStop = (s) => s.state !== 'ended' && (s.user_id === session.user.id || allows(device(s.device_id)?.permissions, 'session:terminate'));

  async function stop(s) {
    try { await api('DELETE', `/sessions/${s.id}`); say('Session stopped.', 'ok'); await load(); } catch (err) { say(err.message); }
  }

  if (!sessions) return <p className="muted">Loading sessions…</p>;

  return (
    <section>
      <div className="toolbar">
        <h2>Sessions</h2>
        <Gated perms={orgPerms} permission="session:start" testid="new-session" onClick={() => setStarting((v) => !v)}>Start a session</Gated>
      </div>

      {starting && (
        <form className="inline-form" onSubmit={async (e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          try {
            await api('POST', `/orgs/${orgId}/sessions`, { deviceId: f.get('deviceId'), mode: f.get('mode') });
            setStarting(false);
            say(`${f.get('mode')} session started.`, 'ok');
            await load();
          } catch (err) { say(err.message); }
        }}>
          <select name="deviceId" data-testid="session-device">{devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</select>
          <select name="mode" data-testid="session-mode"><option>view</option><option>control</option><option>terminal</option></select>
          <button type="submit">Start</button>
        </form>
      )}

      {sessions.length === 0 ? <p className="muted">No sessions yet.</p> : (
        <table>
          <thead><tr><th>Device</th><th>Who</th><th>Mode</th><th>State</th><th>Started</th><th>Expires</th><th></th></tr></thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.id} data-testid="session-row" data-session-id={s.id} data-state-value={s.state}>
                <td>{device(s.device_id)?.name ?? s.device_id}</td>
                <td>{s.user_id === session.user.id ? 'you' : s.user_id}</td>
                <td>{s.mode}</td>
                <td><span className={s.state === 'active' ? 'pill allow' : 'pill'}>{s.state}{s.end_reason ? ` · ${s.end_reason}` : ''}</span></td>
                <td className="muted">{new Date(s.started_at).toLocaleString()}</td>
                <td className="muted">{new Date(s.expires_at).toLocaleString()}</td>
                <td>
                  {canStop(s) && (
                    <button data-testid="stop-session" data-permission={s.user_id === session.user.id ? 'self' : 'session:terminate'} data-state="unlocked" onClick={() => stop(s)}>Stop</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
