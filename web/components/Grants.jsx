// Grants card: the org's live grants, and (with grant:create) a form to add one.
// The permission checkboxes come from the keys of the server's resolved set — the catalogue
// as the database holds it, undocumented permissions included.

import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Gated } from './Gated.jsx';

export function Grants({ orgId, orgPerms, session, say }) {
  const [grants, setGrants] = useState(null);
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [creating, setCreating] = useState(false);

  const load = () => Promise.all([
    api('GET', `/orgs/${orgId}/grants`).then((b) => setGrants(b.grants)),
    api('GET', `/orgs/${orgId}/members`).then((b) => setMembers(b.members)),
    // Device names for the table and the form; a caller without device:list just sees ids.
    api('GET', `/orgs/${orgId}/devices`).then((b) => setDevices(b.devices)).catch(() => setDevices([])),
  ]).catch((e) => say(e.message));
  useEffect(() => { load(); }, [orgId]);

  const nameOf = (id) => members.find((m) => m.userId === id)?.name ?? id;
  const deviceName = (id) => (id === null ? 'whole org' : devices.find((d) => d.id === id)?.name ?? id);
  const catalogue = Object.keys(orgPerms).sort();

  async function submit(e) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const permissions = f.getAll('perm');
    try {
      await api('POST', `/orgs/${orgId}/grants`, {
        userId: f.get('userId'),
        deviceId: f.get('deviceId') || null,
        effect: f.get('effect'),
        permissions,
        expiresAt: f.get('expiresAt') ? new Date(f.get('expiresAt')).toISOString() : undefined,
      });
      setCreating(false);
      say(`Grant created: ${f.get('effect')} ${permissions.join(', ')} for ${nameOf(f.get('userId'))}.`, 'ok');
      await load();
    } catch (err) { say(err.message); }
  }

  if (!grants) return <p className="muted">Loading grants…</p>;

  return (
    <section>
      <div className="toolbar">
        <h2>Grants</h2>
        <Gated perms={orgPerms} permission="grant:create" testid="new-grant" onClick={() => setCreating((v) => !v)}>New grant</Gated>
      </div>

      {creating && (
        <form className="inline-form" onSubmit={submit}>
          <select name="userId" data-testid="grant-user" required>
            {members.filter((m) => m.userId !== session.user.id && m.status === 'active').map((m) => <option key={m.userId} value={m.userId}>{m.name}</option>)}
          </select>
          <select name="deviceId" data-testid="grant-device" defaultValue="">
            <option value="">Whole org</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
          <select name="effect" data-testid="grant-effect" defaultValue="allow">
            <option value="allow">allow</option>
            <option value="deny">deny</option>
          </select>
          <label className="muted">expires <input type="datetime-local" name="expiresAt" data-testid="grant-expires" /></label>
          <div className="perm-list">
            {catalogue.map((key) => (
              <label key={key}><input type="checkbox" name="perm" value={key} data-permission-key={key} /> {key}</label>
            ))}
          </div>
          <button type="submit" data-testid="grant-submit">Create grant</button>
        </form>
      )}

      {grants.length === 0 ? <p className="muted">No grants in this organization.</p> : (
        <table>
          <thead><tr><th>Person</th><th>Scope</th><th>Effect</th><th>Permissions</th><th>Window</th><th></th></tr></thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.id} data-testid="grant-row" data-grant-id={g.id} data-effect={g.effect}>
                <td>{nameOf(g.userId)}</td>
                <td>{deviceName(g.deviceId)}</td>
                <td><span className={`pill ${g.effect}`}>{g.effect}</span></td>
                <td><code>{g.permissions.join(' ')}</code></td>
                <td className="muted">{g.startsAt || g.expiresAt ? `${g.startsAt ?? 'now'} → ${g.expiresAt ?? '∞'}` : 'always'}</td>
                <td>
                  <Gated perms={orgPerms} permission="grant:revoke" testid="revoke-grant" onClick={async () => {
                    try { await api('DELETE', `/orgs/${orgId}/grants/${g.id}`); say('Grant revoked.', 'ok'); await load(); } catch (err) { say(err.message); }
                  }}>Revoke</Gated>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
