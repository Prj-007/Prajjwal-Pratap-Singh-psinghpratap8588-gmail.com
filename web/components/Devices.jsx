// Devices card. Every row carries the caller's resolved permissions for THAT device, straight
// from GET /devices, so each row's entries are decided per row by the server — one request,
// no follow-ups, no rules here.

import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Gated } from './Gated.jsx';

// The device kinds the schema accepts. Only used to offer a choice; the server's CHECK decides.
const KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

export function Devices({ orgId, orgPerms, say }) {
  const [devices, setDevices] = useState(null);
  const [adding, setAdding] = useState(false);
  const [renaming, setRenaming] = useState(null);

  const load = () => api('GET', `/orgs/${orgId}/devices`).then((b) => setDevices(b.devices)).catch((e) => say(e.message));
  useEffect(() => { load(); }, [orgId]);

  async function act(fn, done) {
    try { const out = await fn(); say(done(out), 'ok'); await load(); } catch (e) { say(e.message); }
  }

  const start = (d, mode) => act(() => api('POST', `/orgs/${orgId}/sessions`, { deviceId: d.id, mode }), () => `${mode} session started on ${d.name}.`);

  if (!devices) return <p className="muted">Loading devices…</p>;

  return (
    <section>
      <div className="toolbar">
        <h2>Devices</h2>
        <Gated perms={orgPerms} permission="device:provision" testid="add-device" onClick={() => setAdding((v) => !v)}>Add device</Gated>
      </div>

      {adding && (
        <form className="inline-form" onSubmit={(e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          act(() => api('POST', `/orgs/${orgId}/devices`, { name: f.get('name'), kind: f.get('kind') }), (d) => { setAdding(false); return `Added ${d.name}.`; });
        }}>
          <input name="name" placeholder="device name" data-testid="device-name" required />
          <select name="kind" data-testid="device-kind" defaultValue="linux">{KINDS.map((k) => <option key={k}>{k}</option>)}</select>
          <button type="submit">Add</button>
        </form>
      )}

      {devices.length === 0 ? (
        <p data-testid="devices-empty" className="muted">No devices in this organization yet.</p>
      ) : (
        <table>
          <thead><tr><th>Name</th><th>Kind</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
                <td>
                  {renaming === d.id ? (
                    <form className="actions" onSubmit={(e) => {
                      e.preventDefault();
                      const name = new FormData(e.currentTarget).get('name');
                      act(() => api('PATCH', `/orgs/${orgId}/devices/${d.id}`, { name }), () => { setRenaming(null); return `Renamed to ${name}.`; });
                    }}>
                      <input name="name" defaultValue={d.name} autoFocus />
                      <button type="submit">Save</button>
                      <button type="button" onClick={() => setRenaming(null)}>Cancel</button>
                    </form>
                  ) : d.name}
                </td>
                <td>{d.kind}</td>
                <td><span className={d.online ? 'pill online' : 'pill'}>{d.online ? 'online' : 'offline'}</span></td>
                <td>
                  <div className="actions">
                    <Gated perms={d.permissions} permission="device:view" testid="start-view" onClick={() => start(d, 'view')}>View</Gated>
                    <Gated perms={d.permissions} permission="device:control" testid="start-control" onClick={() => start(d, 'control')}>Control</Gated>
                    <Gated perms={d.permissions} permission="device:terminal" testid="start-terminal" onClick={() => start(d, 'terminal')}>Terminal</Gated>
                    <Gated perms={d.permissions} permission="device:file_transfer" testid="transfer-files" onClick={() => say('File transfer is not part of this build; the permission is held on this device.', 'ok')}>Files</Gated>
                    <Gated perms={d.permissions} permission="device:update" testid="rename-device" onClick={() => setRenaming(d.id)}>Rename</Gated>
                    <Gated perms={d.permissions} permission="device:provision" testid="decommission-device" onClick={() => {
                      if (window.confirm(`Decommission ${d.name}? Live sessions on it will end.`)) act(() => api('DELETE', `/orgs/${orgId}/devices/${d.id}`), () => `${d.name} decommissioned.`);
                    }}>Decommission</Gated>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
