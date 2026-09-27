// People card: members, invites, role changes, suspension, removal.
// Entries follow the org-level resolved set; the server still enforces rank and last-owner
// rules and its refusal is shown in words.

import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Gated, allows } from './Gated.jsx';

export function People({ orgId, orgPerms, session, say }) {
  const [members, setMembers] = useState(null);
  const [roles, setRoles] = useState([]);
  const [inviting, setInviting] = useState(false);
  const [link, setLink] = useState(null);

  const load = () => Promise.all([
    api('GET', `/orgs/${orgId}/members`).then((b) => setMembers(b.members)),
    api('GET', `/orgs/${orgId}/roles`).then((b) => setRoles(b.roles)),
  ]).catch((e) => say(e.message));
  useEffect(() => { load(); }, [orgId]);

  async function act(fn, done) {
    try { await fn(); say(done, 'ok'); await load(); } catch (e) { say(e.message); }
  }

  const assignable = roles.filter((r) => r.assignable);
  if (!members) return <p className="muted">Loading people…</p>;

  return (
    <section>
      <div className="toolbar">
        <h2>People</h2>
        <Gated perms={orgPerms} permission="user:invite" testid="invite-user" onClick={() => { setInviting((v) => !v); setLink(null); }}>Invite</Gated>
      </div>

      {inviting && (
        <form className="inline-form" onSubmit={async (e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          try {
            const inv = await api('POST', `/orgs/${orgId}/invites`, { email: f.get('email'), role: f.get('role') });
            // There is no email delivery; the link is shown once, here.
            setLink(`${window.location.origin}/invite/${inv.inviteToken}`);
            say(`Invite created for ${inv.email}. Copy the link below — it is shown only once.`, 'ok');
          } catch (err) { say(err.message); }
        }}>
          <input name="email" type="email" placeholder="email" data-testid="invite-email-input" required />
          <select name="role" data-testid="invite-role-select">{assignable.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}</select>
          <button type="submit">Send invite</button>
          {link && <code data-testid="invite-link">{link}</code>}
        </form>
      )}

      <table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
          {members.map((m) => {
            const me = m.userId === session.user.id;
            return (
              <tr key={m.userId} data-testid="user-row" data-user-id={m.userId}>
                <td>{m.name}{me && <span className="muted"> (you)</span>}</td>
                <td>{m.email}</td>
                <td>
                  {allows(orgPerms, 'user:role:update') && !me ? (
                    <select data-testid="role-select" data-permission="user:role:update" data-state="unlocked" value={m.role}
                      onChange={(e) => act(() => api('PATCH', `/orgs/${orgId}/members/${m.userId}`, { role: e.target.value }), `${m.name} is now ${e.target.value}.`)}>
                      {/* The member's current role stays listed even if you could not assign it. */}
                      {roles.filter((r) => r.assignable || r.key === m.role).map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
                    </select>
                  ) : m.role}
                </td>
                <td><span className={m.status === 'suspended' ? 'pill deny' : 'pill'}>{m.status}</span></td>
                <td>
                  {!me && (
                    <div className="actions">
                      <Gated perms={orgPerms} permission="user:remove" testid="suspend-user" onClick={() => (m.status === 'suspended'
                        ? act(() => api('DELETE', `/orgs/${orgId}/members/${m.userId}/suspend`), `${m.name} reinstated.`)
                        : act(() => api('POST', `/orgs/${orgId}/members/${m.userId}/suspend`), `${m.name} suspended; their sessions ended.`))}>
                        {m.status === 'suspended' ? 'Reinstate' : 'Suspend'}
                      </Gated>
                      <Gated perms={orgPerms} permission="user:remove" testid="remove-user" onClick={() => {
                        if (window.confirm(`Remove ${m.name} from this organization?`)) act(() => api('DELETE', `/orgs/${orgId}/members/${m.userId}`), `${m.name} removed.`);
                      }}>Remove</Gated>
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
