// Admin card: rename (org:update) and delete (org:delete) — the one pair that separates an
// owner's view from an admin's.

import React from 'react';
import { api } from '../api.js';
import { Gated } from './Gated.jsx';

export function Admin({ orgId, orgPerms, session, say, reload }) {
  async function rename(e) {
    e.preventDefault();
    const name = new FormData(e.currentTarget).get('name');
    try {
      await api('PATCH', `/orgs/${orgId}`, { name });
      say(`Renamed to ${name}.`, 'ok');
      await reload(orgId);
    } catch (err) { say(err.message); }
  }

  async function remove() {
    if (!window.confirm(`Delete ${session.org.name}? Every live session in it ends. This cannot be undone here.`)) return;
    try {
      await api('DELETE', `/orgs/${orgId}`);
      say(`${session.org.name} deleted.`, 'ok');
      await reload(null);          // the token's org is gone: fall back to another org
    } catch (err) { say(err.message); }
  }

  return (
    <section>
      <h2>Admin</h2>
      <form className="inline-form" onSubmit={rename}>
        <input name="name" defaultValue={session.org.name} aria-label="Organization name" />
        <Gated perms={orgPerms} permission="org:update" testid="rename-org" type="submit">Rename org</Gated>
      </form>
      <Gated perms={orgPerms} permission="org:delete" testid="delete-org" className="danger" onClick={remove}>Delete org</Gated>
    </section>
  );
}
