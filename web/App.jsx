// The console shell: sign-in, the org switcher, and the permission-driven navigation.
//
// Nothing here decides a permission. `session.permissions` is the org-level set the server
// resolved; every card and entry is present when that set says allow and absent otherwise.

import React, { useEffect, useState } from 'react';
import * as client from './api.js';
import { Login } from './components/Login.jsx';
import { allows } from './components/Gated.jsx';
import { Devices } from './components/Devices.jsx';
import { People } from './components/People.jsx';

// Which permission shows which card (UI-INVENTORY.md §2). This is the inventory, not a
// role table: the server still decides whether each permission is held.
const CARDS = [
  { key: 'devices', label: 'Devices', show: (can) => can('device:list') },
  { key: 'people', label: 'People', show: (can) => can('user:read') },
  { key: 'grants', label: 'Grants', show: (can) => can('user:read') },
  { key: 'sessions', label: 'Sessions', show: (can) => can('session:view') },
  { key: 'audit', label: 'Audit', show: (can) => can('audit:read') },
  { key: 'admin', label: 'Admin', show: (can) => can('org:update') || can('org:delete') },
];

// Known themes get a hand-picked palette; any other name still gets a stable, distinct hue.
const THEMES = {
  cobalt: { bg: '#e8eefc', accent: '#1f4fd1' },
  amber: { bg: '#fdf1dc', accent: '#b36b00' },
  slate: { bg: '#eceff3', accent: '#44505f' },
};
function palette(theme) {
  if (THEMES[theme]) return THEMES[theme];
  let h = 0;
  for (const ch of String(theme)) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return { bg: `hsl(${h} 60% 93%)`, accent: `hsl(${h} 60% 35%)` };
}

// One component per card. Each mounts fresh when the org or the card changes (the key on
// <main>), so it refetches — nothing from the previous org can linger in the DOM.
function renderView(key, props) {
  switch (key) {
    case 'devices': return <Devices {...props} />;
    case 'people': return <People {...props} />;
    case undefined: return <p className="muted">Nothing here is available to you in this org.</p>;
    default: return <p className="muted">Coming next.</p>;
  }
}

export function App() {
  const [session, setSession] = useState(null);
  const [booting, setBooting] = useState(true);
  const [view, setView] = useState('devices');
  const [notice, setNotice] = useState(null);       // { text, kind: 'error' | 'ok' }
  const say = (text, kind = 'error') => setNotice({ text, kind });

  // A reload: try the refresh cookie before showing the sign-in form.
  useEffect(() => {
    client.refresh().then(setSession).catch(() => {}).finally(() => setBooting(false));
  }, []);

  if (booting) return null;
  if (!session) return <Login onSignedIn={(s) => { setSession(s); setView('devices'); setNotice(null); }} notice={notice?.text} />;

  const can = (key) => allows(session.permissions, key);
  const cards = CARDS.filter((c) => c.show(can));
  const current = cards.some((c) => c.key === view) ? view : cards[0]?.key;
  const colours = palette(session.org.theme);

  async function choose(id) {
    setNotice(null);
    try { setSession(await client.switchOrg(id)); } catch (err) { say(err.message); }
  }

  async function createOrg() {
    const name = window.prompt('Name for the new organization');
    if (!name) return;
    try {
      const org = await client.api('POST', '/orgs', { name });
      setSession(await client.switchOrg(org.id));
      setView('devices');
    } catch (err) { say(err.message); }
  }

  async function signOut() {
    await client.logout().catch(() => {});
    setSession(null);
  }

  return (
    <div
      data-testid="app-shell"
      data-org-id={session.orgId}
      data-org-theme={session.org.theme}
      className="shell"
      style={{ backgroundColor: colours.bg, '--accent': colours.accent }}
    >
      <header className="topbar">
        <strong className="brand">RemoteOps</strong>
        <nav className="orgs" aria-label="Organizations">
          {session.orgs.map((o) => (
            <button
              key={o.id}
              data-testid="org-option"
              data-org-id={o.id}
              className={o.id === session.orgId ? 'org active' : 'org'}
              onClick={() => choose(o.id)}
            >
              {o.name}
            </button>
          ))}
          <button data-testid="create-org" className="org ghost" onClick={createOrg}>+ New org</button>
        </nav>
        <span className="who">
          {session.user.name} · <span data-testid="active-role">{session.role}</span>
        </span>
        <button data-testid="sign-out" className="ghost" onClick={signOut}>Sign out</button>
      </header>

      {notice && <p className={notice.kind === 'ok' ? 'notice ok' : 'notice'} role="alert">{notice.text}</p>}

      <div className="layout">
        <nav className="cards" aria-label="Sections">
          {cards.map((c) => (
            <button key={c.key} data-testid={`nav-${c.key}`} className={c.key === current ? 'card active' : 'card'} onClick={() => setView(c.key)}>
              {c.label}
            </button>
          ))}
        </nav>
        <main className="panel" key={`${session.orgId}:${current}`}>
          {renderView(current, { orgId: session.orgId, orgPerms: session.permissions, session, say })}
        </main>
      </div>
    </div>
  );
}
