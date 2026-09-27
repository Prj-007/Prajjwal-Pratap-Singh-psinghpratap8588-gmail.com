// Audit card: the newest events, allows and denies alike.

import React, { useEffect, useState } from 'react';
import { api } from '../api.js';

const PAGE = 50;

export function Audit({ orgId, say }) {
  const [page, setPage] = useState(null);
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    api('GET', `/orgs/${orgId}/audit?limit=${PAGE}&offset=${offset}`).then(setPage).catch((e) => say(e.message));
  }, [orgId, offset]);

  if (!page) return <p className="muted">Loading audit log…</p>;

  return (
    <section>
      <div className="toolbar">
        <h2>Audit</h2>
        <span className="muted">{page.total} events</span>
        <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Newer</button>
        <button disabled={offset + PAGE >= page.total} onClick={() => setOffset(offset + PAGE)}>Older</button>
      </div>
      <table>
        <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>Reason</th></tr></thead>
        <tbody>
          {page.events.map((e) => (
            <tr key={e.id} data-testid="audit-row" data-result={e.result}>
              <td className="muted">{new Date(e.at).toLocaleString()}</td>
              <td>{e.actor_id ?? '—'}</td>
              <td><code>{e.action}</code></td>
              <td>{e.target_type ? `${e.target_type} ${e.target_id ?? ''}` : '—'}</td>
              <td><span className={`pill ${e.result}`}>{e.result}</span></td>
              <td>{e.reason_code ?? ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
