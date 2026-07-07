import { useEffect, useState } from 'react';
import { api, superApi } from '../../lib/api';
import { useAuth } from '../../lib/auth';
import type { AuditLogEntry } from '../../lib/types';

function fmtTime(iso: string): string {
  const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z');
  return d.toLocaleString();
}

/** Renders sync_manager (and other JSON) details in a readable way. */
function DetailsCell({ entry }: { entry: AuditLogEntry }) {
  const [open, setOpen] = useState(false);
  const raw = entry.details ?? '';
  let parsed: Record<string, unknown> | null = null;
  try { parsed = raw.startsWith('{') ? JSON.parse(raw) : null; } catch { parsed = null; }

  if (!parsed) return <span className="muted" style={{ fontSize: 12.5 }}>{raw || '—'}</span>;

  const added = (parsed.added as string[]) ?? [];
  const removed = (parsed.removed as string[]) ?? [];
  const changed = (parsed.changed as { id: string; fields: string[] }[]) ?? [];
  const summary: string[] = [];
  if (parsed.manager) summary.push(String(parsed.manager));
  if (added.length) summary.push(`+${added.length}`);
  if (removed.length) summary.push(`-${removed.length}`);
  if (changed.length) summary.push(`${changed.length} changed`);

  return (
    <div>
      <span style={{ cursor: 'pointer', fontSize: 12.5 }} onClick={() => setOpen(o => !o)}>
        {open ? '▾' : '▸'} {summary.join(' · ') || 'details'}
      </span>
      {open && (
        <div style={{ marginTop: 6, fontSize: 12 }}>
          {added.length > 0 && <div><span className="badge green">added</span> <span className="mono">{added.join(', ')}</span></div>}
          {removed.length > 0 && <div style={{ marginTop: 4 }}><span className="badge red">removed</span> <span className="mono">{removed.join(', ')}</span></div>}
          {changed.length > 0 && (
            <div style={{ marginTop: 4 }}>
              <span className="badge amber">changed</span>
              {changed.map(c => (
                <div key={c.id} className="mono" style={{ marginLeft: 8 }}>
                  {c.id} <span className="faint">({c.fields.join(', ')})</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AuditLogTab({ deletionsOnly = false }: { deletionsOnly?: boolean }) {
  const { user } = useAuth();
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const p = user?.is_super_admin
      ? superApi.auditLog(deletionsOnly)
      : api.tenantAuditLog(deletionsOnly);
    p.then(r => setEntries(r.entries)).catch(() => setEntries([])).finally(() => setLoading(false));
  }, [user?.is_super_admin, deletionsOnly]);

  return (
    <div>
      <h2 style={{ margin: '0 0 4px' }}>{deletionsOnly ? 'Deletion log' : 'Audit log'}</h2>
      <p className="muted" style={{ margin: '0 0 18px', fontSize: 13 }}>
        {deletionsOnly
          ? 'Every delete action across the platform, retained per policy.'
          : 'Every configuration and administrative action — including exactly what changed on each manager sync.'}
      </p>

      {loading && <div className="empty">Loading…</div>}
      {!loading && (
        <div className="card" style={{ padding: 0, maxHeight: '68vh', overflowY: 'auto' }}>
          <table className="data">
            <thead>
              <tr><th>Time</th><th>Actor</th><th>IP address</th><th>Action</th><th>Target</th><th>Details</th></tr>
            </thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id}>
                  <td className="mono" style={{ whiteSpace: 'nowrap', fontSize: 12 }}>{fmtTime(e.created_at)}</td>
                  <td style={{ fontSize: 12.5 }}>{e.actor_email || <i className="faint">system</i>}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{e.ip_address || <i className="faint">—</i>}</td>
                  <td><span className="badge">{e.action}</span></td>
                  <td className="mono" style={{ fontSize: 12 }}>
                    {e.target_type ? `${e.target_type}${e.target_id ? `:${e.target_id}` : ''}` : '—'}
                  </td>
                  <td><DetailsCell entry={e} /></td>
                </tr>
              ))}
              {entries.length === 0 && (
                <tr><td colSpan={6}><div className="empty" style={{ border: 0 }}>No entries yet.</div></td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
