import { useEffect, useMemo, useState } from 'react';
import { superApi } from '../../lib/api';
import type { LoginActivityEntry } from '../../lib/types';
import { IconAlertTriangle } from '../../icons';

function fmtTime(iso: string): string {
  const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z');
  return d.toLocaleString();
}

/** Compresses a raw user-agent into a short "Browser on OS" label. */
function shortUA(ua?: string | null): string {
  if (!ua) return '—';
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X|Macintosh/.test(ua) ? 'macOS'
    : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS'
    : /Linux/.test(ua) ? 'Linux' : '';
  const br = /Edg\//.test(ua) ? 'Edge' : /OPR\/|Opera/.test(ua) ? 'Opera'
    : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox'
    : /Safari\//.test(ua) ? 'Safari' : 'Unknown';
  return [br, os].filter(Boolean).join(' · ');
}

/** Flags per-entry reasons an entry looks suspicious, keyed by entry id. */
function computeSuspicious(entries: LoginActivityEntry[]): Map<number, string[]> {
  const flags = new Map<number, string[]>();
  const byEmail = new Map<string, LoginActivityEntry[]>();
  for (const e of entries) {
    const key = e.email_attempted.toLowerCase();
    if (!byEmail.has(key)) byEmail.set(key, []);
    byEmail.get(key)!.push(e);
  }
  for (const group of byEmail.values()) {
    const failed = group.filter(e => !e.success);
    if (failed.length >= 3) {
      for (const e of failed) {
        flags.set(e.id, [...(flags.get(e.id) ?? []), `${failed.length} failed attempts for this account`]);
      }
    }
    const ips = new Set(failed.map(e => e.ip_address).filter(Boolean));
    if (ips.size >= 3) {
      for (const e of failed) {
        flags.set(e.id, [...(flags.get(e.id) ?? []), `failures from ${ips.size} different IP addresses`]);
      }
    }
  }
  return flags;
}

export default function LoginActivityTab() {
  const [entries, setEntries] = useState<LoginActivityEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [resultFilter, setResultFilter] = useState<'all' | 'success' | 'failed'>('all');
  const [q, setQ] = useState('');
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);

  useEffect(() => {
    superApi.loginActivity().then(r => setEntries(r.entries)).catch(() => setEntries([])).finally(() => setLoading(false));
  }, []);

  const suspicious = useMemo(() => computeSuspicious(entries), [entries]);

  const filtered = entries.filter(e => {
    if (resultFilter === 'success' && !e.success) return false;
    if (resultFilter === 'failed' && e.success) return false;
    if (suspiciousOnly && !suspicious.has(e.id)) return false;
    if (q.trim()) {
      const needle = q.trim().toLowerCase();
      if (!e.email_attempted.toLowerCase().includes(needle) && !(e.ip_address ?? '').includes(needle)) return false;
    }
    return true;
  });

  return (
    <div>
      <h2 style={{ margin: '0 0 4px' }}>Login activity</h2>
      <p className="muted" style={{ margin: '0 0 18px', fontSize: 13 }}>
        Every sign-in attempt — successful and failed — with source IP, device, and reason. Feeds account lockout.
      </p>

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 14, flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search by email or IP…" style={{ minWidth: 220 }}
          value={q} onChange={e => setQ(e.target.value)} />
        <select value={resultFilter} onChange={e => setResultFilter(e.target.value as never)}>
          <option value="all">All results</option>
          <option value="success">Success only</option>
          <option value="failed">Failed only</option>
        </select>
        <button className={suspiciousOnly ? 'primary' : ''} onClick={() => setSuspiciousOnly(s => !s)}>
          <IconAlertTriangle size={13} /> Suspicious only {suspicious.size > 0 ? `(${new Set([...suspicious.keys()]).size})` : ''}
        </button>
      </div>

      {loading && <div className="empty">Loading…</div>}
      {!loading && (
        <div className="card" style={{ padding: 0, maxHeight: '68vh', overflowY: 'auto' }}>
          <table className="data">
            <thead>
              <tr><th>Time</th><th>Email</th><th>Result</th><th>IP address</th><th>Device</th><th title="Full user agent">Agent</th></tr>
            </thead>
            <tbody>
              {filtered.map(e => {
                const flags = suspicious.get(e.id);
                return (
                  <tr key={e.id} style={flags ? { background: 'var(--red-soft, rgba(220,50,50,.06))' } : undefined}>
                    <td className="mono" style={{ whiteSpace: 'nowrap', fontSize: 12 }}>{fmtTime(e.created_at)}</td>
                    <td className="mono" style={{ fontSize: 12.5 }}>
                      {e.email_attempted}
                      {flags && (
                        <span title={flags.join('; ')} style={{ marginLeft: 6, color: 'var(--red)' }}>
                          <IconAlertTriangle size={12} />
                        </span>
                      )}
                    </td>
                    <td>
                      {e.success
                        ? <span className="badge green">success</span>
                        : <span className="badge red" title={e.reason ?? ''}>{e.reason || 'failed'}</span>}
                    </td>
                    <td className="mono" style={{ fontSize: 12.5 }}>{e.ip_address || '—'}</td>
                    <td style={{ fontSize: 12.5 }}>{shortUA(e.user_agent)}</td>
                    <td className="faint" style={{ fontSize: 11, maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                      title={e.user_agent ?? ''}>{e.user_agent || '—'}</td>
                  </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr><td colSpan={6}><div className="empty" style={{ border: 0 }}>No matching login activity.</div></td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
