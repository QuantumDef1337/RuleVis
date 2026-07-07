import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../lib/api';
import type { DiffResult, FileInfo, Manager, Product } from '../lib/types';

interface SourceOption { value: string; label: string; group: string }

function buildOptions(products: Product[], files: FileInfo[], managers: Manager[]): SourceOption[] {
  const opts: SourceOption[] = [
    { value: 'all', label: 'Entire workspace', group: 'Workspace' },
    { value: 'builtin', label: 'Built-in rules', group: 'Workspace' },
    { value: 'custom', label: 'Custom rules', group: 'Workspace' },
  ];
  for (const p of products) {
    opts.push({ value: `product:${p.name}`, label: p.name, group: 'Products' });
  }
  for (const m of managers) {
    opts.push({ value: `manager:${m.id}`, label: `${m.name || m.url} (fetched cache)`, group: 'Managers' });
  }
  for (const f of files) {
    opts.push({ value: `file:${f.file}`, label: f.file, group: 'Files' });
  }
  return opts;
}

function SourceSelect(props: { options: SourceOption[]; value: string; onChange: (v: string) => void }) {
  const groups = [...new Set(props.options.map(o => o.group))];
  return (
    <select value={props.value} onChange={e => props.onChange(e.target.value)} style={{ minWidth: 230 }}>
      <option value="">— choose source —</option>
      {groups.map(g => (
        <optgroup key={g} label={g}>
          {props.options.filter(o => o.group === g).map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </optgroup>
      ))}
    </select>
  );
}

function ChangeValue({ v }: { v: unknown }) {
  if (v === null || v === undefined) return <i className="faint">—</i>;
  if (Array.isArray(v)) {
    if (v.length && typeof v[0] === 'object') {
      // conditions array
      return (
        <div>
          {(v as { tag: string; text: string; attributes: Record<string, string> }[]).map((c, i) => (
            <div key={i} className="mono" style={{ fontSize: 11.5 }}>
              &lt;{c.tag}{Object.entries(c.attributes ?? {}).map(([k, val]) => ` ${k}="${val}"`)}&gt;{c.text}
            </div>
          ))}
        </div>
      );
    }
    return <span>{(v as string[]).join(', ')}</span>;
  }
  return <span>{String(v)}</span>;
}

export default function Compare() {
  const [options, setOptions] = useState<SourceOption[]>([]);
  const [left, setLeft] = useState('builtin');
  const [right, setRight] = useState('custom');
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [tab, setTab] = useState<'added' | 'removed' | 'changed'>('added');
  const navigate = useNavigate();
  const { tenantId } = useParams();

  useEffect(() => {
    Promise.all([api.products(), api.files(), api.managers()]).then(([p, f, m]) => {
      setOptions(buildOptions(p.products, f.files, m.managers));
    });
  }, []);

  const run = async () => {
    if (!left || !right) return;
    setBusy(true); setErr(''); setDiff(null);
    try {
      const r = await api.diff(left, right);
      setDiff(r);
      setTab(r.added.length ? 'added' : r.removed.length ? 'removed' : 'changed');
    } catch (e) {
      setErr(String((e as Error).message ?? e));
    } finally {
      setBusy(false);
    }
  };

  const rows = diff ? (tab === 'added' ? diff.added : tab === 'removed' ? diff.removed : []) : [];

  return (
    <div className="page">
      <h2 style={{ margin: '0 0 4px' }}>Compare rulesets</h2>
      <p className="muted" style={{ margin: '0 0 18px', fontSize: 13 }}>
        Diff two sources — custom vs built-in, product vs product, or a fetched Wazuh manager
        against your local workspace.
      </p>

      <div className="card" style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
        <SourceSelect options={options} value={left} onChange={setLeft} />
        <span className="muted">vs</span>
        <SourceSelect options={options} value={right} onChange={setRight} />
        <button className="primary" disabled={!left || !right || busy} onClick={run}>
          {busy ? 'Comparing…' : 'Compare'}
        </button>
      </div>

      {err && <div className="empty" style={{ marginTop: 18 }}>{err}</div>}

      {diff && (
        <>
          <div className="diff-summary">
            <div className="diff-pill add">{diff.added.length}<small>only in {diff.right}</small></div>
            <div className="diff-pill rem">{diff.removed.length}<small>only in {diff.left}</small></div>
            <div className="diff-pill chg">{diff.changed.length}<small>changed</small></div>
            <div className="diff-pill same">{diff.unchanged_count}<small>identical</small></div>
          </div>

          <div style={{ display: 'flex', gap: 8, margin: '6px 0 14px' }}>
            <button className={tab === 'added' ? 'on primary' : ''} onClick={() => setTab('added')}>
              Only in {diff.right} ({diff.added.length})
            </button>
            <button className={tab === 'removed' ? 'on primary' : ''} onClick={() => setTab('removed')}>
              Only in {diff.left} ({diff.removed.length})
            </button>
            <button className={tab === 'changed' ? 'on primary' : ''} onClick={() => setTab('changed')}>
              Changed ({diff.changed.length})
            </button>
          </div>

          {tab !== 'changed' && (
            <div className="card" style={{ padding: 0 }}>
              {rows.length === 0 && <div className="empty" style={{ border: 0 }}>Nothing here.</div>}
              {rows.length > 0 && (
                <table className="data">
                  <thead>
                    <tr><th>Rule</th><th>Level</th><th>Description</th><th>File</th></tr>
                  </thead>
                  <tbody>
                    {rows.map(r => (
                      <tr key={r.id} className="clickable"
                        onClick={() => navigate(`/t/${tenantId}/visualizer?focus=${r.id}`)}>
                        <td className="mono" style={{ color: 'var(--accent)', fontWeight: 700 }}>{r.id}</td>
                        <td>{r.level ?? ''}</td>
                        <td>{r.description ?? ''}</td>
                        <td className="mono">{r.file ?? ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {tab === 'changed' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {diff.changed.length === 0 && (
                <div className="empty">
                  No field-level changes{diff.summary ? '' : ' (same-workspace comparisons only detect membership differences)'}.
                </div>
              )}
              {diff.changed.map(c => (
                <div key={c.id} className="card">
                  <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', marginBottom: 8 }}>
                    <span className="mono" style={{ color: 'var(--accent)', fontWeight: 700, cursor: 'pointer' }}
                      onClick={() => navigate(`/t/${tenantId}/visualizer?focus=${c.id}`)}>{c.id}</span>
                    <span className="muted" style={{ fontSize: 13 }}>{c.description}</span>
                    {c.changes.map(ch => <span key={ch.field} className="badge amber">{ch.field}</span>)}
                  </div>
                  <table className="data">
                    <thead>
                      <tr><th style={{ width: 120 }}>Field</th><th>{diff.left}</th><th>{diff.right}</th></tr>
                    </thead>
                    <tbody>
                      {c.changes.map(ch => (
                        <tr key={ch.field}>
                          <td className="mono">{ch.field}</td>
                          <td><ChangeValue v={ch.left} /></td>
                          <td><ChangeValue v={ch.right} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
