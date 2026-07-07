import { useMemo, useState } from 'react';
import { api } from '../../lib/api';
import type { FileInfo, GithubSource, Manager, Product } from '../../lib/types';
import { IconX } from '../../icons';

export function Toast({ msg }: { msg: string }) {
  return msg ? <div className="toast">{msg}</div> : null;
}

// ---------------- Product editor ----------------
export function ProductEditor(props: {
  product: Partial<Product> | null;
  files: FileInfo[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const { product, files, onClose, onSaved } = props;
  const [name, setName] = useState(product?.name ?? '');
  const [icon, setIcon] = useState(product?.icon ?? '');
  const [description, setDescription] = useState(product?.description ?? '');
  const [selected, setSelected] = useState<Set<string>>(new Set(product?.files ?? []));
  const [filter, setFilter] = useState('');
  const [saving, setSaving] = useState(false);

  const visible = useMemo(
    () => files.filter(f => f.file.toLowerCase().includes(filter.toLowerCase())),
    [files, filter]);

  const toggle = (fn: string) => setSelected(s => {
    const next = new Set(s);
    if (next.has(fn)) next.delete(fn); else next.add(fn);
    return next;
  });

  const save = async () => {
    if (!name.trim()) return;
    setSaving(true);
    try {
      await api.upsertProduct({
        id: product?.id, name: name.trim(), icon, description,
        files: Array.from(selected),
      });
      onSaved();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 640 }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3>{product?.id ? `Edit ${product.name}` : 'New product'}</h3>
          <button className="icon-btn" onClick={onClose}><IconX /></button>
        </div>
        <div className="form-row">
          <label>Name</label>
          <input type="text" value={name} placeholder="e.g. Fortigate" onChange={e => setName(e.target.value)} autoFocus />
        </div>
        <div className="form-row">
          <label>Icon (emoji)</label>
          <input type="text" value={icon} placeholder="🔥 (optional)" style={{ maxWidth: 120 }} maxLength={4}
            onChange={e => setIcon(e.target.value)} />
        </div>
        <div className="form-row">
          <label>Description</label>
          <input type="text" value={description} placeholder="optional" onChange={e => setDescription(e.target.value)} />
        </div>

        <div className="form-row" style={{ marginTop: 14 }}>
          <label>Rule files</label>
          <input type="text" value={filter} placeholder="filter files…" onChange={e => setFilter(e.target.value)} />
        </div>
        <div style={{ maxHeight: 300, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 8, padding: 6 }}>
          {visible.map(f => {
            const takenBy = f.product && !(product?.files ?? []).includes(f.file) ? f.product : null;
            return (
              <div key={f.file}
                className={`file-pick ${takenBy ? 'taken' : ''}`}
                onClick={() => !takenBy && toggle(f.file)}>
                <input type="checkbox" readOnly checked={selected.has(f.file)} disabled={!!takenBy} />
                <span className="mono">{f.file}</span>
                <span className="faint">({f.rule_count} rules)</span>
                {f.builtin && <span className="badge">built-in</span>}
                {takenBy && <span className="badge amber">→ {takenBy}</span>}
              </div>
            );
          })}
          {visible.length === 0 && <div className="empty" style={{ padding: 20 }}>No files match.</div>}
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button onClick={onClose}>Cancel</button>
          <button className="primary" disabled={!name.trim() || saving} onClick={save}>
            {saving ? 'Saving…' : `Save product (${selected.size} files)`}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------- Manager editor ----------------
export function ManagerEditor(props: { manager: Partial<Manager> | null; onClose: () => void; onSaved: () => void }) {
  const { manager, onClose, onSaved } = props;
  const [form, setForm] = useState<Partial<Manager>>({
    name: manager?.name ?? '', url: manager?.url ?? 'https://:55000',
    username: manager?.username ?? 'wazuh-wui', password: '',
    verify_tls: manager?.verify_tls ?? false, include: manager?.include ?? true,
    auto_sync: manager?.auto_sync ?? false, sync_interval_minutes: manager?.sync_interval_minutes ?? 60,
    id: manager?.id,
  });
  const set = (k: keyof Manager, v: unknown) => setForm(f => ({ ...f, [k]: v }));
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    try {
      await api.upsertManager(form);
      onSaved();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 560 }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3>{manager?.id ? `Edit ${manager.name || manager.url}` : 'Connect Wazuh manager'}</h3>
          <button className="icon-btn" onClick={onClose}><IconX /></button>
        </div>
        <div className="form-row"><label>Name</label>
          <input type="text" placeholder="e.g. prod-wazuh" value={form.name ?? ''} onChange={e => set('name', e.target.value)} /></div>
        <div className="form-row"><label>API URL</label>
          <input type="url" placeholder="https://192.168.1.150:55000" value={form.url ?? ''} onChange={e => set('url', e.target.value)} /></div>
        <div className="form-row"><label>Username</label>
          <input type="text" value={form.username ?? ''} onChange={e => set('username', e.target.value)} /></div>
        <div className="form-row"><label>Password</label>
          <input type="password" placeholder={manager?.has_password ? '(unchanged)' : ''} value={form.password ?? ''}
            onChange={e => set('password', e.target.value)} /></div>
        <div className="form-row">
          <label>Options</label>
          <label style={{ minWidth: 0, display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={!!form.verify_tls} onChange={e => set('verify_tls', e.target.checked)} />
            Verify TLS
          </label>
          <label style={{ minWidth: 0, display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={!!form.include} onChange={e => set('include', e.target.checked)} />
            Include fetched rules in workspace
          </label>
        </div>
        <div className="form-row">
          <label>Auto-sync</label>
          <label style={{ minWidth: 0, display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={!!form.auto_sync} onChange={e => set('auto_sync', e.target.checked)} />
            Automatically sync with this manager
          </label>
        </div>
        {form.auto_sync && (
          <div className="form-row">
            <label>Sync interval</label>
            <select value={form.sync_interval_minutes ?? 60}
              onChange={e => set('sync_interval_minutes', Number(e.target.value))}>
              <option value={5}>Every 5 minutes</option>
              <option value={15}>Every 15 minutes</option>
              <option value={30}>Every 30 minutes</option>
              <option value={60}>Every hour</option>
              <option value={360}>Every 6 hours</option>
              <option value={1440}>Every 24 hours</option>
            </select>
          </div>
        )}
        {manager?.last_synced_at && (
          <p className="faint" style={{ fontSize: 12, margin: '4px 0 0' }}>
            Last synced: {new Date(manager.last_synced_at).toLocaleString()}
          </p>
        )}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button onClick={onClose}>Cancel</button>
          <button className="primary" disabled={!form.url || saving} onClick={save}>
            {saving ? 'Saving…' : 'Save manager'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------- GitHub source editor ----------------
export function GithubSourceEditor(props: {
  source: Partial<GithubSource> | null; onClose: () => void; onSaved: () => void;
}) {
  const { source, onClose, onSaved } = props;
  const [form, setForm] = useState<Partial<GithubSource>>({
    name: source?.name ?? '', repo: source?.repo ?? '', branch: source?.branch ?? 'main',
    path: source?.path ?? '', token: '', include: source?.include ?? true, id: source?.id,
    auto_sync: source?.auto_sync ?? false, sync_interval_minutes: source?.sync_interval_minutes ?? 60,
  });
  const set = (k: keyof GithubSource, v: unknown) => setForm(f => ({ ...f, [k]: v }));
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    try {
      await api.upsertGithubSource(form);
      onSaved();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 560 }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3>{source?.id ? `Edit ${source.name || source.repo}` : 'Add GitHub source'}</h3>
          <button className="icon-btn" onClick={onClose}><IconX /></button>
        </div>
        <div className="form-row"><label>Name</label>
          <input type="text" placeholder="e.g. internal-rules" value={form.name ?? ''} onChange={e => set('name', e.target.value)} /></div>
        <div className="form-row"><label>Repository</label>
          <input type="text" placeholder="owner/repo" value={form.repo ?? ''} onChange={e => set('repo', e.target.value)} /></div>
        <div className="form-row"><label>Branch</label>
          <input type="text" placeholder="main" value={form.branch ?? ''} onChange={e => set('branch', e.target.value)} /></div>
        <div className="form-row"><label>Path</label>
          <input type="text" placeholder="rules/ (optional — narrows the scan)" value={form.path ?? ''} onChange={e => set('path', e.target.value)} /></div>
        <div className="form-row"><label>Token</label>
          <input type="password" placeholder={source?.has_token ? '(unchanged — leave blank for public repos)' : 'optional, for private repos'}
            value={form.token ?? ''} onChange={e => set('token', e.target.value)} /></div>
        <div className="form-row">
          <label>Options</label>
          <label style={{ minWidth: 0, display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={!!form.include} onChange={e => set('include', e.target.checked)} />
            Include fetched rules in workspace
          </label>
        </div>
        <div className="form-row">
          <label>Auto-sync</label>
          <label style={{ minWidth: 0, display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={!!form.auto_sync} onChange={e => set('auto_sync', e.target.checked)} />
            Automatically sync with this repository
          </label>
        </div>
        {form.auto_sync && (
          <div className="form-row">
            <label>Sync interval</label>
            <select value={form.sync_interval_minutes ?? 60}
              onChange={e => set('sync_interval_minutes', Number(e.target.value))}>
              <option value={5}>Every 5 minutes</option>
              <option value={15}>Every 15 minutes</option>
              <option value={30}>Every 30 minutes</option>
              <option value={60}>Every hour</option>
              <option value={360}>Every 6 hours</option>
              <option value={1440}>Every 24 hours</option>
            </select>
          </div>
        )}
        {source?.last_synced_at && (
          <p className="faint" style={{ fontSize: 12, margin: '4px 0 0' }}>
            Last synced: {new Date(source.last_synced_at).toLocaleString()}
          </p>
        )}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button onClick={onClose}>Cancel</button>
          <button className="primary" disabled={!form.repo || saving} onClick={save}>
            {saving ? 'Saving…' : 'Save source'}
          </button>
        </div>
      </div>
    </div>
  );
}
