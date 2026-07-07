import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { superApi } from '../../lib/api';
import { useAuth } from '../../lib/auth';
import type { AccessibleTenant } from '../../lib/types';
import { IconArrowUpRight, IconPlus, IconServer, IconTrash } from '../../icons';

function fmtDate(iso: string): string {
  const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z');
  return d.toLocaleDateString();
}

export default function TenantsTab({ notify }: { notify: (m: string) => void }) {
  const { refresh } = useAuth();
  const navigate = useNavigate();
  const [tenants, setTenants] = useState<AccessibleTenant[]>([]);
  const [newName, setNewName] = useState('');
  const [busy, setBusy] = useState(false);

  const reload = () => { superApi.tenants().then(r => setTenants(r.tenants)).catch(() => setTenants([])); };
  useEffect(reload, []);

  const create = async () => {
    if (!newName.trim()) return;
    setBusy(true);
    try {
      await superApi.createTenant(newName.trim());
      setNewName('');
      notify('Tenant created.');
      await refresh();  // so the sidebar switcher & accessible-tenants list update
      reload();
    } finally {
      setBusy(false);
    }
  };

  const remove = async (t: AccessibleTenant) => {
    await superApi.deleteTenant(t.id);
    notify(`Deleted tenant "${t.name}".`);
    await refresh();
    reload();
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div>
          <h2 style={{ margin: '0 0 4px' }}>Tenants</h2>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            Isolated environments — each with its own rules, products, managers, GitHub sources and members.
          </p>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16, display: 'flex', gap: 8 }}>
        <input type="text" style={{ flex: 1 }} placeholder="New tenant name — e.g. Customer A prod"
          value={newName} onChange={e => setNewName(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') create(); }} />
        <button className="primary" disabled={!newName.trim() || busy} onClick={create}>
          <IconPlus size={13} /> {busy ? 'Creating…' : 'Add tenant'}
        </button>
      </div>

      <div className="grid cards-3" style={{ marginTop: 16 }}>
        {tenants.map(t => (
          <div key={t.id} className="card product-card">
            <div className="head">
              <div className="product-icon" style={{ background: 'var(--accent-soft)' }}><IconServer size={18} /></div>
              <div style={{ minWidth: 0 }}>
                <h3>{t.name}</h3>
                <span className="muted mono" style={{ fontSize: 11 }}>{t.id}</span>
              </div>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                <button title="Open" onClick={() => navigate(`/t/${t.id}`)}><IconArrowUpRight size={13} /></button>
                {t.id !== 'default' && (
                  <button className="icon-btn danger" title="Delete tenant"
                    onClick={() => remove(t)}><IconTrash size={13} /></button>
                )}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              {t.is_active ? <span className="badge green">active</span> : <span className="badge">inactive</span>}
              {t.id === 'default' && <span className="badge accent">default</span>}
            </div>
            <div className="product-metrics">
              <div className="pm">
                <div className="pm-val">{t.rule_count ?? '—'}</div>
                <div className="pm-label">Rules</div>
              </div>
              <div className="pm">
                <div className="pm-val">{t.member_count ?? 0}</div>
                <div className="pm-label">Members</div>
              </div>
              <div className="pm">
                <div className="pm-val" style={{ fontSize: 13 }}>{fmtDate(t.created_at)}</div>
                <div className="pm-label">Created</div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
