import { useEffect, useState } from 'react';
import { api } from '../../lib/api';
import { useTenant } from '../../lib/useTenant';
import type { ApiKey, SsoConfig, Webhook, WebhookFormat } from '../../lib/types';
import { IconPlus, IconTrash, IconX } from '../../icons';

const EVENT_LABELS: Record<string, string> = {
  sync_manager: 'Manager sync succeeded',
  sync_manager_failed: 'Manager sync failed',
  sync_manager_skipped: 'Manager sync skipped (already running)',
  sync_github_source: 'GitHub sync succeeded',
  sync_github_source_failed: 'GitHub sync failed',
  sync_github_source_skipped: 'GitHub sync skipped (already running)',
  delete_product: 'Product deleted',
  delete_manager: 'Manager deleted',
  delete_github_source: 'GitHub source deleted',
  delete_tenant: 'Tenant deleted',
  delete_user: 'User deleted',
};

function WebhookEditor(props: {
  webhook: Partial<Webhook> | null; availableEvents: string[];
  onClose: () => void; onSaved: () => void;
}) {
  const { webhook, availableEvents, onClose, onSaved } = props;
  const [form, setForm] = useState<Partial<Webhook>>({
    name: webhook?.name ?? '', url: webhook?.url ?? '',
    format: webhook?.format ?? 'generic', events: webhook?.events ?? [],
    enabled: webhook?.enabled ?? true, secret: '', id: webhook?.id,
  });
  const [saving, setSaving] = useState(false);

  const set = (k: keyof Webhook, v: unknown) => setForm(f => ({ ...f, [k]: v }));
  const toggleEvent = (evt: string) => setForm(f => {
    const events = new Set(f.events ?? []);
    if (events.has(evt)) events.delete(evt); else events.add(evt);
    return { ...f, events: [...events] };
  });

  const save = async () => {
    setSaving(true);
    try {
      await api.upsertWebhook(form);
      onSaved();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 560 }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3>{webhook?.id ? `Edit ${webhook.name || webhook.url}` : 'Add webhook'}</h3>
          <button className="icon-btn" onClick={onClose}><IconX /></button>
        </div>
        <div className="form-row"><label>Name</label>
          <input type="text" placeholder="e.g. SOC Slack channel" value={form.name ?? ''}
            onChange={e => set('name', e.target.value)} /></div>
        <div className="form-row"><label>Webhook URL</label>
          <input type="url" placeholder="https://hooks.slack.com/services/..." value={form.url ?? ''}
            onChange={e => set('url', e.target.value)} /></div>
        <div className="form-row"><label>Format</label>
          <select value={form.format} onChange={e => set('format', e.target.value as WebhookFormat)}>
            <option value="generic">Generic JSON (ServiceNow, Jira, custom)</option>
            <option value="slack">Slack incoming webhook</option>
            <option value="teams">Microsoft Teams incoming webhook</option>
          </select>
        </div>
        <div className="form-row"><label>Signing secret</label>
          <input type="password" placeholder={webhook?.has_secret ? '(unchanged)' : 'optional — adds X-RuleVis-Signature header'}
            value={form.secret ?? ''} onChange={e => set('secret', e.target.value)} /></div>

        <div style={{ marginTop: 10 }}>
          <label style={{ fontSize: 13, fontWeight: 600 }}>Events</label>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
            {availableEvents.map(evt => (
              <label key={evt} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                <input type="checkbox" checked={(form.events ?? []).includes(evt)}
                  onChange={() => toggleEvent(evt)} />
                {EVENT_LABELS[evt] ?? evt}
              </label>
            ))}
          </div>
        </div>

        <div className="form-row" style={{ marginTop: 10 }}>
          <label style={{ minWidth: 0, display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={!!form.enabled} onChange={e => set('enabled', e.target.checked)} />
            Enabled
          </label>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button onClick={onClose}>Cancel</button>
          <button className="primary" disabled={!form.url || saving} onClick={save}>
            {saving ? 'Saving…' : 'Save webhook'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function IntegrationsTab({ notify }: { notify: (m: string) => void }) {
  const [webhooksList, setWebhooksList] = useState<Webhook[]>([]);
  const [availableEvents, setAvailableEvents] = useState<string[]>([]);
  const [editing, setEditing] = useState<Partial<Webhook> | null | undefined>(undefined);
  const [testStatus, setTestStatus] = useState<Record<string, string>>({});

  const reload = () => {
    api.webhooks().then(r => { setWebhooksList(r.webhooks); setAvailableEvents(r.available_events); });
  };
  useEffect(reload, []);

  const test = async (w: Webhook) => {
    setTestStatus(s => ({ ...s, [w.id]: 'sending…' }));
    try {
      const r = await api.testWebhook(w.id);
      setTestStatus(s => ({ ...s, [w.id]: r.ok ? `ok: ${r.message}` : `error: ${r.message}` }));
    } catch (e) {
      setTestStatus(s => ({ ...s, [w.id]: `error: ${e}` }));
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div>
          <h2 style={{ margin: '0 0 4px' }}>Webhooks</h2>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            Push rule-change events to Slack, Microsoft Teams, or a generic JSON endpoint
            (ServiceNow, Jira, or your own listener) — instead of only checking the Audit log.
          </p>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <button className="primary" onClick={() => setEditing(null)}>
            <IconPlus size={13} /> Add webhook
          </button>
        </div>
      </div>

      <div className="grid cards-3" style={{ marginTop: 16 }}>
        {webhooksList.map(w => (
          <div key={w.id} className="card product-card">
            <div className="head">
              <div className="product-icon" style={{ background: 'var(--violet-soft)' }}>🔔</div>
              <div style={{ minWidth: 0 }}>
                <h3>{w.name || w.url}</h3>
                <span className="muted mono" style={{ fontSize: 11 }}>{w.format}</span>
              </div>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                <button onClick={() => setEditing(w)}>Edit</button>
                <button className="icon-btn danger" title="Delete"
                  onClick={async () => { await api.deleteWebhook(w.id); notify('Webhook deleted.'); reload(); }}>
                  <IconTrash size={13} />
                </button>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
              {w.enabled ? <span className="badge green">enabled</span> : <span className="badge">disabled</span>}
              <span className="badge" style={{ fontSize: 10.5 }}>{w.events.length} event{w.events.length !== 1 ? 's' : ''}</span>
              <button onClick={() => test(w)} style={{ fontSize: 11, padding: '3px 8px' }}>Send test</button>
            </div>
            {testStatus[w.id] && (
              <div className={`mgr-status ${testStatus[w.id].startsWith('error') ? 'err' : 'ok'}`}>
                {testStatus[w.id]}
              </div>
            )}
          </div>
        ))}
        {webhooksList.length === 0 && (
          <div className="empty" style={{ gridColumn: '1 / -1' }}>
            No webhooks configured for this tenant yet.
          </div>
        )}
      </div>

      {editing !== undefined && (
        <WebhookEditor webhook={editing} availableEvents={availableEvents}
          onClose={() => setEditing(undefined)}
          onSaved={() => { setEditing(undefined); notify('Webhook saved.'); reload(); }} />
      )}

      <ApiKeysSection notify={notify} />
      <SsoSection notify={notify} />
    </div>
  );
}

function fmtDate(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z');
  return d.toLocaleString();
}

function ApiKeysSection({ notify }: { notify: (m: string) => void }) {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [newRole, setNewRole] = useState('viewer');
  const [revealedKey, setRevealedKey] = useState('');

  const reload = () => { api.apiKeys().then(r => setKeys(r.api_keys)); };
  useEffect(reload, []);

  const create = async () => {
    if (!newName.trim()) return;
    const created = await api.createApiKey(newName.trim(), newRole);
    setRevealedKey(created.raw_key ?? '');
    setNewName('');
    setCreating(false);
    reload();
  };

  return (
    <div style={{ marginTop: 40 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div>
          <h2 style={{ margin: '0 0 4px' }}>API keys</h2>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            Programmatic access for scripts, CI pipelines, or your own tooling —
            send <code className="mono">Authorization: Bearer &lt;key&gt;</code> instead of logging in.
          </p>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <button className="primary" onClick={() => setCreating(true)}>
            <IconPlus size={13} /> Create API key
          </button>
        </div>
      </div>

      {revealedKey && (
        <div className="card" style={{ marginTop: 14, borderColor: 'var(--green)' }}>
          <p style={{ margin: '0 0 6px', fontSize: 13 }}>
            Key created — copy it now, it won't be shown again:
          </p>
          <div style={{ display: 'flex', gap: 8 }}>
            <input readOnly value={revealedKey} style={{ flex: 1 }} onFocus={e => e.target.select()} />
            <button onClick={() => { navigator.clipboard?.writeText(revealedKey); notify('Copied to clipboard.'); }}>
              Copy
            </button>
          </div>
        </div>
      )}

      <div className="card" style={{ padding: 0, marginTop: 16 }}>
        <table className="data">
          <thead>
            <tr><th>Name</th><th>Role</th><th>Created</th><th>Last used</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {keys.map(k => (
              <tr key={k.id}>
                <td>{k.name}</td>
                <td><span className="badge">{k.role}</span></td>
                <td className="mono" style={{ fontSize: 12 }}>{fmtDate(k.created_at)}</td>
                <td className="mono" style={{ fontSize: 12 }}>{fmtDate(k.last_used_at)}</td>
                <td>{k.revoked ? <span className="badge red">revoked</span> : <span className="badge green">active</span>}</td>
                <td style={{ textAlign: 'right' }}>
                  {!k.revoked && (
                    <button className="icon-btn danger" title="Revoke"
                      onClick={async () => { await api.revokeApiKey(k.id); notify('Key revoked.'); reload(); }}>
                      <IconTrash size={13} />
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {keys.length === 0 && (
              <tr><td colSpan={6}><div className="empty" style={{ border: 0 }}>No API keys yet.</div></td></tr>
            )}
          </tbody>
        </table>
      </div>

      {creating && (
        <div className="modal-overlay" onClick={() => setCreating(false)}>
          <div className="modal" style={{ maxWidth: 420 }} onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>Create API key</h3>
              <button className="icon-btn" onClick={() => setCreating(false)}><IconX /></button>
            </div>
            <div className="form-row"><label>Name</label>
              <input type="text" autoFocus placeholder="e.g. CI pipeline" value={newName}
                onChange={e => setNewName(e.target.value)} /></div>
            <div className="form-row"><label>Role</label>
              <select value={newRole} onChange={e => setNewRole(e.target.value)}>
                <option value="viewer">Viewer — read-only</option>
                <option value="analyst">Analyst — view + export</option>
                <option value="tenant_admin">Tenant admin — manage tenant</option>
              </select>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
              <button onClick={() => setCreating(false)}>Cancel</button>
              <button className="primary" disabled={!newName.trim()} onClick={create}>Create</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SsoSection({ notify }: { notify: (m: string) => void }) {
  const { tenantId } = useTenant();
  const [cfg, setCfg] = useState<SsoConfig | null>(null);
  const [saving, setSaving] = useState(false);

  const reload = () => { api.ssoConfig().then(setCfg); };
  useEffect(reload, []);

  const set = (k: keyof SsoConfig, v: unknown) => setCfg(c => c ? { ...c, [k]: v } : c);

  const save = async () => {
    if (!cfg) return;
    setSaving(true);
    try {
      const updated = await api.updateSsoConfig(cfg);
      setCfg(updated);
      notify('SSO settings saved.');
    } finally {
      setSaving(false);
    }
  };

  if (!cfg) return null;

  const callbackUrl = `${window.location.origin}/api/auth/sso/${tenantId}/callback`;

  return (
    <div style={{ marginTop: 40 }}>
      <h2 style={{ margin: '0 0 4px' }}>Single sign-on (OIDC)</h2>
      <p className="muted" style={{ margin: 0, fontSize: 13 }}>
        Let this tenant's members sign in through your identity provider (Okta, Azure AD / Entra ID,
        Google Workspace, Auth0, Keycloak — anything that speaks standard OpenID Connect).
      </p>

      <div className="card" style={{ marginTop: 16, maxWidth: 560 }}>
        <div className="form-row">
          <label style={{ minWidth: 0, display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={cfg.enabled} onChange={e => set('enabled', e.target.checked)} />
            Enable SSO for this tenant
          </label>
        </div>
        <div className="form-row"><label>Issuer URL</label>
          <input type="url" placeholder="https://your-org.okta.com" value={cfg.issuer}
            onChange={e => set('issuer', e.target.value)} /></div>
        <div className="form-row"><label>Client ID</label>
          <input type="text" value={cfg.client_id} onChange={e => set('client_id', e.target.value)} /></div>
        <div className="form-row"><label>Client secret</label>
          <input type="password" placeholder={cfg.has_client_secret ? '(unchanged)' : ''}
            value={cfg.client_secret ?? ''} onChange={e => set('client_secret', e.target.value)} /></div>
        <div className="form-row"><label>New-user role</label>
          <select value={cfg.auto_provision_role} onChange={e => set('auto_provision_role', e.target.value)}>
            <option value="viewer">Viewer — read-only</option>
            <option value="analyst">Analyst — view + export</option>
            <option value="tenant_admin">Tenant admin — manage tenant</option>
          </select>
        </div>

        <p className="faint" style={{ fontSize: 12, marginTop: 10 }}>
          Register this redirect URI with your identity provider:
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <input readOnly value={callbackUrl} style={{ flex: 1 }} className="mono" onFocus={e => e.target.select()} />
          <button onClick={() => { navigator.clipboard?.writeText(callbackUrl); notify('Copied to clipboard.'); }}>
            Copy
          </button>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 14 }}>
          <button className="primary" disabled={saving} onClick={save}>
            {saving ? 'Saving…' : 'Save SSO settings'}
          </button>
        </div>
      </div>
    </div>
  );
}
