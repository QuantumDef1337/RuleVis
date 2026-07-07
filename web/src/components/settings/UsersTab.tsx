import { useEffect, useState } from 'react';
import { api, superApi } from '../../lib/api';
import { useAuth } from '../../lib/auth';
import type { TenantUser, User } from '../../lib/types';
import type { Permission } from '../../lib/permissions';
import { IconCheck, IconPlus, IconTrash, IconX } from '../../icons';

const ROLES = ['tenant_admin', 'analyst', 'viewer'] as const;
const ALL_PERMISSIONS: { id: Permission; label: string }[] = [
  { id: 'view_rules', label: 'View rules' },
  { id: 'export', label: 'Export' },
  { id: 'manage_tenant_settings', label: 'Manage tenant settings' },
  { id: 'manage_tenant_users', label: 'Manage tenant users' },
  { id: 'view_activity', label: 'View activity / audit log' },
];

function CreateUserModal(props: { onClose: () => void; onCreated: () => void }) {
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<string>('viewer');
  const [overrides, setOverrides] = useState<Set<Permission>>(new Set());
  const [forceReset, setForceReset] = useState(true);
  const [requireMfa, setRequireMfa] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const toggleOverride = (p: Permission) => {
    setOverrides(prev => {
      const next = new Set(prev);
      if (next.has(p)) next.delete(p); else next.add(p);
      return next;
    });
  };

  const submit = async () => {
    setBusy(true); setErr('');
    try {
      await api.createTenantUser({
        username: username.trim(), display_name: displayName.trim() || undefined,
        email: email.trim() || undefined, password, role,
        permission_overrides: [...overrides],
        force_password_reset: forceReset, require_mfa: requireMfa,
      });
      props.onCreated();
    } catch (e) {
      setErr(String((e as Error).message ?? e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={props.onClose}>
      <div className="modal" style={{ maxWidth: 520 }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3>Create user</h3>
          <button className="icon-btn" onClick={props.onClose}><IconX /></button>
        </div>

        <div className="form-row"><label>Username</label>
          <input type="text" autoFocus value={username} onChange={e => setUsername(e.target.value)}
            placeholder="jdoe" /></div>
        <div className="form-row"><label>Display name</label>
          <input type="text" value={displayName} onChange={e => setDisplayName(e.target.value)}
            placeholder="Jane Doe" /></div>
        <div className="form-row"><label>Email (optional)</label>
          <input type="email" value={email} onChange={e => setEmail(e.target.value)}
            placeholder="jane@company.com" /></div>
        <div className="form-row"><label>Password</label>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)}
            placeholder="At least 12 characters" /></div>
        <div className="form-row"><label>Role</label>
          <select value={role} onChange={e => setRole(e.target.value)}>
            <option value="viewer">Viewer — read-only</option>
            <option value="analyst">Analyst — view + export</option>
            <option value="tenant_admin">Tenant admin — manage tenant</option>
          </select>
        </div>

        <div style={{ marginTop: 10 }}>
          <label style={{ fontSize: 13, fontWeight: 600 }}>Permission overrides</label>
          <p className="muted" style={{ margin: '2px 0 8px', fontSize: 12 }}>
            Grant extra permissions beyond the selected role.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {ALL_PERMISSIONS.map(p => (
              <label key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                <input type="checkbox" checked={overrides.has(p.id)} onChange={() => toggleOverride(p.id)} />
                {p.label}
              </label>
            ))}
          </div>
        </div>

        <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <input type="checkbox" checked={forceReset} onChange={e => setForceReset(e.target.checked)} />
            Force password reset on first login
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <input type="checkbox" checked={requireMfa} onChange={e => setRequireMfa(e.target.checked)} />
            Require MFA enrollment
          </label>
        </div>

        {err && <p style={{ color: 'var(--red)', fontSize: 13 }}>{err}</p>}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 14 }}>
          <button onClick={props.onClose}>Cancel</button>
          <button className="primary" disabled={!username.trim() || password.length < 12 || busy} onClick={submit}>
            {busy ? 'Creating…' : 'Create user'}
          </button>
        </div>
      </div>
    </div>
  );
}

function InviteModal(props: { onClose: () => void; onInvited: (url: string) => void }) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<string>('viewer');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const submit = async () => {
    setBusy(true); setErr('');
    try {
      const r = await api.inviteTenantUser(email.trim(), role);
      props.onInvited(window.location.origin + r.invite_url);
    } catch (e) {
      setErr(String((e as Error).message ?? e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={props.onClose}>
      <div className="modal" style={{ maxWidth: 460 }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3>Invite user to this tenant</h3>
          <button className="icon-btn" onClick={props.onClose}><IconX /></button>
        </div>
        <div className="form-row"><label>Email</label>
          <input type="email" autoFocus value={email} onChange={e => setEmail(e.target.value)}
            placeholder="user@company.com" /></div>
        <div className="form-row"><label>Role</label>
          <select value={role} onChange={e => setRole(e.target.value)}>
            <option value="viewer">Viewer — read-only</option>
            <option value="analyst">Analyst — view + export</option>
            <option value="tenant_admin">Tenant admin — manage tenant</option>
          </select>
        </div>
        {err && <p style={{ color: 'var(--red)', fontSize: 13 }}>{err}</p>}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
          <button onClick={props.onClose}>Cancel</button>
          <button className="primary" disabled={!email.trim() || busy} onClick={submit}>
            {busy ? 'Creating…' : 'Create invite link'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function UsersTab({ notify }: { notify: (m: string) => void }) {
  const { user } = useAuth();
  const [tenantUsers, setTenantUsers] = useState<TenantUser[]>([]);
  const [platformUsers, setPlatformUsers] = useState<User[]>([]);
  const [inviting, setInviting] = useState(false);
  const [inviteLink, setInviteLink] = useState('');
  const [creating, setCreating] = useState(false);

  const reload = () => {
    api.tenantUsers().then(r => setTenantUsers(r.users)).catch(() => setTenantUsers([]));
    if (user?.is_super_admin) {
      superApi.users().then(r => setPlatformUsers(r.users)).catch(() => setPlatformUsers([]));
    }
  };
  useEffect(reload, [user?.is_super_admin]);

  const changeRole = async (uid: string, role: string) => {
    await api.updateTenantUserRole(uid, role);
    notify('Role updated.');
    reload();
  };

  const removeFromTenant = async (uid: string) => {
    await api.removeTenantUser(uid);
    notify('Removed from tenant.');
    reload();
  };

  return (
    <div>
      {/* ---- Tenant users ---- */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div>
          <h2 style={{ margin: '0 0 4px' }}>Team & access</h2>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>Members with access to this tenant.</p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <button className="primary" onClick={() => setCreating(true)}>
            <IconPlus size={13} /> Create user
          </button>
          <button onClick={() => { setInviteLink(''); setInviting(true); }}>
            <IconPlus size={13} /> Invite by email
          </button>
        </div>
      </div>

      {inviteLink && (
        <div className="card" style={{ marginTop: 14, borderColor: 'var(--green)' }}>
          <p style={{ margin: '0 0 6px', fontSize: 13 }}>
            Invite link created — share it with the user (valid 7 days, single use):
          </p>
          <div style={{ display: 'flex', gap: 8 }}>
            <input readOnly value={inviteLink} style={{ flex: 1 }} onFocus={e => e.target.select()} />
            <button onClick={() => { navigator.clipboard?.writeText(inviteLink); notify('Copied to clipboard.'); }}>
              Copy
            </button>
          </div>
        </div>
      )}

      <div className="card" style={{ padding: 0, marginTop: 16 }}>
        <table className="data">
          <thead>
            <tr><th>Username</th><th>Email</th><th>Name</th><th>Role</th><th>MFA</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {tenantUsers.map(u => (
              <tr key={u.id}>
                <td className="mono">{u.username || <i className="faint">—</i>}</td>
                <td className="mono" style={{ fontSize: 12 }}>
                  {u.email.endsWith('@users.rulevis.local') ? <i className="faint">none</i> : u.email}
                </td>
                <td>{u.display_name || <i className="faint">—</i>}</td>
                <td>
                  <select value={u.role} disabled={u.id === user?.id}
                    onChange={e => changeRole(u.id, e.target.value)}>
                    {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                  {(u.permission_overrides?.length ?? 0) > 0 && (
                    <span className="badge violet" style={{ marginLeft: 6 }} title={u.permission_overrides!.join(', ')}>
                      +{u.permission_overrides!.length} extra
                    </span>
                  )}
                </td>
                <td>
                  {u.mfa_enabled ? <span className="badge green">on</span>
                    : u.mfa_required ? <span className="badge amber">required</span>
                    : <span className="badge">off</span>}
                </td>
                <td>{u.is_active ? <span className="badge green">active</span> : <span className="badge red">disabled</span>}</td>
                <td style={{ textAlign: 'right' }}>
                  {u.id !== user?.id && (
                    <button className="icon-btn danger" title="Remove from tenant"
                      onClick={() => removeFromTenant(u.id)}><IconTrash size={13} /></button>
                  )}
                </td>
              </tr>
            ))}
            {tenantUsers.length === 0 && (
              <tr><td colSpan={7}><div className="empty" style={{ border: 0 }}>No members yet — invite or create one.</div></td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ---- Platform users (super admin) ---- */}
      {user?.is_super_admin && (
        <>
          <h2 className="section" style={{ marginTop: 34 }}>All platform users</h2>
          <div className="card" style={{ padding: 0 }}>
            <table className="data">
              <thead>
                <tr><th>Email</th><th>Name</th><th>Super admin</th><th>Status</th><th></th></tr>
              </thead>
              <tbody>
                {platformUsers.map(u => (
                  <tr key={u.id}>
                    <td className="mono">{u.email}</td>
                    <td>{u.display_name || <i className="faint">—</i>}</td>
                    <td>
                      <button className={u.is_super_admin ? 'on' : ''} style={{ fontSize: 11, padding: '3px 8px' }}
                        disabled={u.id === user.id}
                        onClick={async () => { await superApi.updateUser(u.id, { is_super_admin: !u.is_super_admin }); notify('Updated.'); reload(); }}>
                        {u.is_super_admin ? <><IconCheck size={11} /> yes</> : 'no'}
                      </button>
                    </td>
                    <td>
                      <button style={{ fontSize: 11, padding: '3px 8px' }} disabled={u.id === user.id}
                        onClick={async () => { await superApi.updateUser(u.id, { is_active: !u.is_active }); notify('Updated.'); reload(); }}>
                        {u.is_active ? 'active' : 'disabled'}
                      </button>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {u.id !== user.id && (
                        <button className="icon-btn danger" title="Delete user entirely"
                          onClick={async () => { await superApi.deleteUser(u.id); notify('User deleted.'); reload(); }}>
                          <IconTrash size={13} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {inviting && (
        <InviteModal onClose={() => setInviting(false)}
          onInvited={url => { setInviting(false); setInviteLink(url); reload(); }} />
      )}
      {creating && (
        <CreateUserModal onClose={() => setCreating(false)}
          onCreated={() => { setCreating(false); notify('User created.'); reload(); }} />
      )}
    </div>
  );
}
