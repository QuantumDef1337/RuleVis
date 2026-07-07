import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { authApi } from '../lib/api';
import { useAuth } from '../lib/auth';
import Logo from '../components/Logo';

export default function AcceptInvite() {
  const [params] = useSearchParams();
  const token = params.get('token') ?? '';
  const { setSession } = useAuth();
  const navigate = useNavigate();

  const [invite, setInvite] = useState<{ email: string; role: string; tenant_name: string | null } | null>(null);
  const [loadErr, setLoadErr] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!token) { setLoadErr('No invite token provided.'); return; }
    authApi.getInvite(token).then(setInvite).catch(e => setLoadErr(String(e.message ?? e)));
  }, [token]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr('');
    if (password !== confirm) { setErr('Passwords do not match.'); return; }
    setBusy(true);
    try {
      const r = await authApi.acceptInvite(token, password, displayName);
      setSession(r.user, r.tenants);
      navigate(r.tenants[0] ? `/t/${r.tenants[0].id}` : '/', { replace: true });
    } catch (e2) {
      setErr(String((e2 as Error).message ?? e2));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-shell">
      <div className="auth-card" style={{ maxWidth: 420 }}>
        <div className="auth-brand">
          <div className="auth-logo"><Logo size={34} /></div>
          <h1>Join RuleVis</h1>
          {invite && (
            <p>
              You've been invited as <b>{invite.role}</b>
              {invite.tenant_name ? <> on <b>{invite.tenant_name}</b></> : null} — {invite.email}
            </p>
          )}
        </div>

        {loadErr && <p style={{ color: 'var(--red)', fontSize: 13 }}>{loadErr}</p>}

        {invite && (
          <form onSubmit={submit}>
            <div className="form-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              <label style={{ minWidth: 0 }}>Display name</label>
              <input type="text" autoFocus value={displayName} onChange={e => setDisplayName(e.target.value)} />
            </div>
            <div className="form-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              <label style={{ minWidth: 0 }}>Password</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} required />
            </div>
            <div className="form-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              <label style={{ minWidth: 0 }}>Confirm password</label>
              <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)} required />
            </div>
            {err && <p style={{ color: 'var(--red)', fontSize: 13, margin: '4px 0' }}>{err}</p>}
            <button type="submit" className="primary auth-submit" disabled={busy}>
              {busy ? 'Joining…' : 'Accept & create account'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
