import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authApi } from '../lib/api';
import { useAuth } from '../lib/auth';
import Logo from '../components/Logo';

export default function Bootstrap() {
  const { setSession } = useAuth();
  const navigate = useNavigate();
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr('');
    if (password !== confirm) { setErr('Passwords do not match.'); return; }
    setBusy(true);
    try {
      const r = await authApi.bootstrap(email, password, displayName);
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
          <h1>Welcome to RuleVis</h1>
          <p>Create the first administrator account to get started.</p>
        </div>

        <form onSubmit={submit}>
          <div className="form-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
            <label style={{ minWidth: 0 }}>Display name</label>
            <input type="text" autoFocus value={displayName} onChange={e => setDisplayName(e.target.value)}
              placeholder="Jane Doe" />
          </div>
          <div className="form-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
            <label style={{ minWidth: 0 }}>Email</label>
            <input type="email" value={email} onChange={e => setEmail(e.target.value)}
              placeholder="you@company.com" required />
          </div>
          <div className="form-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
            <label style={{ minWidth: 0 }}>Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)}
              placeholder="At least 12 characters" required />
          </div>
          <div className="form-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
            <label style={{ minWidth: 0 }}>Confirm password</label>
            <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)} required />
          </div>

          {err && <p style={{ color: 'var(--red)', fontSize: 13, margin: '4px 0' }}>{err}</p>}

          <button type="submit" className="primary auth-submit" disabled={busy}>
            {busy ? 'Creating account…' : 'Create administrator account'}
          </button>
        </form>
        <p className="faint" style={{ fontSize: 12, marginTop: 14, textAlign: 'center' }}>
          You'll be made a platform super admin, with admin access to the "Default" tenant
          holding your existing rules and settings.
        </p>
      </div>
    </div>
  );
}
