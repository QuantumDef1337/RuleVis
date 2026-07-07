import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { authApi } from '../lib/api';
import { useAuth } from '../lib/auth';
import Logo from '../components/Logo';

export default function Login() {
  const { setSession } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [needsMfa, setNeedsMfa] = useState(false);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [showSso, setShowSso] = useState(false);
  const [ssoTenantId, setSsoTenantId] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(''); setBusy(true);
    try {
      const r = await authApi.login(email, password, needsMfa ? mfaCode : undefined);
      if (r.mfa_required) {
        setNeedsMfa(true);
        return;
      }
      if (r.user && r.tenants) {
        setSession(r.user, r.tenants);
        const from = (location.state as { from?: string })?.from;
        const homeTenant = r.tenants[0] ? `/t/${r.tenants[0].id}` : '/no-access';
        const dest = r.mfa_setup_required ? `${homeTenant}/settings?tab=profile` : (from || homeTenant);
        navigate(dest, { replace: true });
      }
    } catch (e2) {
      setErr(String((e2 as Error).message ?? e2));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="auth-brand">
          <div className="auth-logo"><Logo size={34} /></div>
          <h1>RuleVis</h1>
          <p>Rule Intelligence for Wazuh</p>
        </div>

        <form onSubmit={submit}>
          {!needsMfa && (
            <>
              <div className="form-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
                <label style={{ minWidth: 0 }}>Email or username</label>
                <input type="text" autoFocus value={email} onChange={e => setEmail(e.target.value)}
                  placeholder="you@company.com or username" required />
              </div>
              <div className="form-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
                <label style={{ minWidth: 0 }}>Password</label>
                <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••" required />
              </div>
            </>
          )}
          {needsMfa && (
            <div className="form-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              <label style={{ minWidth: 0 }}>Authentication code</label>
              <p className="faint" style={{ margin: '0 0 6px', fontSize: 12 }}>
                Enter the 6-digit code from your authenticator app, or a backup code.
              </p>
              <input type="text" autoFocus value={mfaCode} onChange={e => setMfaCode(e.target.value)}
                placeholder="123456" required />
            </div>
          )}

          {err && <p style={{ color: 'var(--red)', fontSize: 13, margin: '4px 0' }}>{err}</p>}

          <button type="submit" className="primary auth-submit" disabled={busy}>
            {busy ? 'Signing in…' : needsMfa ? 'Verify' : 'Sign in'}
          </button>
          {needsMfa && (
            <button type="button" style={{ marginTop: 8, width: '100%' }}
              onClick={() => { setNeedsMfa(false); setMfaCode(''); }}>
              Back
            </button>
          )}
        </form>

        {!needsMfa && !showSso && (
          <button type="button" style={{ marginTop: 10, width: '100%' }} onClick={() => setShowSso(true)}>
            Sign in with SSO
          </button>
        )}
        {!needsMfa && showSso && (
          <div className="form-row" style={{ flexDirection: 'column', alignItems: 'stretch', marginTop: 10 }}>
            <label style={{ minWidth: 0 }}>Organization ID</label>
            <input type="text" value={ssoTenantId} onChange={e => setSsoTenantId(e.target.value)}
              placeholder="e.g. acme" />
            <button type="button" className="primary" style={{ marginTop: 8 }} disabled={!ssoTenantId.trim()}
              onClick={() => { window.location.href = `/api/auth/sso/${encodeURIComponent(ssoTenantId.trim())}/login`; }}>
              Continue with SSO
            </button>
          </div>
        )}
      </div>
      <p className="auth-footer">RuleVis — Wazuh Rule Intelligence Platform</p>
    </div>
  );
}
