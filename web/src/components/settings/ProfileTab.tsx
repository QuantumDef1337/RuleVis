import { useState } from 'react';
import { authApi } from '../../lib/api';
import { useAuth } from '../../lib/auth';
import { IconCheckCircle, IconShieldAlert } from '../../icons';

export default function ProfileTab({ notify }: { notify: (m: string) => void }) {
  const { user, refresh } = useAuth();

  // password change
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [pwBusy, setPwBusy] = useState(false);
  const [pwErr, setPwErr] = useState('');

  const changePassword = async () => {
    setPwErr('');
    if (newPw !== confirmPw) { setPwErr('Passwords do not match.'); return; }
    setPwBusy(true);
    try {
      await authApi.changePassword(newPw);
      setNewPw(''); setConfirmPw('');
      notify('Password changed.');
    } catch (e) {
      setPwErr(String((e as Error).message ?? e));
    } finally {
      setPwBusy(false);
    }
  };

  // MFA enrollment
  const [enroll, setEnroll] = useState<{ secret: string; uri: string; backup_codes: string[] } | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  const [mfaErr, setMfaErr] = useState('');
  const [mfaBusy, setMfaBusy] = useState(false);

  const startEnroll = async () => {
    setMfaErr('');
    try {
      const r = await authApi.mfaSetup();
      setEnroll(r);
    } catch (e) {
      setMfaErr(String((e as Error).message ?? e));
    }
  };

  const confirmEnroll = async () => {
    setMfaErr(''); setMfaBusy(true);
    try {
      await authApi.mfaEnable(mfaCode);
      setEnroll(null); setMfaCode('');
      await refresh();
      notify('Two-factor authentication enabled.');
    } catch (e) {
      setMfaErr(String((e as Error).message ?? e));
    } finally {
      setMfaBusy(false);
    }
  };

  const disableMfa = async () => {
    await authApi.mfaDisable();
    await refresh();
    notify('Two-factor authentication disabled.');
  };

  return (
    <div style={{ maxWidth: 560 }}>
      <h2 style={{ margin: '0 0 4px' }}>My profile</h2>
      <p className="muted" style={{ margin: 0, fontSize: 13 }}>
        {user?.display_name || user?.email}
        {user?.is_super_admin && <span className="badge violet" style={{ marginLeft: 8 }}>super admin</span>}
      </p>

      {/* ---- Change password ---- */}
      <div className="card" style={{ marginTop: 20 }}>
        <h3 style={{ margin: '0 0 12px' }}>Change password</h3>
        <div className="form-row"><label>New password</label>
          <input type="password" value={newPw} onChange={e => setNewPw(e.target.value)} /></div>
        <div className="form-row"><label>Confirm</label>
          <input type="password" value={confirmPw} onChange={e => setConfirmPw(e.target.value)} /></div>
        {pwErr && <p style={{ color: 'var(--red)', fontSize: 13 }}>{pwErr}</p>}
        <button className="primary" disabled={!newPw || pwBusy} onClick={changePassword}>
          {pwBusy ? 'Saving…' : 'Update password'}
        </button>
      </div>

      {/* ---- MFA ---- */}
      <div className="card" style={{ marginTop: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <h3 style={{ margin: 0 }}>Two-factor authentication</h3>
          {user?.mfa_enabled
            ? <span className="badge green"><IconCheckCircle size={12} /> enabled</span>
            : <span className="badge amber"><IconShieldAlert size={12} /> off</span>}
        </div>
        <p className="muted" style={{ fontSize: 13, marginTop: 8 }}>
          Protect your account with a time-based one-time code from an authenticator app
          (Google Authenticator, Authy, 1Password, …).
        </p>

        {user?.mfa_enabled && !enroll && (
          <button className="danger" onClick={disableMfa}>Disable 2FA</button>
        )}

        {!user?.mfa_enabled && !enroll && (
          <button className="primary" onClick={startEnroll}>Set up 2FA</button>
        )}

        {enroll && (
          <div style={{ marginTop: 12 }}>
            <p style={{ fontSize: 13, margin: '0 0 8px' }}>
              1. Scan this QR code, or enter the secret manually, in your authenticator app:
            </p>
            <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
              <img alt="MFA QR code" width={160} height={160}
                style={{ background: '#fff', borderRadius: 8, padding: 6 }}
                src={`https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=${encodeURIComponent(enroll.uri)}`} />
              <div>
                <div className="faint" style={{ fontSize: 11 }}>SECRET</div>
                <code style={{ fontSize: 13, wordBreak: 'break-all' }}>{enroll.secret}</code>
              </div>
            </div>

            <p style={{ fontSize: 13, margin: '14px 0 6px' }}>
              2. Save these backup codes somewhere safe — each works once if you lose your device:
            </p>
            <div className="backup-codes">
              {enroll.backup_codes.map(c => <code key={c}>{c}</code>)}
            </div>

            <p style={{ fontSize: 13, margin: '14px 0 6px' }}>3. Enter the current 6-digit code to finish:</p>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input type="text" placeholder="123456" value={mfaCode} maxLength={6}
                onChange={e => setMfaCode(e.target.value)} style={{ width: 120 }} />
              <button className="primary" disabled={mfaCode.length < 6 || mfaBusy} onClick={confirmEnroll}>
                {mfaBusy ? 'Verifying…' : 'Enable 2FA'}
              </button>
              <button onClick={() => { setEnroll(null); setMfaCode(''); }}>Cancel</button>
            </div>
            {mfaErr && <p style={{ color: 'var(--red)', fontSize: 13 }}>{mfaErr}</p>}
          </div>
        )}
        {mfaErr && !enroll && <p style={{ color: 'var(--red)', fontSize: 13 }}>{mfaErr}</p>}
      </div>
    </div>
  );
}
