import { useEffect, useState } from 'react';
import { superApi } from '../../lib/api';
import type { PlatformSettings } from '../../lib/types';

const FIELDS: { key: keyof PlatformSettings; label: string; hint: string; group: string }[] = [
  { group: 'Retention', key: 'audit_log_retention_days', label: 'Audit log (days)', hint: 'How long audit entries are kept' },
  { group: 'Retention', key: 'deletion_log_retention_days', label: 'Deletion log (days)', hint: 'How long deletion entries are kept' },
  { group: 'Retention', key: 'login_history_retention_days', label: 'Login history (days)', hint: 'How long login attempts are kept' },
  { group: 'Account lockout', key: 'lockout_threshold', label: 'Failed attempts threshold', hint: 'Lock account after this many failed logins' },
  { group: 'Account lockout', key: 'lockout_duration_minutes', label: 'Lockout duration (minutes)', hint: 'How long an account stays locked' },
  { group: 'Password policy', key: 'password_min_length', label: 'Minimum length', hint: 'Recommended: 12 or higher' },
  { group: 'Password policy', key: 'password_history_depth', label: 'History depth', hint: 'Block reuse of the last N passwords' },
  { group: 'Session & MFA', key: 'session_idle_timeout_minutes', label: 'Session idle timeout (minutes)', hint: 'Auto sign-out after inactivity' },
  { group: 'Session & MFA', key: 'mfa_backup_codes_count', label: 'MFA backup codes count', hint: 'One-time recovery codes generated per user' },
];

export default function SystemSettingsTab({ notify }: { notify: (m: string) => void }) {
  const [settings, setSettings] = useState<PlatformSettings | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { superApi.platformSettings().then(setSettings).catch(() => {}); }, []);

  const set = (k: keyof PlatformSettings, v: number) =>
    setSettings(s => (s ? { ...s, [k]: v } : s));

  const save = async () => {
    if (!settings) return;
    setBusy(true);
    try {
      const saved = await superApi.updatePlatformSettings(settings);
      setSettings(saved);
      notify('System settings saved.');
    } finally {
      setBusy(false);
    }
  };

  if (!settings) return <div className="empty">Loading…</div>;

  const groups = [...new Set(FIELDS.map(f => f.group))];

  return (
    <div style={{ maxWidth: 720 }}>
      <h2 style={{ margin: '0 0 4px' }}>System security settings</h2>
      <p className="muted" style={{ margin: '0 0 8px', fontSize: 13 }}>
        Platform-wide security policy. Changes apply immediately; retention is enforced when these logs are next viewed.
      </p>

      {groups.map(group => (
        <div key={group} className="card" style={{ marginTop: 16 }}>
          <h3 style={{ margin: '0 0 12px', fontSize: 13, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--text-faint)' }}>
            {group}
          </h3>
          <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
            {FIELDS.filter(f => f.group === group).map(f => (
              <div key={f.key}>
                <label className="meta-label" style={{ display: 'block', marginBottom: 4 }}>{f.label}</label>
                <input type="number" min={0} style={{ width: '100%' }}
                  value={settings[f.key]} onChange={e => set(f.key, parseInt(e.target.value || '0', 10))} />
                <div className="faint" style={{ fontSize: 11, marginTop: 3 }}>{f.hint}</div>
              </div>
            ))}
          </div>
        </div>
      ))}

      <button className="primary" style={{ marginTop: 18 }} disabled={busy} onClick={save}>
        {busy ? 'Saving…' : 'Save settings'}
      </button>
    </div>
  );
}
