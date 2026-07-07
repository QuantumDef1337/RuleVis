import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTenant } from '../lib/useTenant';
import { Toast } from '../components/settings/editors';
import WorkspaceTab from '../components/settings/WorkspaceTab';
import IntegrationsTab from '../components/settings/IntegrationsTab';
import UnmappedFilesTab from '../components/settings/UnmappedFilesTab';
import ProfileTab from '../components/settings/ProfileTab';
import UsersTab from '../components/settings/UsersTab';
import TenantsTab from '../components/settings/TenantsTab';
import AuditLogTab from '../components/settings/AuditLogTab';
import LoginActivityTab from '../components/settings/LoginActivityTab';
import SystemSettingsTab from '../components/settings/SystemSettingsTab';

type TabId = 'workspace' | 'integrations' | 'unmapped' | 'profile' | 'users' | 'tenants'
  | 'audit' | 'deletions' | 'logins' | 'system';

export default function SettingsPage() {
  const { can, isSuperAdmin } = useTenant();
  const [toast, setToast] = useState('');
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3500); };

  const manageSettings = can('manage_tenant_settings');
  const manageUsers = can('manage_tenant_users');
  const viewActivity = can('view_activity');

  const allTabs: { id: TabId; label: string; show: boolean }[] = [
    { id: 'workspace', label: 'Workspace', show: manageSettings },
    { id: 'integrations', label: 'Integrations', show: manageSettings },
    { id: 'unmapped', label: 'Unmapped files', show: manageSettings },
    { id: 'profile', label: 'My profile', show: true },
    { id: 'users', label: 'Team & access', show: manageUsers },
    { id: 'tenants', label: 'Tenants', show: isSuperAdmin },
    { id: 'audit', label: 'Audit log', show: viewActivity },
    { id: 'deletions', label: 'Deletion log', show: viewActivity },
    { id: 'logins', label: 'Login activity', show: isSuperAdmin },
    { id: 'system', label: 'System settings', show: isSuperAdmin },
  ];
  const tabs = allTabs.filter(t => t.show);

  const [searchParams] = useSearchParams();
  const tabParam = searchParams.get('tab') as TabId | null;
  const [active, setActive] = useState<TabId>(
    (tabParam && tabs.some(t => t.id === tabParam)) ? tabParam : (tabs[0]?.id ?? 'profile'));
  const current = tabs.find(t => t.id === active) ? active : (tabs[0]?.id ?? 'profile');

  return (
    <div className="page">
      <Toast msg={toast} />

      <div className="settings-tabs">
        {tabs.map(t => (
          <button key={t.id}
            className={`settings-tab ${current === t.id ? 'active' : ''}`}
            onClick={() => setActive(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      <div style={{ marginTop: 22 }}>
        {current === 'workspace' && <WorkspaceTab notify={notify} />}
        {current === 'integrations' && <IntegrationsTab notify={notify} />}
        {current === 'unmapped' && <UnmappedFilesTab notify={notify} />}
        {current === 'profile' && <ProfileTab notify={notify} />}
        {current === 'users' && <UsersTab notify={notify} />}
        {current === 'tenants' && <TenantsTab notify={notify} />}
        {current === 'audit' && <AuditLogTab />}
        {current === 'deletions' && <AuditLogTab deletionsOnly />}
        {current === 'logins' && <LoginActivityTab />}
        {current === 'system' && <SystemSettingsTab notify={notify} />}
      </div>
    </div>
  );
}
