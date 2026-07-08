import { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet, useLocation, useParams } from 'react-router-dom';
import {
  IconChevronDown, IconCompare, IconGraph, IconHome, IconLogOut, IconMenu, IconMoon,
  IconRules, IconSettings, IconSun,
} from '../icons';
import { useAuth } from '../lib/auth';
import { can } from '../lib/permissions';
import Logo from './Logo';
import TenantSwitcher from './TenantSwitcher';

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState<string>(
    () => localStorage.getItem('rulevis-theme') ?? 'dark');
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('rulevis-theme', theme);
  }, [theme]);
  return [theme, () => setTheme(t => (t === 'dark' ? 'light' : 'dark'))];
}

export default function Shell() {
  const { tenantId } = useParams();
  const { user, tenants, logout } = useAuth();
  const [theme, toggleTheme] = useTheme();
  const [navOpen, setNavOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const accountRef = useRef<HTMLDivElement>(null);
  const location = useLocation();

  useEffect(() => setNavOpen(false), [location.pathname]);
  useEffect(() => setAccountOpen(false), [location.pathname]);

  useEffect(() => {
    if (!accountOpen) return;
    const onDocClick = (e: MouseEvent) => {
      if (accountRef.current && !accountRef.current.contains(e.target as Node)) setAccountOpen(false);
    };
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, [accountOpen]);

  const tenant = tenants.find(t => t.id === tenantId);
  const isSuperAdmin = !!user?.is_super_admin;
  const canManageUsers = can(tenant?.role, isSuperAdmin, 'manage_tenant_users');

  const base = `/t/${tenantId}`;
  const NAV = [
    { to: base, label: 'Home', icon: <IconHome />, end: true },
    { to: `${base}/rules`, label: 'Rules', icon: <IconRules /> },
    { to: `${base}/visualizer`, label: 'Visualizer', icon: <IconGraph /> },
    { to: `${base}/compare`, label: 'Compare', icon: <IconCompare /> },
    { to: `${base}/settings`, label: 'Settings', icon: <IconSettings /> },
  ];

  return (
    <div className="shell">
      <aside className={`sidebar ${navOpen ? 'open' : ''}`}>
        <div className="brand">
          <Logo size={28} />
          <div>
            RuleVis
            <small>WAZUH RULE INTELLIGENCE</small>
          </div>
        </div>

        <TenantSwitcher />

        {NAV.map(item => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}

        <div className="spacer" />

        <div className="account-menu" ref={accountRef}>
          {accountOpen && (
            <div className="account-popover">
              <div className="account-popover-head">
                <div className="user-avatar">
                  {(user?.display_name || user?.email || '?').trim()[0]?.toUpperCase()}
                </div>
                <div style={{ minWidth: 0 }}>
                  <div className="user-name">{user?.display_name || user?.email}</div>
                  <div className="user-email">{user?.email}</div>
                </div>
              </div>
              <div className="user-roles" style={{ padding: '8px 12px 0' }}>
                {isSuperAdmin && <span className="badge violet">super admin</span>}
                {tenant && tenant.role !== 'super_admin' && <span className="badge">{tenant.role}</span>}
              </div>
              <div className="account-popover-sep" />
              <button className="account-popover-item" onClick={toggleTheme}>
                {theme === 'dark' ? <IconSun size={14} /> : <IconMoon size={14} />}
                {theme === 'dark' ? 'Light mode' : 'Dark mode'}
              </button>
              <button className="account-popover-item danger" onClick={logout}>
                <IconLogOut size={14} />
                Sign out
              </button>
            </div>
          )}
          <button className="user-card" onClick={() => setAccountOpen(o => !o)}>
            <div className="user-avatar">
              {(user?.display_name || user?.email || '?').trim()[0]?.toUpperCase()}
            </div>
            <div style={{ minWidth: 0, flex: 1, textAlign: 'left' }}>
              <div className="user-name">{user?.display_name || user?.email}</div>
              <div className="user-roles">
                {isSuperAdmin && <span className="badge violet">super admin</span>}
                {tenant && tenant.role !== 'super_admin' && <span className="badge">{tenant.role}</span>}
              </div>
            </div>
            <IconChevronDown size={14} />
          </button>
        </div>
      </aside>

      <main className="main">
        <div className="topbar">
          <button className="icon-btn menu-btn" onClick={() => setNavOpen(o => !o)} aria-label="Menu">
            <IconMenu />
          </button>
          <h1>{NAV.find(n => location.pathname === n.to
            || (!n.end && location.pathname.startsWith(n.to)))?.label ?? 'RuleVis'}</h1>
          <div className="grow" />
          {canManageUsers && (
            <NavLink to={`${base}/settings`} className="muted" style={{ fontSize: 12 }}>
              Team &amp; access
            </NavLink>
          )}
        </div>
        <Outlet />
      </main>
    </div>
  );
}
