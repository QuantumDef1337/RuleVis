/**
 * Mirrors src/internal/authz.py's ROLE_PERMISSIONS. This is UI convenience
 * only (hiding buttons a role can't use) — the server enforces the real
 * boundary on every request, so drift here only affects polish, not security.
 */
import type { TenantRole } from './types';

export type Permission = 'view_rules' | 'export' | 'manage_tenant_settings'
  | 'manage_tenant_users' | 'view_activity';

const ROLE_PERMISSIONS: Record<Exclude<TenantRole, 'super_admin'>, Permission[]> = {
  tenant_admin: ['view_rules', 'export', 'manage_tenant_settings', 'manage_tenant_users', 'view_activity'],
  analyst: ['view_rules', 'export'],
  viewer: ['view_rules'],
};

export function can(role: TenantRole | undefined | null, isSuperAdmin: boolean, perm: Permission): boolean {
  if (isSuperAdmin) return true;
  if (!role || role === 'super_admin') return false;
  return ROLE_PERMISSIONS[role].includes(perm);
}
