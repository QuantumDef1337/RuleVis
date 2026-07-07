import { useParams } from 'react-router-dom';
import { useAuth } from './auth';
import { can, Permission } from './permissions';
import type { AccessibleTenant } from './types';

/** Current tenant (from the /t/:tenantId/* route) plus a permission-check
 * helper bound to the user's role in that tenant. */
export function useTenant(): {
  tenant: AccessibleTenant | undefined;
  tenantId: string | undefined;
  can: (perm: Permission) => boolean;
  isSuperAdmin: boolean;
} {
  const { tenantId } = useParams();
  const { user, tenants } = useAuth();
  const tenant = tenants.find(t => t.id === tenantId);
  const isSuperAdmin = !!user?.is_super_admin;
  return {
    tenant,
    tenantId,
    isSuperAdmin,
    can: (perm: Permission) => can(tenant?.role, isSuperAdmin, perm),
  };
}
