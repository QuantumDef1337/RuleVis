import { Navigate, Outlet, useParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { setCurrentTenantId } from '../lib/tenantContext';

/**
 * Mounted once per /t/:tenantId/* route. Verifies the current user actually
 * has access to this tenant (client-side convenience — the server enforces
 * the real boundary on every request) and points the api layer's tenant
 * context at it. Set synchronously in the render body (not just useEffect)
 * so the very first API call fired by a child page already uses the right
 * tenant id.
 */
export default function TenantLayout() {
  const { tenantId } = useParams();
  const { user, tenants, loading } = useAuth();

  if (loading) return null;

  const tenant = tenants.find(t => t.id === tenantId);
  if (!tenant && !user?.is_super_admin) {
    return <Navigate to="/no-access" replace />;
  }

  setCurrentTenantId(tenantId ?? null);
  return <Outlet />;
}
