import { useEffect, useState } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { authApi } from '../lib/api';
import { useAuth } from '../lib/auth';

/**
 * Top-level gate: checks whether the platform has ever been set up
 * (bootstrap-status) before falling back to the normal auth check, so a
 * fresh install lands on /bootstrap instead of a login form with no
 * accounts to log into.
 */
export default function RequireAuth() {
  const { user, loading } = useAuth();
  const location = useLocation();
  const [needsBootstrap, setNeedsBootstrap] = useState<boolean | null>(null);

  useEffect(() => {
    if (!user) {
      authApi.bootstrapStatus().then(r => setNeedsBootstrap(r.needs_bootstrap)).catch(() => setNeedsBootstrap(false));
    }
  }, [user]);

  if (loading || (!user && needsBootstrap === null)) {
    return <div className="empty" style={{ margin: 40 }}>Loading…</div>;
  }
  if (!user) {
    if (needsBootstrap) return <Navigate to="/bootstrap" replace />;
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  }
  return <Outlet />;
}
