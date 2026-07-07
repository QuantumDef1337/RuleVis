import { Navigate } from 'react-router-dom';
import { useAuth } from '../lib/auth';

/** Bare "/" for a signed-in user — send them into their first tenant. */
export default function RootRedirect() {
  const { tenants, loading } = useAuth();
  if (loading) return null;
  if (tenants.length === 0) return <Navigate to="/no-access" replace />;
  return <Navigate to={`/t/${tenants[0].id}`} replace />;
}
