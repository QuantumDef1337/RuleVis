import { useAuth } from '../lib/auth';

export default function NoAccess() {
  const { user, logout } = useAuth();
  return (
    <div className="page" style={{ textAlign: 'center', marginTop: 60 }}>
      <h2>No tenant access yet</h2>
      <p className="muted">
        Signed in as {user?.email}, but you aren't assigned to any tenant. Ask a tenant
        or platform administrator to invite you.
      </p>
      <button onClick={logout} style={{ marginTop: 12 }}>Sign out</button>
    </div>
  );
}
