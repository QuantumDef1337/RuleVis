import {
  createContext, useCallback, useContext, useEffect, useState,
} from 'react';
import { authApi, UNAUTHORIZED_EVENT } from './api';
import type { AccessibleTenant, User } from './types';

interface AuthState {
  user: User | null;
  tenants: AccessibleTenant[];
  loading: boolean;
  refresh: () => Promise<void>;
  setSession: (user: User, tenants: AccessibleTenant[]) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [tenants, setTenants] = useState<AccessibleTenant[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const r = await authApi.me();
      setUser(r.user);
      setTenants(r.tenants);
    } catch {
      setUser(null);
      setTenants([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    const onUnauthorized = () => { setUser(null); setTenants([]); };
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  const setSession = (u: User, t: AccessibleTenant[]) => {
    setUser(u); setTenants(t); setLoading(false);
  };

  const logout = async () => {
    await authApi.logout().catch(() => {});
    setUser(null); setTenants([]);
  };

  return (
    <AuthContext.Provider value={{ user, tenants, loading, refresh, setSession, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
