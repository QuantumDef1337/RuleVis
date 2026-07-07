import { getCurrentTenantId } from './tenantContext';
import type {
  AccessibleTenant, ActivityEntry, ApiKey, AuditLogEntry, DiffResult, FileInfo,
  GithubSource, GraphEdge, GraphNode, Health, Heatmap, LoginActivityEntry,
  Manager, Overview, PlatformSettings, Product, RuleDetail, SearchResult,
  Settings, SsoConfig, Stats, TenantUser, User, Webhook,
} from './types';

/** Fired on any 401 so AuthProvider can clear state and redirect to /login,
 * without api.ts importing the auth context (would create a circular dep). */
const UNAUTHORIZED_EVENT = 'rulevis:unauthorized';

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...init, credentials: 'include' });
  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    throw new Error('Not authenticated');
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch { /* not json */ }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

const json = (body: unknown, method = 'POST'): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

/** Prefixes a path with the current tenant, e.g. t('overview') -> /api/t/<id>/overview */
function t(path: string): string {
  const tid = getCurrentTenantId();
  if (!tid) throw new Error('No tenant selected');
  return `/api/t/${encodeURIComponent(tid)}/${path}`;
}

export const api = {
  overview: () => req<Overview>(t('overview')),

  health: () => req<Health>(t('health')),

  activity: () => req<{ activity: ActivityEntry[] }>(t('activity')),

  products: () =>
    req<{ products: Product[]; unmapped_files: FileInfo[] }>(t('products')),

  files: () => req<{ files: FileInfo[] }>(t('files')),

  productGraph: (pid: string) =>
    req<{ product: Product; nodes: GraphNode[]; edges: GraphEdge[] }>(
      t(`products/${encodeURIComponent(pid)}/graph`)),

  graphByScope: (scope: string) =>
    req<{ scope: string; label: string; nodes: GraphNode[]; edges: GraphEdge[] }>(
      t(`graph?scope=${encodeURIComponent(scope)}`)),

  nodesRoot: () =>
    req<{ nodes: GraphNode[]; edges: GraphEdge[] }>(t('nodes?mode=root')),

  nodeChildren: (id: string, displayed: string[]) =>
    req<{ nodes: GraphNode[]; edges: GraphEdge[] }>(
      t(`nodes?id=${encodeURIComponent(id)}&neighbors=children&displayed=${displayed.join(',')}`)),

  nodeParents: (id: string, displayed: string[]) =>
    req<{ nodes: GraphNode[]; edges: GraphEdge[] }>(
      t(`nodes?id=${encodeURIComponent(id)}&neighbors=parents&displayed=${displayed.join(',')}`)),

  nodesBatch: (ids: string[], displayed: string[]) =>
    req<{ nodes: GraphNode[]; edges: GraphEdge[] }>(
      t(`nodes?ids=${ids.join(',')}&displayed=${displayed.join(',')}`)),

  nodeSearch: (id: string, displayed: string[]) =>
    req<{ nodes: GraphNode[]; edges: GraphEdge[] }>(
      t(`nodes?mode=search&id=${encodeURIComponent(id)}&displayed=${displayed.join(',')}`)),

  edgesAmong: (ids: string[]) =>
    req<{ edges: GraphEdge[] }>(t('edges'), json({ ids })),

  search: (q: string, product?: string, limit = 30) =>
    req<{ results: SearchResult[]; total: number }>(
      t(`rules/search?q=${encodeURIComponent(q)}${product ? `&product=${encodeURIComponent(product)}` : ''}&limit=${limit}`)),

  rule: (id: string) => req<RuleDetail>(t(`rules/${encodeURIComponent(id)}`)),

  stats: (product?: string) =>
    req<Stats>(t(`stats${product ? `?product=${encodeURIComponent(product)}` : ''}`)),

  heatmap: (blockSize: number) =>
    req<Heatmap>(t(`heatmap?block_size=${blockSize}`)),

  exportUrl: (fmt: string, scope: string) =>
    t(`export/${fmt}?scope=${encodeURIComponent(scope)}`),

  settings: () => req<Settings>(t('settings')),

  updateSettings: (patch: Partial<Settings>) =>
    req<Settings>(t('settings'), json(patch, 'PUT')),

  upsertProduct: (p: Partial<Product>) =>
    req<Product>(t('products-config'), json(p)),

  deleteProduct: (id: string) =>
    req<{ deleted: boolean }>(t(`products-config/${id}`), { method: 'DELETE' }),

  managers: () => req<{ managers: Manager[] }>(t('managers')),

  upsertManager: (m: Partial<Manager>) => req<Manager>(t('managers'), json(m)),

  deleteManager: (id: string) =>
    req<{ deleted: boolean }>(t(`managers/${id}`), { method: 'DELETE' }),

  testManager: (id: string) =>
    req<{ ok: boolean; info?: Record<string, unknown>; error?: string }>(
      t(`managers/${id}/test`), { method: 'POST' }),

  fetchManager: (id: string, opts?: { include_builtin?: boolean; include_custom?: boolean }) =>
    req<{ downloaded: number; skipped: number; total: number; errors: unknown[]; diff?: DiffResult }>(
      t(`managers/${id}/fetch`), json(opts ?? {})),

  githubSources: () => req<{ github_sources: GithubSource[] }>(t('github-sources')),

  upsertGithubSource: (s: Partial<GithubSource>) =>
    req<GithubSource>(t('github-sources'), json(s)),

  deleteGithubSource: (id: string) =>
    req<{ deleted: boolean }>(t(`github-sources/${id}`), { method: 'DELETE' }),

  testGithubSource: (id: string) =>
    req<{ ok: boolean; info?: Record<string, unknown>; error?: string }>(
      t(`github-sources/${id}/test`), { method: 'POST' }),

  fetchGithubSource: (id: string) =>
    req<{ downloaded: number; total: number; errors: unknown[]; overview?: Overview }>(
      t(`github-sources/${id}/fetch`), json({})),

  webhooks: () => req<{ webhooks: Webhook[]; available_events: string[] }>(t('webhooks')),

  upsertWebhook: (w: Partial<Webhook>) => req<Webhook>(t('webhooks'), json(w)),

  deleteWebhook: (id: string) =>
    req<{ deleted: boolean }>(t(`webhooks/${id}`), { method: 'DELETE' }),

  testWebhook: (id: string) =>
    req<{ ok: boolean; message: string }>(t(`webhooks/${id}/test`), { method: 'POST' }),

  apiKeys: () => req<{ api_keys: ApiKey[] }>(t('api-keys')),

  createApiKey: (name: string, role: string) =>
    req<ApiKey>(t('api-keys'), json({ name, role })),

  revokeApiKey: (id: string) =>
    req<{ revoked: boolean }>(t(`api-keys/${id}`), { method: 'DELETE' }),

  ssoConfig: () => req<SsoConfig>(t('sso-config')),

  updateSsoConfig: (patch: Partial<SsoConfig>) => req<SsoConfig>(t('sso-config'), json(patch, 'PUT')),

  rebuild: () => req<Overview>(t('rebuild'), { method: 'POST' }),

  upload: (files: FileList | File[]) => {
    const form = new FormData();
    Array.from(files).forEach(f => form.append('files', f));
    return req<{ saved: string[]; rejected: string[]; overview: Overview }>(
      t('upload'), { method: 'POST', body: form });
  },

  diff: (left: string, right: string) =>
    req<DiffResult>(t(`diff?left=${encodeURIComponent(left)}&right=${encodeURIComponent(right)}`)),

  // ---- tenant-scoped user management ----
  tenantUsers: () => req<{ users: TenantUser[] }>(t('users')),

  inviteTenantUser: (email: string, role: string) =>
    req<{ invite_url: string; token: string; expires_at: string }>(
      t('users/invite'), json({ email, role })),

  createTenantUser: (body: {
    username: string; display_name?: string; email?: string; password: string;
    role: string; permission_overrides?: string[];
    force_password_reset?: boolean; require_mfa?: boolean;
  }) => req<{ user: User }>(t('users/create'), json(body)),

  updateTenantUserRole: (uid: string, role: string, permission_overrides?: string[]) =>
    req<{ ok: boolean }>(t(`users/${uid}`), json({ role, permission_overrides }, 'PUT')),

  removeTenantUser: (uid: string) =>
    req<{ deleted: boolean }>(t(`users/${uid}`), { method: 'DELETE' }),

  tenantAuditLog: (deletionsOnly = false) =>
    req<{ entries: AuditLogEntry[] }>(
      t(`audit-log${deletionsOnly ? '?deletions_only=1' : ''}`)),
};

// ---------------- auth (not tenant-scoped) ----------------
export const authApi = {
  bootstrapStatus: () => req<{ needs_bootstrap: boolean }>('/api/auth/bootstrap-status'),

  bootstrap: (email: string, password: string, display_name?: string) =>
    req<{ user: User; tenants: AccessibleTenant[] }>(
      '/api/auth/bootstrap', json({ email, password, display_name })),

  login: (email: string, password: string, mfa_code?: string) =>
    req<{ user?: User; tenants?: AccessibleTenant[]; mfa_required?: boolean; mfa_setup_required?: boolean }>(
      '/api/auth/login', json({ email, password, mfa_code })),

  logout: () => req<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),

  me: () => req<{ user: User; tenants: AccessibleTenant[] }>('/api/auth/me'),

  changePassword: (new_password: string) =>
    req<{ ok: boolean }>('/api/auth/change-password', json({ new_password })),

  mfaSetup: () =>
    req<{ secret: string; uri: string; backup_codes: string[] }>(
      '/api/auth/mfa/setup', { method: 'POST' }),

  mfaEnable: (code: string) =>
    req<{ ok: boolean }>('/api/auth/mfa/enable', json({ code })),

  mfaDisable: () => req<{ ok: boolean }>('/api/auth/mfa/disable', { method: 'POST' }),

  getInvite: (token: string) =>
    req<{ email: string; role: string; tenant_name: string | null }>(
      `/api/invites/${encodeURIComponent(token)}`),

  acceptInvite: (token: string, password: string, display_name?: string) =>
    req<{ user: User; tenants: AccessibleTenant[] }>(
      `/api/invites/${encodeURIComponent(token)}/accept`, json({ password, display_name })),
};

// ---------------- platform admin (super_admin only) ----------------
export const superApi = {
  tenants: () => req<{ tenants: AccessibleTenant[] }>('/api/super/tenants'),

  createTenant: (name: string) =>
    req<AccessibleTenant>('/api/super/tenants', json({ name })),

  deleteTenant: (id: string) =>
    req<{ deleted: boolean }>(`/api/super/tenants/${id}`, { method: 'DELETE' }),

  users: () => req<{ users: User[] }>('/api/super/users'),

  updateUser: (uid: string, patch: Partial<Pick<User, 'is_super_admin' | 'is_active' | 'display_name'>>) =>
    req<User>(`/api/super/users/${uid}`, json(patch, 'PUT')),

  deleteUser: (uid: string) =>
    req<{ deleted: boolean }>(`/api/super/users/${uid}`, { method: 'DELETE' }),

  loginActivity: () => req<{ entries: LoginActivityEntry[] }>('/api/super/login-activity'),

  auditLog: (deletionsOnly = false) =>
    req<{ entries: AuditLogEntry[] }>(
      `/api/super/audit-log${deletionsOnly ? '?deletions_only=1' : ''}`),

  platformSettings: () => req<PlatformSettings>('/api/platform-settings'),

  updatePlatformSettings: (patch: Partial<PlatformSettings>) =>
    req<PlatformSettings>('/api/platform-settings', json(patch, 'PUT')),
};

export { UNAUTHORIZED_EVENT };
