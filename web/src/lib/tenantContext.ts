/**
 * The API client is a module-level singleton (existing call sites do
 * `import { api } from './api'; api.products()` all over the app), so rather
 * than threading a tenantId prop through every page/component, the current
 * tenant is tracked here and the api layer reads it when building URLs.
 * TenantLayout (mounted once per /t/:tenantId/* route) keeps this in sync.
 */
let currentTenantId: string | null = null;

export function setCurrentTenantId(id: string | null): void {
  currentTenantId = id;
}

export function getCurrentTenantId(): string | null {
  return currentTenantId;
}
