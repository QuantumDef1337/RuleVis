# RuleVis — Product & Engineering Guide

**Purpose of this document:** a complete, end-to-end reference for RuleVis — what it is, how it's built, every feature and why it exists, every bug found and fixed along the way, and how to install/run it. A new engineer should be able to read this document and rebuild the product from scratch, or safely extend it.

---

## 1. What RuleVis Is

RuleVis is a **multi-tenant SIEM rule-intelligence platform for Wazuh**. It ingests Wazuh detection rule XML (from local files, a live Wazuh manager API, or a GitHub repository), parses the rule hierarchy into a dependency graph, and gives security teams:

- An interactive **visual graph explorer** of rules and their parent/child relationships.
- **Health analytics**: broken dependencies, duplicate rule IDs, disabled parent rules, orphan rules, MITRE ATT&CK coverage, compliance-tag coverage.
- **Rule comparison** between two snapshots/sources (diffing).
- **Export** in multiple formats (documentation, MITRE Navigator-style data, etc.).
- Full **multi-tenant RBAC**: isolated workspaces ("tenants") each with their own rules, products, managers, users, and settings, plus a platform-wide super-admin layer.
- Enterprise features: MFA, account lockout, audit logging, per-IP rate limiting, secrets encryption at rest, webhooks, a programmatic API, and OIDC single sign-on.

Target users: SOC analysts (explore/understand rules), SOC managers (health/coverage reporting, change auditing), and platform/security engineers (multi-tenant administration, integrations).

---

## 2. Technology Stack

| Layer | Technology | Notes |
|---|---|---|
| Backend | Python 3.9+, Flask | Single Flask app (`internal/visualizer.py`), served via **waitress** in production (falls back to Flask's dev server if waitress isn't installed) |
| Identity DB | SQLite by default, or **any SQLAlchemy-supported DB** (Postgres tested) | Set `RULEVIS_DATABASE_URL` env var to point at Postgres for multi-process/multi-host deployments |
| Per-tenant config | Flat JSON files on disk (`~/.rulevis/tenants/<id>/config.json`) | Deliberately NOT in the DB — predates multi-tenancy, kept for simplicity of products/managers/paths config |
| Graph engine | `networkx` (`MultiDiGraph`) | Rules are nodes, `if_sid`/`if_matched_sid`/`if_group`/`if_matched_group` relations are edges |
| Frontend | React + TypeScript + Vite | Built to static assets served directly by Flask — no separate frontend server in production |
| Styling | Hand-written CSS (`app.css`), CSS variables for theming (dark/light) | No CSS framework |
| Icons | `lucide-react`, wrapped in `web/src/icons.tsx` for a stable internal naming layer |
| Auth crypto | `werkzeug.security` (password hashing), stdlib `hmac`/`hashlib` (hand-rolled TOTP), `cryptography` (Fernet, secrets-at-rest), `python-jose` (OIDC JWT/JWKS verification) |
| Testing | `pytest` (backend only; no frontend test suite yet) |

---

## 3. High-Level Architecture

```
                        ┌─────────────────────────────┐
                        │        React SPA (web/)      │
                        │  built → src/internal/static/ │
                        │           dist/               │
                        └───────────────┬───────────────┘
                                        │ fetch() JSON, cookie session
                                        ▼
                        ┌─────────────────────────────┐
                        │   Flask app (visualizer.py)  │
                        │  before_request: resolves     │
                        │  session OR API key → g.user, │
                        │  g.tenant_id, g.ws             │
                        └───────┬───────────────┬───────┘
                                │               │
                 ┌──────────────▼───┐   ┌───────▼─────────────┐
                 │  db.py (identity) │   │ TenantManager        │
                 │  SQLAlchemy Core  │   │ → Workspace per      │
                 │  users, tenants,  │   │   tenant (lazy,       │
                 │  roles, audit,    │   │   cached)             │
                 │  sessions data    │   │   → Config (JSON)     │
                 └───────────────────┘   │   → networkx graph    │
                                          └───────────────────────┘
```

Two background daemon threads run inside the same process (started in `create_app()`):
1. **Auto-sync loop** (`_auto_sync_loop`, every 60s) — checks every tenant's managers/GitHub sources for `auto_sync=True` entries whose interval has elapsed, and syncs them.
2. **Retention sweep loop** (`_retention_sweep_loop`, every 3600s) — enforces audit-log/login-history/rate-limit-table retention on a fixed schedule (not just when a user happens to open a Settings page).

---

## 4. Multi-Tenancy Model

- A **tenant** is an isolated workspace: its own rule files, product mappings, Wazuh managers, GitHub sources, webhooks, SSO config, and case tags.
- Tenant identity/metadata (id, name, slug, active flag) lives in the SQLite/Postgres `tenants` table.
- Tenant *content* config lives in `~/.rulevis/tenants/<tenant_id>/config.json` (see `internal/config.py`), with cached rule downloads under `.../cache/<manager_id>/` and manual uploads under `.../uploads/`.
- `TenantManager` (`internal/tenancy.py`) lazily builds and caches one `Workspace` object per tenant (thread-safe via a lock), each holding its own `networkx` graph. `tenant_manager.invalidate(tenant_id)` forces a rebuild (used after tenant deletion).
- The very first tenant is called `"default"` — created during migration from the original single-tenant version of RuleVis (see §14, migration history) or on first bootstrap. **The `default` tenant cannot be deleted** (enforced in the delete-tenant route).
- Deleting a tenant removes both its DB row **and** its entire on-disk directory (`config.delete_tenant_dir()`) — this was a bug fixed mid-project (see §13).

---

## 5. RBAC & Permissions Model

**Roles** (`internal/authz.py`):
- `super_admin` — a **platform-wide boolean flag** on the user row (`users.is_super_admin`), not a tenant role. Bypasses all per-tenant checks and sees every tenant.
- `tenant_admin`, `analyst`, `viewer` — scoped **per tenant** via the `user_tenant_roles` table. The same user can be `tenant_admin` in one tenant and `viewer` in another.

**Permissions** (enum): `view_rules`, `export`, `manage_tenant_settings`, `manage_tenant_users`, `view_activity`.

**Role → permission matrix:**

| Role | view_rules | export | manage_tenant_settings | manage_tenant_users | view_activity |
|---|---|---|---|---|---|
| tenant_admin | ✅ | ✅ | ✅ | ✅ | ✅ |
| analyst | ✅ | ✅ | ❌ | ❌ | ❌ |
| viewer | ✅ | ❌ | ❌ | ❌ | ❌ |

**Per-user permission overrides**: a `user_tenant_roles.permission_overrides` JSON column lets an admin grant *extra* permissions to a specific user beyond their role (e.g. a `viewer` who can also `export`), without bumping their whole role. `authz.role_has_permission(role, perm, overrides)` checks the override set first, then falls back to the role matrix.

**Enforcement**: every tenant-scoped route is decorated `@require_permission(Permission.X)`. The decorator (in order):
1. Rejects if not authenticated.
2. If an API key is in play (`g.api_key_role`), checks that key's role directly (no overrides for API keys — kept simple).
3. If `user["is_super_admin"]`, allow.
4. Otherwise looks up `db.get_user_tenant_access(user_id, tenant_id)` and checks role + overrides.

Platform-only routes use `@require_super_admin`. Routes needing just "any logged-in user, no tenant" use `@require_login`.

---

## 6. Authentication & Security Features

### 6.1 Session-based login
- Email **or username** + password (`db.verify_login`) — both looked up case-insensitively via `LOWER()` comparisons (portable across SQLite/Postgres).
- Flask signed-cookie sessions; `SECRET_KEY` persisted once at `~/.rulevis/secret_key` (never regenerated — regenerating would invalidate every session on every restart).
- Idle session timeout (`platform_settings.session_idle_timeout_minutes`, default 30) — enforced in `before_request`.

### 6.2 MFA (TOTP)
- Hand-rolled RFC 6238 TOTP implementation (`internal/totp.py`) — no external MFA library, just stdlib `hmac`/`hashlib`. Verified against `pyotp` for correctness during development, then `pyotp` was removed (dev-time only dependency).
- QR provisioning via `otpauth://` URI rendered through `api.qrserver.com`.
- Backup codes: generated, hashed with `werkzeug.security.generate_password_hash` before storage, single-use (consumed and removed on use).
- **`mfa_required`** flag per user (settable at creation time) — nudges the user to `/settings?tab=profile` after login if MFA isn't enrolled yet. **Known limitation:** this is a nudge, not a hard gate — nothing currently stops the user from navigating away without enrolling.

### 6.3 Account lockout & password policy
- `platform_settings`: `lockout_threshold` (default 5), `lockout_duration_minutes` (default 15), `password_min_length` (default 12), `password_history_depth` (default 5, prevents password reuse).
- `db.register_failed_login` / `db.reset_failed_login` / `db.is_locked_out` implement per-account lockout.

### 6.4 Per-IP login rate limiting
- Separate from account lockout — stops **credential stuffing across many different accounts from one IP**, which per-account lockout alone doesn't catch.
- Stored in the database (`login_ip_failures` table), **not** an in-process dict — this matters because an in-memory limiter only sees requests that land on that one process; the moment you run more than one worker process or host, each gets its own blind spot. `db.is_ip_rate_limited(ip, max_failures, window_seconds)` / `db.register_ip_login_failure(ip)`. Default: 20 failures / 15 minutes → HTTP 429.
- Table is swept on the retention loop's schedule (`db.sweep_ip_login_failures`).

### 6.5 Secrets encryption at rest
- **This was the single biggest security gap found in review**: Wazuh manager passwords and GitHub tokens were originally stored in **plaintext** in each tenant's `config.json`.
- Fixed with `internal/crypto.py`: Fernet (AES-128-CBC + HMAC-SHA256) keyed by SHA-256 of the app's existing `secret_key` (no separate key to generate/rotate/lose).
- `config.py`'s `upsert_manager`/`upsert_github_source`/`upsert_webhook`/`set_sso_config` encrypt the secret field before writing to disk; `wazuh_api.client_from_config`/`github_source.client_from_config`/`webhooks.dispatch_event` decrypt at the single point of actual use.
- **Backward compatible**: `crypto.decrypt()` falls back to returning the input unchanged if it's not a valid Fernet token (i.e. pre-existing plaintext value) — upgrading never breaks an existing manager connection; it's silently re-encrypted the next time it's saved through the UI.

### 6.6 Audit logging
- `db.log_audit(action, actor_user_id, actor_email, target_type, target_id, details, tenant_id, ip_address)` — one central function, called from a `_log_audit` wrapper inside `create_app()` that auto-fills `ip_address` from the request and (see §6.8) fires webhooks.
- **Deletion Log** is just the same audit log filtered to `action LIKE 'delete_%'` — a dedicated view because deletions are the one class of action that's often irreversible, so an admin investigating "who removed X" shouldn't have to scroll past routine syncs/logins to find it.
- Manager/GitHub syncs log a **full diff** (added/removed/changed rule IDs with which fields changed) as JSON in `details` — not just a count — so "what changed" is always answerable from the audit log, not just from a vague activity-feed line.

### 6.7 Login activity monitoring
- Every login attempt (success/failure, reason, IP, user-agent) recorded in `login_activity`.
- Frontend tab supports filtering (result, free-text search on email/IP) and **suspicious-activity flagging**: an account with 3+ failed attempts, or failures from 3+ distinct IPs, gets a visible warning badge.

### 6.8 Webhooks (outbound integrations)
- Per-tenant, event-filtered (`internal/webhooks.py`): `sync_manager[_failed|_skipped]`, `sync_github_source[_failed|_skipped]`, `delete_product`, `delete_manager`, `delete_github_source`, `delete_tenant`, `delete_user`.
- Three payload formats: `generic` (JSON, for ServiceNow/Jira/n8n/custom), `slack` (`{"text": ...}`), `teams` (MessageCard format).
- HMAC-SHA256 signed via `X-RuleVis-Signature` header when a per-webhook secret is set (same pattern as GitHub/Stripe webhooks) — secret encrypted at rest like manager passwords.
- Dispatched **fire-and-forget from a background thread** (`_log_audit` spawns `threading.Thread(target=webhooks.dispatch_event, ...)`) — a slow/dead endpoint must never block or fail the request that triggered the event.

### 6.9 Public API (API keys)
- `internal/db.py`: `api_keys` table, `create_api_key`/`list_api_keys`/`revoke_api_key`/`verify_api_key`.
- Keys look like `rvk_<32-byte-urlsafe-random>`; only a **SHA-256 hash** is stored (deterministic, not salted — unlike passwords, a high-entropy random token doesn't need per-value salting, and a deterministic hash is what makes O(1) lookup-by-value possible for authenticating every request).
- Scoped to exactly one tenant and one role (`tenant_admin`/`analyst`/`viewer`) at creation time.
- Auth via `Authorization: Bearer rvk_...` header, checked in `before_request` before falling back to session-cookie auth. Cannot reach `/api/super/*` routes (synthetic user has `is_super_admin=False`) or any tenant other than the one it was minted for.

### 6.10 SSO (OpenID Connect)
- `internal/oidc.py` — Authorization Code flow, works with any standard OIDC IdP (Okta, Azure AD/Entra ID, Google Workspace, Auth0, Keycloak, plain Google `accounts.google.com`).
- Per-tenant config (`Config.sso` / `set_sso_config`): `enabled`, `issuer`, `client_id`, `client_secret` (encrypted at rest), `auto_provision_role`.
- Flow: `/api/auth/sso/<tenant_id>/login` (fetches IdP discovery doc, redirects to its authorize endpoint with a CSRF `state` stored in the session) → `/api/auth/sso/<tenant_id>/callback` (validates `state`, exchanges the code for tokens, **verifies the ID token's RS256 signature against the IdP's live JWKS using `python-jose`** — deliberately not hand-rolled, since JWT signature verification is exactly the kind of crypto code that should use a vetted library) → finds-or-creates the user by email, assigns `auto_provision_role` if they have no existing tenant access, establishes a normal session.
- **Deliberately does not implement SAML** — a separate, much larger effort (XML signing/parsing, metadata exchange, an ACS endpoint) that would need its own dedicated pass.
- **Known gap**: no domain restriction (`hd` claim) or `email_verified` check yet — anyone reaching the flow with a valid account at the configured IdP gets auto-provisioned. Discussed but not yet implemented.

---

## 7. Feature Catalog (by page)

### Home (`/t/:tenantId`)
Platform metrics (total/custom/built-in rules, files, products, MITRE techniques, compliance frameworks, dependencies, groups), rule-health cards (broken dependencies, duplicate IDs, disabled parents, orphans, MITRE/compliance gaps), MITRE/compliance coverage bars, dependency-chain stats, a mini graph preview, product overview cards, and a **Recent Activity** feed. Activity entries for sync/import events link ("What changed?") into the Audit Log tab (deep-linked via `?tab=audit`), closing the loop between "something changed" and "here's exactly what."

### Rules (`/t/:tenantId/rules`)
Product-organized browse view. Each product card shows Total rules / Production rules / clickable file count (opens a modal listing every mapped file) — this exact card pattern was later reused for the Workspace tab's product cards for consistency.

### Visualizer (`/t/:tenantId/visualizer[/:productId]`)
The core graph explorer — force/hierarchical/radial layouts, search, filters, focus mode, multi-select, stats panel, heatmap, export. Clicking a node opens the **Rule Detail panel**, redesigned for readability into three columns:
1. **Summary card** — title, severity as "level 5 · Medium" (not a bare number), rule type (atomic/correlation) with a one-line plain-English explanation, alert/production-tag status, file/groups.
2. **Hierarchy** — "Parent rules (must match first, if any)" → pinned "this rule" box → "Sub-rules (build on top of this one)". Each ancestor/child card collapsed by default; click to expand its own conditions.
3. **"What this rule means"** (MITRE + compliance tags) then **"Everything that must be true to fire this alert"** — the full ancestor condition chain flattened into one continuously-numbered checklist (not restarting at 1 per rule), explicitly framed as "read top to bottom."

### Compare (`/t/:tenantId/compare`)
Diffs two rule sets/snapshots.

### Settings (`/t/:tenantId/settings`) — tabbed, permission-gated
- **Workspace** — Products (file mapping, rule counts), Case tags (what marks a rule as "production"), Wazuh managers (connect, test, sync, **auto-sync toggle + interval + last-sync status/error badge**), GitHub sources (same pattern), manual upload, local rule paths.
- **Integrations** — Webhooks (CRUD, test-send button), API keys (create/revoke, one-time key reveal), SSO/OIDC config (issuer/client id/secret, auto-provision role, shows the exact callback URL to register with the IdP).
- **Unmapped files** — files not yet assigned to a product.
- **My profile** — password change, full MFA enrollment (QR, backup codes, enable/disable).
- **Team & access** — tenant member list (role, MFA status, permission-override badge), **direct user creation** (username, display name, optional email, password, role, permission overrides via checkboxes, force-password-reset toggle, require-MFA toggle) *and* email-invite flow side by side, plus (super-admin only) a cross-tenant "all platform users" table.
- **Tenants** (super-admin only) — create/delete tenants, each card showing rule count, member count, created date.
- **Audit log** / **Deletion log** — same component, `deletionsOnly` prop toggles the filter; expandable diff details for sync events; now includes an **IP address** column.
- **Login activity** (super-admin) — filterable, suspicious-activity flagged.
- **System settings** (super-admin) — retention windows, lockout thresholds, password policy, session timeout, MFA backup-code count.

### Auth pages (standalone, outside the tenant shell)
`Login`, `Bootstrap` (first-run admin creation), `AcceptInvite` — all share the real 3-circle brand `Logo` component (previously a generic shield icon). `Login` also offers a "Sign in with SSO" flow (asks for an "Organization ID" / tenant id, redirects to that tenant's SSO login route).

### Sidebar (`Shell.tsx`)
Compact account-menu pattern: avatar + name + role badge as a single clickable trigger, opening a dropdown popover (email, role badges, theme toggle, sign out) — replaced an earlier design that permanently occupied footer space with an always-expanded card plus separate buttons.

---

## 8. Backend Module Reference (`src/internal/`)

| Module | Responsibility |
|---|---|
| `visualizer.py` | The Flask app itself: `create_app()`, all routes, `before_request` auth/tenant resolution, the `Workspace` class (per-tenant graph + derived stats), background thread startup, manager/GitHub sync orchestration (`sync_manager_now`/`sync_github_source_now`, with a `SyncInProgress` guard against overlapping syncs), `_log_audit` (central audit+webhook dispatch point) |
| `db.py` | All identity/authz persistence — users, tenants, roles, invites, api keys, audit log, login activity, IP rate-limit table, platform settings. SQLAlchemy Core, dual SQLite/Postgres schema, portable queries throughout |
| `config.py` | Per-tenant JSON config (`Config` class): products, managers, GitHub sources, webhooks, SSO config, case tags, paths, activity feed. Thread-safe via a lock; atomic writes (write to `.tmp`, `os.replace`) |
| `authz.py` | `Role`/`Permission` enums, role→permission matrix, `require_permission`/`require_super_admin`/`require_login` decorators |
| `crypto.py` | Fernet encrypt/decrypt for secrets-at-rest, keyed from the app's `secret_key` |
| `totp.py` | Hand-rolled RFC 6238 TOTP (generation, verification with ±1 step window, backup codes, provisioning URI) |
| `oidc.py` | OIDC discovery, authorize-URL building, code exchange, ID-token verification (via `python-jose`) |
| `webhooks.py` | Outbound webhook payload building (per format) + HMAC signing + delivery |
| `tenancy.py` | `TenantManager` — lazy, thread-safe per-tenant `Workspace` cache |
| `migrate.py` | One-time migration from the original single-tenant on-disk layout into the `default` tenant |
| `generator.py` | Parses rule XML into the `networkx` graph (handles overwrite tags, forward references, duplicate detection) |
| `analyzer.py` | Graph statistics, heatmap data |
| `health.py` | Rule-health computation: broken deps, duplicate IDs, disabled parents, orphans, dependency-chain depth (BFS/longest-path) |
| `differ.py` | Rule-set / graph diffing (used by both Compare page and sync-event diffing) |
| `exporter.py` | Export format implementations |
| `wazuh_api.py` | Wazuh Manager REST API client (JWT auth, rule-file listing/download) |
| `github_source.py` | GitHub Contents API client (public repos need no token; private repos use a PAT) |

---

## 9. Frontend Structure (`web/src/`)

- **Routing** (`App.tsx`): `/login`, `/bootstrap`, `/accept-invite` standalone; everything else behind `RequireAuth` → `/t/:tenantId` (`TenantLayout`, verifies tenant access) → `Shell` (sidebar/topbar) → page routes.
- **Tenant context pattern**: rather than threading `tenantId` through every component/prop, a module-level singleton (`lib/tenantContext.ts`) holds `currentTenantId`, set by `TenantLayout` on route mount. `lib/api.ts`'s `t(path)` helper auto-prefixes tenant-scoped API calls with it.
- **Auth state**: `lib/auth.tsx`'s `AuthProvider`/`useAuth()` — fetches `/api/auth/me` on mount, listens for a `rulevis:unauthorized` custom event (dispatched by `api.ts` on any 401) to clear state and redirect to `/login`.
- **Permission checks**: `lib/permissions.ts` mirrors the backend role→permission matrix for UI-only gating (hiding buttons a role can't use) — the server is the real enforcement boundary.
- **`lib/api.ts`**: three API surfaces — `api` (tenant-scoped, auto-prefixed), `authApi` (login/logout/me/bootstrap/mfa/invites), `superApi` (platform-admin, cross-tenant).
- **Component organization**: `pages/` (route-level), `components/` (shared: `Shell`, `RuleDetail`, `GraphCanvas`, `Logo`, tenant-switching), `components/settings/` (one file per Settings tab, plus `editors.tsx` for the shared modal editors — Product/Manager/GithubSource/Webhook).

---

## 10. Testing Strategy

`tests/` (pytest, 42 tests as of this writing). Every test is isolated via an **autouse fixture** (`tests/conftest.py`) that redirects `HOME`/`USERPROFILE` to a fresh pytest `tmp_path` per test — so tests never touch a real user's `~/.rulevis`, and each test gets a completely fresh database.

| File | Covers |
|---|---|
| `test_auth_and_permissions.py` | Login by email/username (case-insensitivity), duplicate-username rejection, role→permission matrix, permission overrides |
| `test_lockout_and_rate_limit.py` | Account lockout threshold/reset, per-IP rate limiting (trip, per-IP scoping, sweep) |
| `test_retention.py` | Retention sweep prunes old audit/login records, keeps recent ones |
| `test_tenant_lifecycle.py` | Tenant directory cleanup on delete (config/cache/uploads all removed) |
| `test_app_routes.py` | Full Flask app via `test_client()`: default-tenant delete guard, tenant-dir cleanup at the route level, IP rate limit over real HTTP |
| `test_secrets_encryption.py` | Encrypt/decrypt roundtrip, plaintext-fallback for pre-encryption values, manager/GitHub secrets actually encrypted on disk, blank-password-on-edit doesn't wipe the stored secret |
| `test_webhooks.py` | Payload shaping per format, event-subscription filtering, disabled-webhook no-op, HMAC signing verified against a **real local HTTP test server** |
| `test_api_keys.py` | Key creation/verification/revocation, tenant isolation, super-admin-route blocking, role-based permission enforcement — all over real HTTP |
| `test_sso_oidc.py` | Full OIDC flow against a **real local mock IdP** (real RSA keypair, real RS256-signed JWT, real JWKS) — login redirect, callback completion + user auto-provisioning, CSRF state mismatch rejection, disabled-SSO 404 |

No frontend test suite exists yet — frontend changes were verified manually via the Claude Code browser-preview tooling against a running instance, using throwaway super-admin accounts created directly via `db.create_user()` and deleted immediately after each check (never polluting real user data).

---

## 11. Installation & Deployment

### Prerequisites
- Python 3.9+ (any OS)
- Node.js + npm — **only if you need to rebuild the frontend**; not needed to just run the app, since `src/internal/static/dist/` ships pre-built in the repo.

### Install
```bash
git clone https://github.com/<you>/rulevis.git
cd rulevis
pip install .
```
This installs Flask, networkx, waitress, SQLAlchemy, cryptography, and python-jose automatically (declared in `pyproject.toml`).

### Run
```bash
rulevis                      # uses waitress if installed, else falls back to Flask's dev server
rulevis --path /some/rules   # optionally point at local rule directories (CLI-only, not used per-tenant)
```
Opens `http://localhost:5000/` automatically. First run walks you through creating the initial super-admin account (`/bootstrap`).

### Database
- Default: SQLite at `~/.rulevis/rulevis.db` — zero configuration.
- For multi-process/multi-host deployments: `export RULEVIS_DATABASE_URL=postgresql+psycopg2://user:pass@host/rulevis` (also `pip install psycopg2-binary` or `pip install .[postgres]`).

### Rebuilding the frontend (only if you change `web/src`)
```bash
cd web
npm install
npm run build     # outputs directly to ../src/internal/static/dist/
```

### Data locations (all under `~/.rulevis/`)
- `rulevis.db` — identity/authz (or external DB if `RULEVIS_DATABASE_URL` is set)
- `secret_key` — session signing key, generated once
- `tenants/<id>/config.json` — per-tenant products/managers/GitHub sources/webhooks/SSO config/case tags/paths
- `tenants/<id>/cache/<manager_id>/` — mirrored Wazuh manager rule files
- `tenants/<id>/cache/gh-<source_id>/` — mirrored GitHub-source rule files
- `tenants/<id>/uploads/` — manually uploaded rule XML

---

## 12. Bugs Found and Fixed During Development

| # | Bug | Root cause | Fix |
|---|---|---|---|
| 1 | Decorator attached to the wrong function | Inserting a helper function before a route handler moved the `@app.route(...)` decorator away from the intended function | Moved the decorator to immediately precede the route function |
| 2 | Infinite loop in dependency-depth BFS (`health.py`) | Relax-until-stable BFS spun forever on legitimate Wazuh rule self-loops/cycles | Visit-once BFS (deque, skip visited) for shortest-hop depth; longest-chain calc strips self-loops before `nx.dag_longest_path` |
| 3 | False-positive duplicate-rule detection | Forward-referenced rule IDs (via `if_sid` pointing at a not-yet-parsed rule) get an attribute-less phantom node auto-created by `networkx.add_edge()`, wrongly flagged as a duplicate | Only flag as duplicate if `"conditions" in existing` (real parsed rules always have this key) |
| 4 | XML syntax highlighter corrupting output | Chained `.replace()` calls let the second (attribute-highlighting) pass re-match HTML inserted by the first (tag-highlighting) pass | Single-pass tokenizing regex with alternation |
| 5 | Condition values collapsing to 1 character per line | `.cond .val` lacked `min-width: 0`/proper flex-basis, so flexbox squeezed it near zero under `word-break: break-all` | `flex: 1 1 100%; min-width: 0; overflow-wrap: anywhere;` |
| 6 | Tenant isolation leak | CLI `--path` sample rules leaked into **every** tenant via `TenantManager` (a freshly created tenant already had rules) | `cli_paths = self._cli_paths if tenant_id == "default" else []` |
| 7 | CLI crash after multi-tenancy migration | `rulevis.py`'s sanity check called `Config()` with no arguments, but `Config.__init__` now requires `tenant_id` | Removed the dead check (rule sources are now per-tenant, configured in-app) |
| 8 | TS build errors: implicit-Promise `useEffect`, tab-array type mismatch | `useEffect(reload, [])` where `reload` returned a Promise; an inline tab array wasn't typed as `TabId[]` | Wrapped effect bodies in explicit blocks; explicitly typed the tabs array |
| 9 | Workspace product cards always showed "0 rules" | `WorkspaceTab` read products from `/settings` (raw config, no computed `rule_count`) instead of the enriched `/products` endpoint `Rules.tsx` uses | Fetch from `/products` for the card data, keep `/settings` only for the raw config fields |
| 10 | `init_schema()` crashed on existing databases with `no such column: username` | A `CREATE UNIQUE INDEX ... ON users(username)` statement was embedded directly in the `SCHEMA` DDL string, which runs via `executescript` *before* the incremental `_ensure_column` calls that actually add the `username` column to pre-existing DBs | Removed the index statement from the DDL block; kept it only in the post-`_ensure_column` step |
| 11 | Tenant deletion left orphaned files on disk forever | `db.delete_tenant()` only removed the DB row; `~/.rulevis/tenants/<id>/` (config, cache, uploads) was never cleaned up | Added `config.delete_tenant_dir()`, called right after the DB row is deleted; also added a guard so the `default` tenant can never be deleted |
| 12 | Manager passwords / GitHub tokens stored in plaintext | No encryption existed for these fields in `config.json` | `internal/crypto.py` (Fernet) + encrypt-on-write/decrypt-at-point-of-use, with backward-compatible plaintext fallback |
| 13 | Login rate limiting wouldn't survive horizontal scaling | Original rate limiter was an in-process Python dict — invisible to any other worker process or host | Moved to a `login_ip_failures` DB table, checked/updated via `db.is_ip_rate_limited`/`register_ip_login_failure` |
| 14 | `.gitignore` silently excluded the built frontend from version control | An unanchored `dist/` pattern (meant for Python's `dist/` packaging output) also matched `src/internal/static/dist/`, the built frontend Flask actually serves; `web/node_modules/` had no ignore rule at all | Anchored `/dist/` and `/build/` to the repo root; added `node_modules/` and related Node ignores |

---

## 13. Known Gaps / Deliberately Out of Scope

- **SAML SSO** — only OIDC is implemented; SAML needs its own dedicated effort (XML signing/parsing, metadata exchange, ACS endpoint).
- **Google Workspace domain restriction / `email_verified` check** for OIDC — not yet implemented; anyone completing the IdP flow gets auto-provisioned.
- **MFA-required is a nudge, not a hard gate** — a user with `mfa_required=True` is redirected toward enrollment on login but isn't technically blocked from navigating elsewhere first.
- **No frontend automated test suite** — all UI verification so far has been manual (via browser preview tooling), not automated (e.g. Playwright/Cypress).
- **Live Postgres verification** — the Postgres code path is written to be portable (dialect-aware schema, no SQLite-specific syntax) and unit-tested against SQLite, but has not been run against a live Postgres instance in this environment (Docker wasn't available at the time).
- **No CI pipeline** — tests and frontend build are run manually; not yet wired into GitHub Actions or similar.
- **No rate limiting beyond login** — other endpoints (e.g. export, search) have no throttling.
- **No production process-management guidance** — waitress runs the app, but there's no documented systemd/Windows-service/supervisor setup for auto-restart-on-crash.

---

## 14. Glossary

- **Tenant** — an isolated customer/organization workspace within one RuleVis instance.
- **Workspace** (code) — the in-memory object holding one tenant's loaded graph + derived stats (`visualizer.py`'s `Workspace` class); not to be confused with the Settings → "Workspace" tab (product/manager/GitHub-source management UI).
- **Case-managed rule** — a rule (or one of its ancestors) carrying one of the tenant's configured "case tags," used to compute "Production Rules" counts.
- **Atomic vs. correlation rule** — an atomic rule fires directly off log/decoder fields; a correlation rule fires only when other rules have already matched (built on top of them via `if_matched_sid`/`if_matched_group` etc.).
