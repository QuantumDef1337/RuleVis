export type TenantRole = 'super_admin' | 'tenant_admin' | 'analyst' | 'viewer';

export interface User {
  id: string;
  email: string;
  username?: string | null;
  display_name?: string | null;
  is_super_admin: boolean;
  is_active: boolean;
  mfa_enabled: boolean;
  mfa_required?: boolean;
  force_password_reset: boolean;
  locked_until?: string | null;
  created_at: string;
}

export interface AccessibleTenant {
  id: string;
  name: string;
  slug: string;
  is_active: boolean;
  created_at: string;
  role: TenantRole;
  member_count?: number;
  rule_count?: number | null;
}

export interface TenantUser extends User {
  role: TenantRole;
  permission_overrides?: string[];
}

export interface AuditLogEntry {
  id: number;
  actor_user_id?: string | null;
  actor_email?: string | null;
  action: string;
  target_type?: string | null;
  target_id?: string | null;
  details?: string | null;
  tenant_id?: string | null;
  ip_address?: string | null;
  created_at: string;
}

export interface LoginActivityEntry {
  id: number;
  user_id?: string | null;
  email_attempted: string;
  success: boolean | number;
  reason?: string | null;
  ip_address?: string | null;
  user_agent?: string | null;
  created_at: string;
}

export interface PlatformSettings {
  audit_log_retention_days: number;
  deletion_log_retention_days: number;
  login_history_retention_days: number;
  lockout_threshold: number;
  lockout_duration_minutes: number;
  password_min_length: number;
  password_history_depth: number;
  session_idle_timeout_minutes: number;
  mfa_backup_codes_count: number;
}

export interface Overview {
  total_rules: number;
  builtin_rules: number;
  custom_rules: number;
  total_edges: number;
  total_files: number;
  total_groups: number;
  total_products: number;
  unmapped_files: number;
  levels: Record<string, number>;
  paths: string[];
}

export interface BrokenDependency { id: string; referenced_by: string[] }
export interface DuplicateRuleId { id: string; file: string; existing_file: string }

export interface Health {
  broken_dependencies: { count: number; items: BrokenDependency[] };
  duplicate_rule_ids: { count: number; items: DuplicateRuleId[] };
  non_alerting_parents: { count: number; items: string[] };
  rules_without_mitre: { count: number; pct: number };
  rules_without_compliance: { count: number; pct: number };
  orphan_rules: { count: number; items: string[] };
  mitre_technique_count: number;
  mitre_covered_rules: number;
  compliance_frameworks: Record<string, number>;
  dependency: {
    max_depth: number;
    avg_depth: number;
    longest_chain: string[];
    longest_chain_length: number;
  };
}

export interface ActivityEntry {
  ts: number;
  kind: 'import' | 'compare' | 'export' | 'fetch' | string;
  detail: string;
}

export interface FileInfo {
  file: string;
  path?: string;
  rule_count: number;
  product?: string | null;
  builtin?: boolean;
}

export interface Product {
  id: string;
  name: string;
  icon?: string;
  description?: string;
  files: string[];
  rule_count?: number;
  production_rules?: number;
  file_details?: FileInfo[];
  levels?: Record<string, number>;
}

export interface Condition {
  tag: string;
  text: string;
  attributes: Record<string, string>;
}

export interface RelatedRule {
  id: string;
  relation_type: string;
  description?: string | null;
  level?: string | null;
  frequency?: string | null;
  timeframe?: string | null;
  groups?: string[];
  conditions?: Condition[];
}

export interface ConditionChainStep {
  id: string;
  description?: string | null;
  level?: string | null;
  conditions: Condition[];
}

export type RuleType = 'atomic' | 'correlation';

export interface RuleDetail {
  id: string;
  description?: string | null;
  groups: string[];
  level?: string | null;
  file?: string;
  path?: string;
  product?: string | null;
  source?: string | null;
  mitre: string[];
  conditions: Condition[];
  raw?: string;
  overwritten?: boolean;
  raw_overwrite?: string | null;
  frequency?: string | null;
  timeframe?: string | null;
  ignore?: string | null;
  noalert?: string | null;
  rule_type: RuleType;
  alerts: boolean;
  case: boolean;
  parents: RelatedRule[];
  children: RelatedRule[];
  condition_chain: ConditionChainStep[];
}

export interface SearchResult {
  id: string;
  description?: string;
  level?: string | null;
  groups: string[];
  file?: string;
  product?: string | null;
}

export interface GraphNode {
  id: string;
  description?: string | null;
  groups?: string[];
  level?: string | null;
  file?: string;
  product?: string | null;
  children_ids?: string[];
  expandable?: boolean;
  external?: boolean;
  mitre?: string[];
}

export interface GraphEdge {
  source: string;
  target: string;
  relation_type: string;
}

export interface StatsItem {
  id: string;
  count?: number;
}

export interface Stats {
  top_direct_descendants: StatsItem[];
  top_indirect_descendants: StatsItem[];
  top_direct_ancestors: StatsItem[];
  top_indirect_ancestors: StatsItem[];
  isolated_rules: StatsItem[];
  self_loops: StatsItem[];
  cycles: string[][];
}

export interface Manager {
  id: string;
  name?: string;
  url: string;
  username?: string;
  password?: string;
  has_password?: boolean;
  verify_tls?: boolean;
  include?: boolean;
  auto_sync?: boolean;
  sync_interval_minutes?: number;
  last_synced_at?: string | null;
  last_sync_status?: 'success' | 'failed' | null;
  last_sync_error?: string | null;
}

export interface GithubSource {
  id: string;
  name?: string;
  repo: string;
  branch?: string;
  path?: string;
  token?: string;
  has_token?: boolean;
  include?: boolean;
  auto_sync?: boolean;
  sync_interval_minutes?: number;
  last_synced_at?: string | null;
  last_sync_status?: 'success' | 'failed' | null;
  last_sync_error?: string | null;
}

export type WebhookFormat = 'generic' | 'slack' | 'teams';

export interface Webhook {
  id: string;
  name?: string;
  url: string;
  format: WebhookFormat;
  events: string[];
  enabled: boolean;
  secret?: string;
  has_secret?: boolean;
}

export interface ApiKey {
  id: string;
  tenant_id: string;
  name: string;
  role: TenantRole;
  created_at: string;
  last_used_at?: string | null;
  revoked: boolean;
  raw_key?: string;
}

export interface SsoConfig {
  enabled: boolean;
  issuer: string;
  client_id: string;
  client_secret?: string;
  has_client_secret?: boolean;
  auto_provision_role: string;
}

export interface Settings {
  version: number;
  paths: string[];
  products: Product[];
  managers: Manager[];
  github_sources: GithubSource[];
  ui: { theme?: string };
  case_tags: string[];
}

export interface DiffChange {
  field: string;
  left: unknown;
  right: unknown;
}

export interface DiffRule {
  id: string;
  level?: string | null;
  description?: string | null;
  file?: string;
  product?: string | null;
  groups?: string[];
}

export interface DiffResult {
  left: string;
  right: string;
  added: DiffRule[];
  removed: DiffRule[];
  changed: {
    id: string;
    description?: string | null;
    file_left?: string;
    file_right?: string;
    changes: DiffChange[];
  }[];
  unchanged_count: number;
  summary?: {
    left_total: number;
    right_total: number;
    added: number;
    removed: number;
    changed: number;
  };
}

export interface HeatmapBlock {
  id: string;
  count: number;
}

export interface Heatmap {
  metadata?: { block_size: number; max_id: number; total_blocks: number };
  blocks?: HeatmapBlock[];
  ids?: string[];
  block_size?: number;
}
