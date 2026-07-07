import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import GraphCanvas from '../components/GraphCanvas';
import {
  IconActivity, IconAlertTriangle, IconArrowUpRight, IconBoxes, IconCheckCircle,
  IconCloud, IconCompare, IconContainer, IconDatabase, IconDownload,
  IconFileText, IconGitBranch, IconGitCompare, IconLayers, IconNetwork,
  IconRules, IconSearch, IconServer, IconSettings, IconShield, IconShieldAlert,
  IconUpload, IconXCircle,
} from '../icons';
import { api } from '../lib/api';
import type {
  ActivityEntry, Health, Overview, Product, SearchResult,
} from '../lib/types';

function timeAgo(ts: number): string {
  const diff = Date.now() / 1000 - ts;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const ACTIVITY_ICON: Record<string, JSX.Element> = {
  import: <IconUpload size={14} />,
  fetch: <IconDatabase size={14} />,
  export: <IconDownload size={14} />,
  compare: <IconGitCompare size={14} />,
};
const ACTIVITY_COLOR: Record<string, string> = {
  import: 'var(--green)', fetch: 'var(--blue)', export: 'var(--accent)', compare: 'var(--violet)',
};

function productIcon(name: string) {
  const n = name.toLowerCase();
  if (/(aws|azure|gcp|cloud)/.test(n)) return <IconCloud size={18} />;
  if (/(kubernetes|k8s|docker|container)/.test(n)) return <IconContainer size={18} />;
  if (/(linux|sysmon|windows|endpoint)/.test(n)) return <IconServer size={18} />;
  if (/(network|firewall|fortigate|cisco|palo)/.test(n)) return <IconNetwork size={18} />;
  return <IconShield size={18} />;
}

// ---------------- metric card ----------------
function Metric(props: {
  icon: JSX.Element; label: string; value?: number; color: string; locked?: boolean;
}) {
  return (
    <div className="metric-card" style={{ ['--m-color' as string]: props.color }}>
      {props.locked && <span className="m-badge">soon</span>}
      <div className="m-icon">{props.icon}</div>
      <div className={`m-val ${props.locked ? 'dash' : ''}`}>
        {props.locked ? '—' : (props.value ?? 0).toLocaleString()}
      </div>
      <div className="m-label">{props.label}</div>
    </div>
  );
}

// ---------------- health card ----------------
function HealthCard(props: {
  icon: JSX.Element; label: string; count: number; caption: string; onClick?: () => void;
}) {
  const color = props.count === 0 ? 'var(--green)' : props.count < 5 ? 'var(--amber)' : 'var(--red)';
  return (
    <div className="health-card" style={{ ['--h-color' as string]: color, cursor: props.onClick ? 'pointer' : undefined }}
      onClick={props.onClick}>
      <div className="h-icon">{props.count === 0 ? <IconCheckCircle size={20} /> : props.icon}</div>
      <div>
        <div className="h-val" style={{ color }}>{props.count}</div>
        <div className="h-label">{props.label}</div>
        <div className="h-caption">{props.caption}</div>
      </div>
    </div>
  );
}

// ---------------- mini graph preview ----------------
function MiniGraphPreview() {
  const navigate = useNavigate();
  const { tenantId } = useParams();

  return (
    <div className="mini-graph-card" onClick={() => navigate(`/t/${tenantId}/visualizer`)}>
      <GraphCanvas
        engineRef={e => {
          if (!e) return;
          e.setFocusMode(false);
          api.nodesRoot().then(r => e.setData(r.nodes, r.edges, true)).catch(() => {});
        }}
        onSelect={() => {}}
        onExpand={() => {}}
        onMultiSelectChange={() => {}}
      />
      <div className="mg-overlay">
        <span className="mg-cta"><IconGitBranch size={15} /> Open Rule Visualizer</span>
      </div>
    </div>
  );
}

// ---------------- quick search ----------------
function QuickSearch() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const [results, setResults] = useState<SearchResult[] | null>(null);
  const navigate = useNavigate();
  const { tenantId } = useParams();

  useEffect(() => {
    if (!q.trim()) { setResults(null); return; }
    const t = setTimeout(() => {
      api.search(q.trim(), undefined, 20).then(r => setResults(r.results)).catch(() => setResults([]));
    }, 220);
    return () => clearTimeout(t);
  }, [q]);

  if (!open) {
    return (
      <button className="qa-btn" onClick={() => setOpen(true)}>
        <IconSearch size={14} /> Search rules
      </button>
    );
  }
  return (
    <div className="search-wrap" style={{ minWidth: 280 }}>
      <IconSearch />
      <input autoFocus placeholder="Rule ID or description…" value={q}
        onChange={e => setQ(e.target.value)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={e => { if (e.key === 'Escape') setOpen(false); }} />
      {results !== null && (
        <div className="search-results">
          {results.length === 0 && <div className="sr"><span className="muted">No matches.</span></div>}
          {results.map(r => (
            <div key={r.id} className="sr" onMouseDown={() => navigate(`/t/${tenantId}/visualizer?focus=${r.id}`)}>
              <span className="rid">{r.id}</span>
              <span className="badge">{r.level ?? '?'}</span>
              <span className="rdesc">{r.description || <i>no description</i>}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Home() {
  const [ov, setOv] = useState<Overview | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [products, setProducts] = useState<Product[]>([]);
  const [activity, setActivity] = useState<ActivityEntry[]>([]);
  const [err, setErr] = useState('');
  const navigate = useNavigate();
  const { tenantId } = useParams();
  const base = `/t/${tenantId}`;

  useEffect(() => {
    Promise.all([
      api.overview(), api.health(), api.products(), api.activity(),
    ]).then(([o, h, p, a]) => {
      setOv(o); setHealth(h); setProducts(p.products); setActivity(a.activity);
    }).catch(e => setErr(String(e.message ?? e)));
  }, []);

  const complianceEntries = health ? Object.entries(health.compliance_frameworks) : [];
  const mitrePct = ov && health && ov.total_rules
    ? Math.round((health.mitre_covered_rules / ov.total_rules) * 100) : 0;
  const compliancePct = ov && health && ov.total_rules
    ? Math.round(((ov.total_rules - health.rules_without_compliance.count) / ov.total_rules) * 100) : 0;

  return (
    <div className="page">
      <div className="dash-hero">
        <span className="eyebrow"><IconShield size={12} /> Rule Intelligence Platform</span>
        <h1>Rule Intelligence for Wazuh</h1>
        <div className="tagline">Visualize. Understand. Optimize. Validate.</div>
        <p className="lead">
          Live health and analytics for your entire Wazuh ruleset — dependency integrity, MITRE ATT&amp;CK
          and compliance coverage, and structural risk across every custom and built-in rule.
        </p>
        <div className="qa-row">
          <Link to={`${base}/settings`} className="qa-btn primary"><IconUpload size={14} /> Import ruleset</Link>
          <Link to={`${base}/visualizer`} className="qa-btn"><IconGitBranch size={14} /> Open graph explorer</Link>
          <Link to={`${base}/compare`} className="qa-btn"><IconCompare size={14} /> Compare rulesets</Link>
          <Link to={`${base}/rules`} className="qa-btn"><IconRules size={14} /> Browse products</Link>
          <a className="qa-btn" href={api.exportUrl('json', 'all')}><IconFileText size={14} /> Export documentation</a>
          <QuickSearch />
        </div>
      </div>

      {err && <div className="empty" style={{ marginTop: 20 }}>Backend not reachable: {err}</div>}

      {/* ---- metrics ---- */}
      <div className="section-head"><h2>Platform metrics</h2></div>
      <div className="metric-grid">
        <Metric icon={<IconLayers size={16} />} label="Total rules" value={ov?.total_rules} color="var(--accent)" />
        <Metric icon={<IconRules size={16} />} label="Custom rules" value={ov?.custom_rules} color="var(--green)" />
        <Metric icon={<IconShield size={16} />} label="Built-in rules" value={ov?.builtin_rules} color="var(--blue)" />
        <Metric icon={<IconFileText size={16} />} label="Rule files" value={ov?.total_files} color="var(--text-dim)" />
        <Metric icon={<IconBoxes size={16} />} label="Products" value={ov?.total_products} color="var(--violet)" />
        <Metric icon={<IconDatabase size={16} />} label="Decoders" locked color="var(--text-faint)" />
        <Metric icon={<IconShieldAlert size={16} />} label="MITRE techniques" value={health?.mitre_technique_count} color="var(--violet)" />
        <Metric icon={<IconCheckCircle size={16} />} label="Compliance frameworks" value={complianceEntries.length} color="var(--green)" />
        <Metric icon={<IconGitBranch size={16} />} label="Dependencies" value={ov?.total_edges} color="var(--amber)" />
        <Metric icon={<IconLayers size={16} />} label="Rule groups" value={ov?.total_groups} color="var(--blue)" />
      </div>

      {/* ---- health ---- */}
      <div className="section-head">
        <h2>Rule health</h2>
        <span className="sub">Issues are derived directly from the loaded ruleset, not estimated.</span>
      </div>
      <div className="health-grid">
        <HealthCard icon={<IconXCircle size={18} />} label="Broken dependencies" count={health?.broken_dependencies.count ?? 0}
          caption="if_sid / if_group references to rule IDs that are never defined."
          onClick={() => navigate(`${base}/visualizer`)} />
        <HealthCard icon={<IconAlertTriangle size={18} />} label="Duplicate rule IDs" count={health?.duplicate_rule_ids.count ?? 0}
          caption="Same rule ID defined more than once without an overwrite tag." />
        <HealthCard icon={<IconAlertTriangle size={18} />} label="Disabled parent rules" count={health?.non_alerting_parents.count ?? 0}
          caption="level=0 parent rules — grouping/decoding only, never alert on their own." />
        <HealthCard icon={<IconShieldAlert size={18} />} label="Rules without MITRE mapping" count={health?.rules_without_mitre.count ?? 0}
          caption={`${health?.rules_without_mitre.pct ?? 0}% of rules have no <mitre> tag.`} />
        <HealthCard icon={<IconCheckCircle size={18} />} label="Rules without compliance tags" count={health?.rules_without_compliance.count ?? 0}
          caption={`${health?.rules_without_compliance.pct ?? 0}% of rules have no compliance group.`} />
        <HealthCard icon={<IconLayers size={18} />} label="Orphan rules" count={health?.orphan_rules.count ?? 0}
          caption="No children and no real parent — fully isolated from the rule tree." />
      </div>

      {/* ---- coverage ---- */}
      <div className="section-head"><h2>Detection coverage</h2></div>
      <div className="coverage-grid">
        <div className="coverage-card">
          <div className="coverage-head">
            <h4>MITRE ATT&amp;CK coverage</h4>
            <span className="coverage-pct" style={{ color: 'var(--violet)' }}>{mitrePct}%</span>
          </div>
          <div className="coverage-bar-track">
            <div className="coverage-bar-fill" style={{ width: `${mitrePct}%`, background: 'var(--violet)' }} />
          </div>
          <div className="coverage-legend">
            <span className="badge violet">{health?.mitre_technique_count ?? 0} unique techniques</span>
            <span className="badge">{health?.mitre_covered_rules ?? 0} rules mapped</span>
          </div>
        </div>
        <div className="coverage-card">
          <div className="coverage-head">
            <h4>Compliance coverage</h4>
            <span className="coverage-pct" style={{ color: 'var(--green)' }}>{compliancePct}%</span>
          </div>
          <div className="coverage-bar-track">
            <div className="coverage-bar-fill" style={{ width: `${compliancePct}%`, background: 'var(--green)' }} />
          </div>
          <div className="coverage-legend">
            {complianceEntries.length === 0 && <span className="faint" style={{ fontSize: 12 }}>No compliance-tagged groups found.</span>}
            {complianceEntries.map(([name, count]) => (
              <span key={name} className="badge green">{name} · {count}</span>
            ))}
          </div>
        </div>
      </div>

      {/* ---- dependency intelligence ---- */}
      <div className="section-head"><h2>Dependency intelligence</h2></div>
      <div className="dep-stats-row">
        <div className="dep-mini-stat"><div className="v">{health?.dependency.longest_chain_length ?? 0}</div><div className="l">Longest chain</div></div>
        <div className="dep-mini-stat"><div className="v">{health?.dependency.max_depth ?? 0}</div><div className="l">Max depth</div></div>
        <div className="dep-mini-stat"><div className="v">{health?.dependency.avg_depth ?? 0}</div><div className="l">Avg depth</div></div>
        <div className="dep-mini-stat"><div className="v" style={{ color: (health?.broken_dependencies.count ?? 0) > 0 ? 'var(--red)' : undefined }}>
          {health?.broken_dependencies.count ?? 0}</div><div className="l">Broken references</div></div>
      </div>
      {(health?.dependency.longest_chain.length ?? 0) > 0 && (
        <div className="card">
          <div className="dep-chain">
            {health!.dependency.longest_chain.map((id, i) => (
              <span key={id} style={{ display: 'contents' }}>
                {i > 0 && <span className="arrow">→</span>}
                <span className="link" onClick={() => navigate(`${base}/visualizer?focus=${id}`)}>{id}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ---- products + graph preview ---- */}
      <div className="section-head">
        <h2>Product overview</h2>
        <span className="grow" />
        <Link to={`${base}/rules`} className="muted" style={{ fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
          Browse all <IconArrowUpRight size={12} />
        </Link>
      </div>
      <div className="dash-grid-2">
        <div className="grid cards-4">
          {products.map(p => (
            <div key={p.id} className="prod-overview-card" onClick={() => navigate(`${base}/visualizer/${encodeURIComponent(p.id)}`)}>
              <div className="p-icon">{p.icon || productIcon(p.name)}</div>
              <div>
                <div className="p-name">{p.name}</div>
                <div className="p-count">{p.rule_count ?? 0} rules · {p.files.length} files</div>
              </div>
            </div>
          ))}
          {products.length === 0 && (
            <div className="empty" style={{ gridColumn: '1/-1' }}>
              No products mapped yet. <Link to={`${base}/settings`}>Create one in Settings</Link>.
            </div>
          )}
        </div>
        <MiniGraphPreview />
      </div>

      {/* ---- activity ---- */}
      <div className="section-head"><h2>Recent activity</h2></div>
      <div className="card">
        {activity.length === 0 && (
          <p className="faint" style={{ margin: '4px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
            <IconActivity size={13} />
            No activity yet — imports, comparisons and exports will show up here.
          </p>
        )}
        <div className="activity-list">
          {activity.map((a, i) => (
            <div key={i} className="activity-item">
              <div className="a-icon" style={{ color: ACTIVITY_COLOR[a.kind] ?? 'var(--text-dim)' }}>
                {ACTIVITY_ICON[a.kind] ?? <IconActivity size={14} />}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="a-detail">{a.detail}</div>
                <div className="a-time" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {timeAgo(a.ts)}
                  {(a.kind === 'fetch' || a.kind === 'import') && (
                    <Link to={`${base}/settings?tab=audit`} className="muted" style={{ fontSize: 11 }}>
                      What changed? <IconArrowUpRight size={10} />
                    </Link>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {ov && ov.unmapped_files > 0 && (
        <p className="muted" style={{ marginTop: 22, fontSize: 13, display: 'flex', alignItems: 'center', gap: 5 }}>
          <IconSettings size={13} />
          {ov.unmapped_files} rule file{ov.unmapped_files > 1 ? 's are' : ' is'} not mapped to a
          product yet — organize them in <Link to={`${base}/settings`}>Settings</Link>.
        </p>
      )}
    </div>
  );
}
