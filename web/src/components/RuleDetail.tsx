import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import type { Condition, RelatedRule, RuleDetail as RuleDetailT } from '../lib/types';
import { IconX } from '../icons';

const DEP_TAGS = new Set([
  'if_sid', 'if_group', 'if_matched_sid', 'if_matched_group', 'if_level', 'if_fts',
]);

function severityLabel(n: number): string {
  if (n <= 0) return 'Informational';
  if (n <= 3) return 'Low';
  if (n <= 6) return 'Medium';
  if (n <= 11) return 'High';
  return 'Critical';
}

function levelBadge(level?: string | null, withLabel = false) {
  const n = parseInt(level ?? '', 10);
  if (Number.isNaN(n)) return <span className="badge">level ?</span>;
  const cls = n >= 12 ? 'red' : n >= 7 ? 'amber' : n >= 4 ? '' : 'green';
  return <span className={`badge ${cls}`}>level {n}{withLabel ? ` · ${severityLabel(n)}` : ''}</span>;
}

function ConditionRow({ c, i }: { c: Condition; i: number }) {
  const isDep = DEP_TAGS.has(c.tag);
  const attrs = Object.entries(c.attributes)
    .map(([k, v]) => `${k}="${v}"`).join(' ');
  return (
    <div className={`cond ${isDep ? 'dep' : ''}`}>
      <span className="no">{i + 1}</span>
      <span className="tag">{c.tag}</span>
      {attrs && <span className="attrs">{attrs}</span>}
      <span className="val">{c.text || <i className="faint">(presence check)</i>}</span>
    </div>
  );
}

/**
 * Tiny XML syntax highlighter. Tag names and attributes are matched in a
 * single regex pass (alternation) so the replacer only ever sees the
 * original escaped text — a second chained .replace() would re-match its
 * own previously-inserted style="..." attributes and corrupt the markup.
 */
const XML_TOKEN = /(&lt;\/?)([\w:-]+)|([\w:-]+)=(&quot;|")([^"&]*?)(&quot;|")/g;

function XmlView({ xml }: { xml: string }) {
  const esc = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const html = esc(xml).replace(XML_TOKEN, (_m, ltSlash, tagName, attrName, _q1, attrVal) => {
    if (tagName !== undefined) {
      return `${ltSlash}<span style="color:var(--accent)">${tagName}</span>`;
    }
    return `<span style="color:var(--amber)">${attrName}</span>=<span style="color:var(--green)">"${attrVal}"</span>`;
  });
  return <pre className="xml" dangerouslySetInnerHTML={{ __html: html }} />;
}

function YesNo({ value, yesLabel = 'Yes', noLabel = 'No' }: { value: boolean; yesLabel?: string; noLabel?: string }) {
  return <span className={`badge ${value ? 'green' : ''}`}>{value ? yesLabel : noLabel}</span>;
}

function HierBox(props: {
  rule: RelatedRule; onJump: () => void;
  expanded: boolean; onToggle: () => void;
}) {
  const { rule, expanded } = props;
  return (
    <div className="hier-box">
      <div className="hb-head">
        <div onClick={props.onJump} style={{ cursor: 'pointer', flex: 1, minWidth: 0 }}>
          <div className="hb-id">{rule.id}{rule.level != null && <span className="faint"> · L{rule.level}</span>}</div>
          <div className="hb-desc">{rule.description || 'no description'}</div>
        </div>
        <button className="hb-expand" onClick={props.onToggle} title="View conditions & parameters">
          {expanded ? '▾' : '▸'}
        </button>
      </div>
      <div className="hb-tags">
        {rule.relation_type && <span className="badge violet" style={{ fontSize: 9.5 }}>{rule.relation_type}</span>}
        {rule.frequency && (
          <span className="badge amber" style={{ fontSize: 9.5 }}>freq {rule.frequency}×/{rule.timeframe}s</span>
        )}
      </div>
      {expanded && (
        <div className="hb-expanded">
          {(rule.conditions ?? []).length === 0
            ? <p className="faint" style={{ margin: '4px 0', fontSize: 11 }}>No matching conditions.</p>
            : (rule.conditions ?? []).map((c, i) => <ConditionRow key={i} c={c} i={i} />)}
        </div>
      )}
    </div>
  );
}

function MetaRow(props: { label: string; children: React.ReactNode }) {
  return (
    <div className="meta-row">
      <span className="meta-label">{props.label}</span>
      <span className="meta-value">{props.children}</span>
    </div>
  );
}

export default function RuleDetail(props: {
  ruleId: string;
  displayed?: Set<string>;
  onClose: () => void;
  onJump: (id: string) => void;
  onExpandChildren?: (id: string) => void;
  onExpandParents?: (id: string, parentIds: string[]) => void;
}) {
  const { ruleId, displayed, onClose, onJump } = props;
  const [detail, setDetail] = useState<RuleDetailT | null>(null);
  const [err, setErr] = useState('');
  const [showXml, setShowXml] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    setDetail(null); setErr(''); setShowXml(false); setExpanded(new Set());
    api.rule(ruleId).then(setDetail).catch(e => setErr(String(e.message ?? e)));
  }, [ruleId]);

  const toggleExpand = (id: string) => setExpanded(s => {
    const next = new Set(s);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  if (err) {
    return (
      <div className="panel-inner">
        <div className="close-row"><h3>Rule {ruleId}</h3><button className="icon-btn" onClick={onClose}><IconX /></button></div>
        <p style={{ color: 'var(--red)' }}>{err}</p>
      </div>
    );
  }
  if (!detail) {
    return (
      <div className="panel-inner">
        <div className="close-row"><h3>Rule {ruleId}</h3><button className="icon-btn" onClick={onClose}><IconX /></button></div>
        <p className="muted">Loading…</p>
      </div>
    );
  }

  const hiddenParents = detail.parents.filter(p => displayed && !displayed.has(p.id));
  const hiddenChildren = detail.children.filter(c => displayed && !displayed.has(c.id));
  const VISIBLE = 4;
  const visibleParents = detail.parents.slice(0, VISIBLE);
  const visibleChildren = detail.children.slice(0, VISIBLE);

  return (
    <div className="rule-detail-grid">
      {/* ---- column 1: what is this rule ---- */}
      <div className="rd-col rd-meta">
        <div className="close-row" style={{ marginBottom: 2 }}>
          <h3 style={{ minWidth: 0 }}>Rule <span className="mono" style={{ color: 'var(--accent)' }}>{ruleId}</span></h3>
          <button className="icon-btn" onClick={onClose}><IconX /></button>
        </div>

        <div className="rd-summary">
          <div className="rd-summary-title">{detail.description || <i className="faint">untitled rule</i>}</div>
          <div className="rd-summary-badges">
            {levelBadge(detail.level, true)}
            <span className={`badge ${detail.rule_type === 'correlation' ? 'violet' : ''}`}>
              {detail.rule_type === 'correlation' ? 'Correlation rule' : 'Atomic rule'}
            </span>
            {detail.product && <span className="badge accent">{detail.product}</span>}
          </div>
          <p className="rd-summary-hint">
            {detail.rule_type === 'correlation'
              ? 'Fires only when other rules match first (a "meta" rule built on top of them).'
              : 'Fires directly off log/decoder fields — no other rule needs to match first.'}
          </p>
        </div>

        <div className="meta-list">
          <MetaRow label="Alerts">
            <YesNo value={detail.alerts} />
            <span className="faint" style={{ marginLeft: 6, fontSize: 10.5 }}>level ≥ 3</span>
          </MetaRow>
          <MetaRow label="Production / case">
            <YesNo value={detail.case} />
            <span className="faint" style={{ marginLeft: 6, fontSize: 10.5 }}>tagged case-managed</span>
          </MetaRow>
          <MetaRow label="File">
            <span className="badge mono">{detail.file}</span>
          </MetaRow>
          <MetaRow label="Groups">
            {detail.groups.length
              ? detail.groups.map(g => <span key={g} className="chip">{g}</span>)
              : <span className="faint">none</span>}
          </MetaRow>
          {detail.overwritten && <MetaRow label="Overwritten"><span className="badge amber">yes — see XML below</span></MetaRow>}
        </div>
      </div>

      {/* ---- column 2: parent rules -> this rule -> sub-rules ---- */}
      <div className="rd-col rd-hierarchy">
        <h4 className="rd-section-head">Parent rules <span className="faint">(must match first, if any)</span></h4>
        <div className="hier-stack">
          {visibleParents.length === 0 && (
            <div className="hier-more">none — this is a top-level rule</div>
          )}
          {visibleParents.map(p => (
            <HierBox key={p.id} rule={p} onJump={() => onJump(p.id)}
              expanded={expanded.has(p.id)} onToggle={() => toggleExpand(p.id)} />
          ))}
          {detail.parents.length > VISIBLE && (
            <div className="hier-more">+{detail.parents.length - VISIBLE} more parent(s)</div>
          )}
          {hiddenParents.length > 0 && props.onExpandParents && (
            <button style={{ fontSize: 10.5, padding: '3px 8px', alignSelf: 'center' }}
              onClick={() => props.onExpandParents!(ruleId, hiddenParents.map(p => p.id))}>
              show on graph
            </button>
          )}
        </div>

        <div className="hier-arrow-v">↓</div>
        <div className="hier-box current">
          <div className="hb-id">{ruleId}</div>
          <div className="hb-desc">this rule</div>
        </div>
        <div className="hier-arrow-v">↓</div>

        <h4 className="rd-section-head">Sub-rules <span className="faint">(build on top of this one)</span></h4>
        <div className="hier-stack">
          {visibleChildren.length === 0 && (
            <div className="hier-more">none — nothing depends on this rule</div>
          )}
          {visibleChildren.map(c => (
            <HierBox key={c.id} rule={c} onJump={() => onJump(c.id)}
              expanded={expanded.has(c.id)} onToggle={() => toggleExpand(c.id)} />
          ))}
          {detail.children.length > VISIBLE && (
            <div className="hier-more">+{detail.children.length - VISIBLE} more child(ren)</div>
          )}
          {hiddenChildren.length > 0 && props.onExpandChildren && (
            <button style={{ fontSize: 10.5, padding: '3px 8px', alignSelf: 'center' }}
              onClick={() => props.onExpandChildren!(ruleId)}>
              expand on graph
            </button>
          )}
        </div>
      </div>

      {/* ---- column 3: mitre/tags, then the plain-english trigger checklist ---- */}
      <div className="rd-col rd-conditions">
        <h4 className="rd-section-head" style={{ marginTop: 0 }}>What this rule means</h4>
        <MetaRow label="MITRE ATT&CK">
          {detail.mitre.length > 0
            ? detail.mitre.map(t => (
              <a key={t} className="chip" style={{ background: 'var(--red-soft)', color: 'var(--red)' }}
                href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                target="_blank" rel="noreferrer">
                {t}
              </a>
            ))
            : <span className="faint">none</span>}
        </MetaRow>
        <MetaRow label="Compliance / tags">
          {detail.groups.length
            ? detail.groups.map(g => <span key={g} className="chip">{g}</span>)
            : <span className="faint">none</span>}
        </MetaRow>

        <h4 className="rd-section-head">
          Everything that must be true to fire this alert
        </h4>
        <p className="faint" style={{ margin: '0 0 8px', fontSize: 11.5 }}>
          Read top to bottom — every step below has to match, starting from the
          top-most parent down to this rule itself.
        </p>
        <div className="chain-list">
          {(() => {
            let counter = 0;
            return detail.condition_chain.map(step => (
              <div key={step.id} className={`chain-step ${step.id === ruleId ? 'current' : ''}`}>
                <div className="chain-step-head">
                  <span className="mono" style={{ fontWeight: 700, color: step.id === ruleId ? 'var(--accent)' : 'var(--text-dim)' }}>
                    {step.id}
                  </span>
                  <span className="faint" style={{ fontSize: 11 }}>{step.description}</span>
                  {step.id === ruleId && <span className="badge accent" style={{ fontSize: 9.5 }}>this rule</span>}
                </div>
                {step.conditions.length === 0
                  ? <p className="faint" style={{ margin: '4px 0 0', fontSize: 11 }}>No matching conditions (grouping rule).</p>
                  : (
                    <div className="cond-list">
                      {step.conditions.map(c => <ConditionRow key={counter} c={c} i={counter++} />)}
                    </div>
                  )}
              </div>
            ));
          })()}
        </div>

        <h4 style={{ margin: '14px 0 2px', cursor: 'pointer', fontSize: 12 }} onClick={() => setShowXml(s => !s)}>
          {showXml ? '▾' : '▸'} Rule XML
        </h4>
        {showXml && detail.raw && <XmlView xml={detail.raw} />}
        {showXml && detail.raw_overwrite && (
          <>
            <p className="muted" style={{ fontSize: 11 }}>Overwrite applied from another file:</p>
            <XmlView xml={detail.raw_overwrite} />
          </>
        )}
      </div>
    </div>
  );
}
