import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import GraphCanvas, { GraphEngine, GraphFilter, LayoutMode } from '../components/GraphCanvas';
import HeatmapModal from '../components/HeatmapModal';
import RuleDetail from '../components/RuleDetail';
import StatsPanel from '../components/StatsPanel';
import { IconDownload, IconSearch, IconX } from '../icons';
import { api } from '../lib/api';
import type { SearchResult } from '../lib/types';

const EDGE_LEGEND = [
  ['if_sid', 'var(--g-edge-if_sid)'],
  ['if_matched_sid', 'var(--g-edge-if_matched_sid)'],
  ['if_group', 'var(--g-edge-if_group)'],
  ['if_matched_group', 'var(--g-edge-if_matched_group)'],
] as const;

export default function Visualizer() {
  const { productId, tenantId } = useParams();
  const [params, setParams] = useSearchParams();
  const fileScope = params.get('file') ?? undefined;
  const navigate = useNavigate();

  const engineRef = useRef<GraphEngine | null>(null);
  const [ready, setReady] = useState(0);
  const [scopeLabel, setScopeLabel] = useState('All rules');
  const [productName, setProductName] = useState<string | undefined>(undefined);
  const [counts, setCounts] = useState({ nodes: 0, edges: 0 });
  const [selected, setSelected] = useState<string | null>(null);
  const [multi, setMulti] = useState<Set<string>>(new Set());
  const [panel, setPanel] = useState<'detail' | 'stats' | null>(null);
  const [sheetHeight, setSheetHeight] = useState(() => Math.round(window.innerHeight * 0.58));
  const dragRef = useRef<{ startY: number; startHeight: number } | null>(null);
  const [showHeatmap, setShowHeatmap] = useState(false);
  const [focusOn, setFocusOn] = useState(true);
  const [paused, setPaused] = useState(false);
  const [layout, setLayout] = useState<LayoutMode>('force');
  const [filter, setFilter] = useState<GraphFilter>({});
  const [showFilters, setShowFilters] = useState(false);
  const [groups, setGroups] = useState<string[]>([]);
  const [exportOpen, setExportOpen] = useState(false);
  const [q, setQ] = useState('');
  const [results, setResults] = useState<SearchResult[] | null>(null);
  const [toast, setToast] = useState('');
  const [err, setErr] = useState('');

  const isScoped = !!productId || !!fileScope;
  const notify = (m: string) => { setToast(m); setTimeout(() => setToast(''), 3000); };

  const refreshCounts = useCallback(() => {
    const e = engineRef.current;
    if (e) {
      setCounts({ nodes: e.nodeCount, edges: e.edgeCount });
      setGroups(e.allGroups());
    }
  }, []);

  // ---------- load data ----------
  useEffect(() => {
    const e = engineRef.current;
    if (!e) return;
    setErr('');
    setSelected(null); setPanel(null); setMulti(new Set());

    const focus = params.get('focus');
    const afterLoad = () => {
      refreshCounts();
      if (focus) {
        setTimeout(() => {
          e.select(focus, true);
          setSelected(focus);
          setPanel('detail');
        }, 600);
      }
    };

    if (productId) {
      api.productGraph(productId)
        .then(r => {
          setProductName(r.product.name);
          setScopeLabel(r.product.name);
          e.setData(r.nodes, r.edges, true);
          afterLoad();
        })
        .catch(ex => setErr(String(ex.message ?? ex)));
    } else if (fileScope) {
      api.graphByScope(`file:${fileScope}`)
        .then(r => {
          setProductName(undefined);
          setScopeLabel(r.label);
          e.setData(r.nodes, r.edges, true);
          afterLoad();
        })
        .catch(ex => setErr(String(ex.message ?? ex)));
    } else {
      setProductName(undefined);
      setScopeLabel('All rules');
      api.nodesRoot()
        .then(r => {
          e.setData(r.nodes, r.edges, true);
          if (focus) {
            return api.nodeSearch(focus, Array.from(e.displayed)).then(sr => {
              e.merge(sr.nodes, sr.edges);
              afterLoad();
            });
          }
          afterLoad();
          return undefined;
        })
        .catch(ex => setErr(String(ex.message ?? ex)));
    }
  }, [productId, fileScope, ready]);

  // ---------- engine callbacks ----------
  const handleSelect = useCallback((id: string | null) => {
    setSelected(id);
    setPanel(id ? 'detail' : null);
  }, []);

  const expandChildren = useCallback((id: string) => {
    const e = engineRef.current;
    if (!e) return;
    api.nodeChildren(id, Array.from(e.displayed)).then(r => {
      e.merge(r.nodes, r.edges);
      api.edgesAmong(Array.from(e.displayed)).then(er => e.merge([], er.edges));
      refreshCounts();
    });
  }, [refreshCounts]);

  const expandParents = useCallback((id: string, parentIds: string[]) => {
    const e = engineRef.current;
    if (!e) return;
    const missing = parentIds.filter(p => !e.displayed.has(p));
    if (!missing.length) return;
    api.nodesBatch(missing, Array.from(e.displayed)).then(r => {
      e.merge(r.nodes, r.edges);
      api.edgesAmong(Array.from(e.displayed)).then(er => e.merge([], er.edges));
      refreshCounts();
    });
  }, [refreshCounts]);

  const jumpTo = useCallback((id: string) => {
    const e = engineRef.current;
    if (!e) return;
    if (e.getNode(id)) {
      e.select(id, true);
      setSelected(id); setPanel('detail');
    } else if (!isScoped) {
      api.nodeSearch(id, Array.from(e.displayed)).then(r => {
        e.merge(r.nodes, r.edges);
        setTimeout(() => { e.select(id, true); }, 500);
        setSelected(id); setPanel('detail');
        refreshCounts();
      }).catch(() => notify(`Rule ${id} not found.`));
    } else {
      // outside current scope → open in all-rules view
      navigate(`/t/${tenantId}/visualizer?focus=${id}`);
    }
  }, [isScoped, navigate, refreshCounts]);

  // ---------- search ----------
  useEffect(() => {
    if (!q.trim()) { setResults(null); return; }
    const t = setTimeout(() => {
      api.search(q.trim(), productName, 30)
        .then(r => setResults(r.results))
        .catch(() => setResults([]));
    }, 220);
    return () => clearTimeout(t);
  }, [q, productName]);

  // ---------- keyboard ----------
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).tagName === 'INPUT') return;
      if (e.code === 'Space') {
        e.preventDefault();
        setPaused(engineRef.current?.pauseToggle() ?? false);
      } else if (e.key === 'Escape') {
        setPanel(null); setShowHeatmap(false); setShowFilters(false); setExportOpen(false);
        engineRef.current?.select(null);
        setSelected(null);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const handleSheetDragStart = (e: React.PointerEvent) => {
    dragRef.current = { startY: e.clientY, startHeight: sheetHeight };
    const onMove = (ev: PointerEvent) => {
      if (!dragRef.current) return;
      const delta = dragRef.current.startY - ev.clientY;
      const min = 200;
      const max = window.innerHeight * 0.9;
      setSheetHeight(Math.min(max, Math.max(min, dragRef.current.startHeight + delta)));
    };
    const onUp = () => {
      dragRef.current = null;
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
  };

  const applyFilter = (f: GraphFilter) => {
    setFilter(f);
    engineRef.current?.setFilter(f);
  };

  const exportScope = productName
    ? `product:${productName}`
    : fileScope ? `file:${fileScope}` : 'all';

  const filterCount = (filter.group ? 1 : 0) + (filter.pattern ? 1 : 0)
    + (filter.minLevel !== undefined || filter.maxLevel !== undefined ? 1 : 0);

  return (
    <div className="page wide">
      {/* ---------------- toolbar ---------------- */}
      <div className="viz-toolbar">
        <strong style={{ fontSize: 13.5 }}>{scopeLabel}</strong>
        {isScoped && (
          <button style={{ fontSize: 11.5, padding: '3px 9px' }}
            onClick={() => navigate(`/t/${tenantId}/visualizer`)}>view all rules</button>
        )}
        <div className="sep" />

        <div className="search-wrap">
          <IconSearch />
          <input
            placeholder={`Search ${scopeLabel.toLowerCase()} — ID or description…`}
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && results?.length) {
                jumpTo(results[0].id); setQ(''); setResults(null);
              }
            }}
          />
          {results !== null && (
            <div className="search-results">
              {results.length === 0 && <div className="sr"><span className="muted">No matches.</span></div>}
              {results.map(r => (
                <div key={r.id} className="sr"
                  onClick={() => { jumpTo(r.id); setQ(''); setResults(null); }}>
                  <span className="rid">{r.id}</span>
                  <span className="badge">{r.level ?? '?'}</span>
                  <span className="rdesc">{r.description || <i>no description</i>}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="sep" />
        <select value={layout} title="Layout"
          onChange={e => {
            const m = e.target.value as LayoutMode;
            setLayout(m);
            engineRef.current?.setLayout(m);
          }}>
          <option value="force">Force layout</option>
          <option value="hierarchical">Hierarchical</option>
          <option value="radial">Radial</option>
        </select>

        <div style={{ position: 'relative' }}>
          <button className={filterCount ? 'on' : ''} onClick={() => setShowFilters(s => !s)}>
            Filters{filterCount ? ` (${filterCount})` : ''}
          </button>
          {showFilters && (
            <div className="filters-pop">
              <label>Group</label>
              <select value={filter.group ?? ''}
                onChange={e => applyFilter({ ...filter, group: e.target.value || undefined })}>
                <option value="">any group</option>
                {groups.map(g => <option key={g} value={g}>{g}</option>)}
              </select>
              <label>Level range</label>
              <div style={{ display: 'flex', gap: 8 }}>
                <input type="number" min={0} max={16} placeholder="min" style={{ width: 80 }}
                  value={filter.minLevel ?? ''}
                  onChange={e => applyFilter({
                    ...filter,
                    minLevel: e.target.value === '' ? undefined : +e.target.value,
                  })} />
                <input type="number" min={0} max={16} placeholder="max" style={{ width: 80 }}
                  value={filter.maxLevel ?? ''}
                  onChange={e => applyFilter({
                    ...filter,
                    maxLevel: e.target.value === '' ? undefined : +e.target.value,
                  })} />
              </div>
              <label>Pattern (id / description / file)</label>
              <input type="text" placeholder="e.g. ssh, 5710, auth…"
                value={filter.pattern ?? ''}
                onChange={e => applyFilter({ ...filter, pattern: e.target.value || undefined })} />
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <button onClick={() => { applyFilter({}); }}>Clear</button>
                <button className="primary" onClick={() => setShowFilters(false)}>Done</button>
              </div>
            </div>
          )}
        </div>

        <button className={focusOn ? 'on' : ''} title="Dim everything except the selected rule and its neighbors"
          onClick={() => {
            const next = !focusOn;
            setFocusOn(next);
            engineRef.current?.setFocusMode(next);
          }}>Focus</button>

        <div className="sep" />
        <button onClick={() => setPanel(p => (p === 'stats' ? null : 'stats'))}
          className={panel === 'stats' ? 'on' : ''}>Stats</button>
        <button onClick={() => setShowHeatmap(true)}>Heatmap</button>

        <div style={{ position: 'relative' }}>
          <button onClick={() => setExportOpen(o => !o)}><IconDownload size={13} /> Export</button>
          {exportOpen && (
            <div className="filters-pop" style={{ width: 180 }}>
              {(['json', 'csv', 'graphml'] as const).map(fmt => (
                <a key={fmt} href={api.exportUrl(fmt, exportScope)}
                  onClick={() => setExportOpen(false)}
                  style={{ padding: '6px 8px', borderRadius: 6 }}>
                  {fmt.toUpperCase()} — {scopeLabel}
                </a>
              ))}
            </div>
          )}
        </div>

        <div className="sep" />
        <button onClick={() => engineRef.current?.resetZoom()}>Reset zoom</button>
        <button onClick={() => setReady(r => r + 1)}>Reload</button>
        <button onClick={() => setPaused(engineRef.current?.pauseToggle() ?? false)}>
          {paused ? 'Resume' : 'Pause'}
        </button>

        {multi.size > 0 && (
          <>
            <div className="sep" />
            <span className="badge violet">{multi.size} selected</span>
            <button onClick={() => { engineRef.current?.selectFamily(); }}>
              Highlight family
            </button>
            <button onClick={() => { engineRef.current?.clearMultiSelect(); }}>
              <IconX size={12} /> Clear
            </button>
          </>
        )}
      </div>

      {/* ---------------- canvas + panels ---------------- */}
      <div className="viz-layout">
        <div style={{ flex: 1, position: 'relative', minWidth: 0, display: 'flex' }}>
          <GraphCanvas
            engineRef={e => { engineRef.current = e; if (e) setReady(r => r + 1); }}
            onSelect={handleSelect}
            onExpand={expandChildren}
            onMultiSelectChange={setMulti}
          />
          <div className="graph-legend">
            <div className="li"><span className="dot" style={{ background: 'var(--g-node-expandable)' }} /> expandable (dbl-click)</div>
            <div className="li"><span className="dot" style={{ background: 'var(--g-node)' }} /> rule</div>
            {isScoped && <div className="li"><span className="dot" style={{ background: 'var(--g-node-external)' }} /> external dependency</div>}
            {EDGE_LEGEND.map(([label, color]) => (
              <div className="li" key={label}><span className="line" style={{ background: color }} /> {label}</div>
            ))}
            <div className="li faint" style={{ marginTop: 4 }}>shift+click / shift+drag: multi-select</div>
          </div>
          <div className="graph-counter">
            {counts.nodes.toLocaleString()} nodes · {counts.edges.toLocaleString()} edges
          </div>
          {err && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div className="empty" style={{ background: 'var(--panel)' }}>{err}</div>
            </div>
          )}
        </div>

        {/* Always mounted so the slide-up transition can play; content swaps
            based on `panel`, sheet stays hidden below the fold when null. */}
        <div className={`side-panel ${panel ? 'open' : ''}`} style={{ height: sheetHeight }}>
          <div className="sheet-handle" onPointerDown={handleSheetDragStart}><span /></div>
          {panel === 'detail' && selected && (
            <RuleDetail
              ruleId={selected}
              displayed={engineRef.current?.displayed}
              onClose={() => { setPanel(null); engineRef.current?.select(null); setSelected(null); }}
              onJump={jumpTo}
              onExpandChildren={isScoped ? undefined : expandChildren}
              onExpandParents={isScoped ? undefined : expandParents}
            />
          )}
          {panel === 'stats' && (
            <StatsPanel
              product={productName}
              onClose={() => setPanel(null)}
              onJump={jumpTo}
              onHighlightCycle={ids => {
                const e = engineRef.current;
                if (!e) return;
                const missing = ids.filter(id => !e.displayed.has(id));
                const after = () => {
                  e.multiSelected = new Set(ids);
                  setMulti(new Set(ids));
                  e.requestRender();
                  if (ids[0]) e.centerOn(ids[0]);
                };
                if (missing.length && !isScoped) {
                  api.nodesBatch(missing, Array.from(e.displayed)).then(r => {
                    e.merge(r.nodes, r.edges); after();
                  });
                } else after();
              }}
            />
          )}
        </div>
      </div>

      {showHeatmap && <HeatmapModal onClose={() => setShowHeatmap(false)} />}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
