import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../lib/api';
import type { Product, SearchResult } from '../lib/types';
import { IconDownload, IconFile, IconSearch, IconShield, IconX } from '../icons';

const LEVEL_COLORS = {
  low: 'var(--green)', med: 'var(--amber)', high: 'var(--red)',
} as const;

function levelBucket(level: string): keyof typeof LEVEL_COLORS {
  const n = parseInt(level, 10);
  if (n >= 10) return 'high';
  if (n >= 5) return 'med';
  return 'low';
}

function bucketize(levels: Record<string, number>) {
  const buckets = { low: 0, med: 0, high: 0 };
  for (const [lvl, count] of Object.entries(levels)) buckets[levelBucket(lvl)] += count;
  return buckets;
}

function LevelBar({ levels }: { levels: Record<string, number> }) {
  const b = bucketize(levels);
  const total = b.low + b.med + b.high || 1;
  return (
    <div className="level-bar" title={`low(0-4): ${b.low} · medium(5-9): ${b.med} · high(10+): ${b.high}`}>
      {(['low', 'med', 'high'] as const).map(k =>
        b[k] > 0 ? <div key={k} style={{ width: `${(b[k] / total) * 100}%`, background: LEVEL_COLORS[k] }} /> : null,
      )}
    </div>
  );
}

function FilesModal({ product, onClose }: { product: Product; onClose: () => void }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 480 }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3>{product.name} — {product.files.length} file{product.files.length !== 1 ? 's' : ''}</h3>
          <button className="icon-btn" onClick={onClose}><IconX /></button>
        </div>
        <div style={{ marginTop: 8 }}>
          {(product.file_details ?? product.files.map(f => ({ file: f, rule_count: 0 }))).map(fd => (
            <div key={fd.file} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 0', borderBottom: '1px solid var(--border)' }}>
              <IconFile size={13} />
              <span className="mono" style={{ flex: 1 }}>{fd.file}</span>
              {'rule_count' in fd && fd.rule_count ? <span className="faint" style={{ fontSize: 12 }}>{fd.rule_count} rules</span> : null}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ProductCard({ product, onOpen }: { product: Product; onOpen: () => void }) {
  const [showFiles, setShowFiles] = useState(false);
  const total = product.rule_count ?? 0;
  const prod = product.production_rules ?? 0;

  return (
    <>
      <div className="card clickable product-card" onClick={onOpen}>
        <div className="head">
          <div className="product-icon">{product.icon || <IconShield size={20} />}</div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <h3>{product.name}</h3>
            {product.description && <span className="muted" style={{ fontSize: 12 }}>{product.description}</span>}
          </div>
          <a className="icon-btn" style={{ display: 'inline-flex', border: '1px solid var(--border)', borderRadius: 8 }}
            href={api.exportUrl('csv', `product:${product.name}`)} title="Export CSV"
            onClick={e => e.stopPropagation()}><IconDownload size={14} /></a>
        </div>

        <div className="product-metrics">
          <div className="pm">
            <div className="pm-val">{total.toLocaleString()}</div>
            <div className="pm-label">Total rules</div>
          </div>
          <div className="pm">
            <div className="pm-val" style={{ color: prod > 0 ? 'var(--green)' : undefined }}>{prod.toLocaleString()}</div>
            <div className="pm-label">Production</div>
          </div>
          <div className="pm">
            <button className="pm-files" onClick={e => { e.stopPropagation(); setShowFiles(true); }}
              title="View file names">
              {product.files.length}
            </button>
            <div className="pm-label">Files</div>
          </div>
        </div>

        <div style={{ marginTop: 10 }}>
          <div className="pm-label" style={{ marginBottom: 4 }}>Severity</div>
          {product.levels && Object.keys(product.levels).length > 0
            ? <LevelBar levels={product.levels} />
            : <span className="faint" style={{ fontSize: 12 }}>—</span>}
        </div>
      </div>
      {showFiles && <FilesModal product={product} onClose={() => setShowFiles(false)} />}
    </>
  );
}

export default function Rules() {
  const { tenantId } = useParams();
  const [products, setProducts] = useState<Product[]>([]);
  const [q, setQ] = useState('');
  const [results, setResults] = useState<SearchResult[] | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    api.products().then(r => setProducts(r.products)).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!q.trim()) { setResults(null); return; }
    const t = setTimeout(() => {
      api.search(q.trim(), undefined, 50).then(r => setResults(r.results)).catch(() => setResults([]));
    }, 250);
    return () => clearTimeout(t);
  }, [q]);

  return (
    <div className="page">
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
        <div>
          <h2 style={{ margin: '0 0 4px' }}>Deployed log sources</h2>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            Rule files organized by product. Open a product to explore its rules in the visualizer.
          </p>
        </div>
        <div className="grow" style={{ flex: 1 }} />
        <div className="search-wrap">
          <IconSearch />
          <input placeholder="Search all rules — ID or description…" value={q} onChange={e => setQ(e.target.value)} />
          {results !== null && (
            <div className="search-results">
              {results.length === 0 && <div className="sr"><span className="muted">No rules found.</span></div>}
              {results.map(r => (
                <div key={r.id} className="sr" onClick={() => {
                  const dest = r.product
                    ? `/t/${tenantId}/visualizer/${encodeURIComponent(r.product)}?focus=${r.id}`
                    : `/t/${tenantId}/visualizer?focus=${r.id}`;
                  navigate(dest);
                }}>
                  <span className="rid">{r.id}</span>
                  <span className="badge">{r.level ?? '?'}</span>
                  <span className="rdesc">{r.description || <i>no description</i>}</span>
                  {r.product && <span className="badge accent">{r.product}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {loading && <div className="empty" style={{ marginTop: 24 }}>Loading catalog…</div>}

      {!loading && products.length === 0 && (
        <div className="empty" style={{ marginTop: 24 }}>
          No products defined yet.<br />
          Go to <Link to={`/t/${tenantId}/settings`}>Settings</Link> to map your rule files
          (e.g. fortigate1.xml + fortigate_2.xml → <b>Fortigate</b>).
        </div>
      )}

      <div className="grid cards-3" style={{ marginTop: 22 }}>
        {products.map(p => (
          <ProductCard key={p.id} product={p}
            onOpen={() => navigate(`/t/${tenantId}/visualizer/${encodeURIComponent(p.id)}`)} />
        ))}
      </div>
    </div>
  );
}
