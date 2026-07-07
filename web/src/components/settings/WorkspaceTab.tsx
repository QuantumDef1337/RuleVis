import { useEffect, useState } from 'react';
import { api } from '../../lib/api';
import type { FileInfo, GithubSource, Manager, Product } from '../../lib/types';
import {
  IconFile, IconGitBranch, IconPlus, IconRefresh, IconServer, IconTrash,
  IconUpload, IconX,
} from '../../icons';
import { GithubSourceEditor, ManagerEditor, ProductEditor } from './editors';

function ProductFilesModal({ product, onClose }: { product: Product; onClose: () => void }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 480 }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3>{product.name} — {product.files.length} file{product.files.length !== 1 ? 's' : ''}</h3>
          <button className="icon-btn" onClick={onClose}><IconX /></button>
        </div>
        <div style={{ marginTop: 8 }}>
          {product.files.length === 0 && <p className="faint">No files mapped.</p>}
          {product.files.map(f => (
            <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 0', borderBottom: '1px solid var(--border)' }}>
              <IconFile size={13} />
              <span className="mono">{f}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function WorkspaceTab({ notify }: { notify: (m: string) => void }) {
  const [products, setProducts] = useState<Product[]>([]);
  const [managers, setManagers] = useState<Manager[]>([]);
  const [githubSources, setGithubSources] = useState<GithubSource[]>([]);
  const [files, setFiles] = useState<FileInfo[]>([]);
  const [paths, setPaths] = useState<string[]>([]);
  const [newPath, setNewPath] = useState('');
  const [caseTags, setCaseTags] = useState<string[]>([]);
  const [newCaseTag, setNewCaseTag] = useState('');
  const [editProduct, setEditProduct] = useState<Partial<Product> | null | undefined>(undefined);
  const [viewFilesProduct, setViewFilesProduct] = useState<Product | null>(null);
  const [editManager, setEditManager] = useState<Partial<Manager> | null | undefined>(undefined);
  const [editGithubSource, setEditGithubSource] = useState<Partial<GithubSource> | null | undefined>(undefined);
  const [busy, setBusy] = useState<string>('');
  const [mgrStatus, setMgrStatus] = useState<Record<string, string>>({});
  const [ghStatus, setGhStatus] = useState<Record<string, string>>({});

  const reload = () => {
    api.settings().then(s => {
      setManagers(s.managers); setPaths(s.paths);
      setCaseTags(s.case_tags ?? []); setGithubSources(s.github_sources ?? []);
    });
    // Settings only returns the raw config (no rule_count/production_rules) —
    // /products is the enriched catalog Rules.tsx also uses, so product cards
    // show real counts instead of always reading 0.
    api.products().then(r => setProducts(r.products));
    api.files().then(r => setFiles(r.files));
  };
  useEffect(reload, []);

  const savePaths = async (next: string[]) => {
    await api.updateSettings({ paths: next } as never);
    setPaths(next);
    notify('Paths saved — rebuild to apply.');
  };

  const saveCaseTags = async (next: string[]) => {
    await api.updateSettings({ case_tags: next } as never);
    setCaseTags(next);
    notify('Case tags saved.');
  };

  const uploadFiles = async (fl: FileList | File[]) => {
    if (!fl || Array.from(fl).length === 0) return;
    setBusy('upload');
    try {
      const r = await api.upload(fl);
      notify(`Uploaded ${r.saved.length} file(s)${r.rejected.length ? `, skipped ${r.rejected.length} (not .xml)` : ''}.`);
      reload();
    } catch (err) {
      notify(`Upload failed: ${err}`);
    } finally {
      setBusy('');
    }
  };

  const rebuild = async () => {
    setBusy('rebuild');
    try {
      const ov = await api.rebuild();
      notify(`Rebuilt: ${ov.total_rules.toLocaleString()} rules from ${ov.total_files} files.`);
      reload();
    } catch (e) {
      notify(`Rebuild failed: ${e}`);
    } finally {
      setBusy('');
    }
  };

  const testManager = async (m: Manager) => {
    setMgrStatus(s => ({ ...s, [m.id]: 'testing…' }));
    try {
      const r = await api.testManager(m.id);
      setMgrStatus(s => ({
        ...s,
        [m.id]: r.ok ? `ok: ${(r.info as { version?: string })?.version ?? 'connected'}` : `error: ${r.error}`,
      }));
    } catch (e) {
      setMgrStatus(s => ({ ...s, [m.id]: `error: ${e}` }));
    }
  };

  const fetchManager = async (m: Manager) => {
    setBusy(`fetch-${m.id}`);
    setMgrStatus(s => ({ ...s, [m.id]: 'syncing…' }));
    try {
      const r = await api.fetchManager(m.id);
      const d = r.diff?.summary;
      const diffMsg = d ? ` — +${d.added}, -${d.removed}, ${d.changed} changed` : '';
      setMgrStatus(s => ({ ...s, [m.id]: `synced ${r.downloaded}/${r.total} files${diffMsg}` }));
      notify(`Synced ${r.downloaded} rule files from ${m.name || m.url}.${diffMsg} See Audit log for details.`);
      reload();
    } catch (e) {
      setMgrStatus(s => ({ ...s, [m.id]: `error: ${e}` }));
    } finally {
      setBusy('');
    }
  };

  const testGithubSource = async (s: GithubSource) => {
    setGhStatus(st => ({ ...st, [s.id]: 'testing…' }));
    try {
      const r = await api.testGithubSource(s.id);
      setGhStatus(st => ({
        ...st,
        [s.id]: r.ok ? `ok: ${(r.info as { full_name?: string })?.full_name ?? 'connected'}` : `error: ${r.error}`,
      }));
    } catch (e) {
      setGhStatus(st => ({ ...st, [s.id]: `error: ${e}` }));
    }
  };

  const fetchGithubSource = async (s: GithubSource) => {
    setBusy(`gh-fetch-${s.id}`);
    setGhStatus(st => ({ ...st, [s.id]: 'downloading rule files…' }));
    try {
      const r = await api.fetchGithubSource(s.id);
      setGhStatus(st => ({ ...st, [s.id]: `fetched ${r.downloaded}/${r.total} files` }));
      notify(`Fetched ${r.downloaded} rule files from ${s.name || s.repo}. Workspace rebuilt.`);
      reload();
    } catch (e) {
      setGhStatus(st => ({ ...st, [s.id]: `error: ${e}` }));
    } finally {
      setBusy('');
    }
  };

  return (
    <div>
      {/* ---- Products ---- */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <h2 style={{ margin: 0 }}>Products</h2>
        <span className="muted" style={{ fontSize: 13 }}>Map rule files to the log sources they belong to.</span>
        <div style={{ marginLeft: 'auto' }}>
          <button className="primary" onClick={() => setEditProduct(null)}>
            <IconPlus size={13} /> New product
          </button>
        </div>
      </div>

      <div className="grid cards-3" style={{ marginTop: 16 }}>
        {products.map(p => (
          <div key={p.id} className="card product-card">
            <div className="head">
              <div className="product-icon">{p.icon || '📦'}</div>
              <div style={{ minWidth: 0 }}>
                <h3>{p.name}</h3>
              </div>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                <button onClick={() => setEditProduct(p)}>Edit</button>
                <button className="icon-btn danger" title="Delete"
                  onClick={async () => {
                    await api.deleteProduct(p.id);
                    notify(`Deleted ${p.name}.`);
                    reload();
                  }}><IconTrash size={13} /></button>
              </div>
            </div>
            <div className="product-metrics">
              <div className="pm">
                <div className="pm-val">{(p.rule_count ?? 0).toLocaleString()}</div>
                <div className="pm-label">Total rules</div>
              </div>
              <div className="pm">
                <div className="pm-val" style={{ color: (p.production_rules ?? 0) > 0 ? 'var(--green)' : undefined }}>
                  {(p.production_rules ?? 0).toLocaleString()}
                </div>
                <div className="pm-label">Production</div>
              </div>
              <div className="pm">
                <button className="pm-files" onClick={() => setViewFilesProduct(p)}>{p.files.length}</button>
                <div className="pm-label">Files</div>
              </div>
            </div>
          </div>
        ))}
        {products.length === 0 && (
          <div className="empty" style={{ gridColumn: '1 / -1' }}>
            No products yet. Create one — e.g. <b>Fortigate</b> — and assign its rule files.
            Unmapped files live in the <b>Unmapped files</b> tab.
          </div>
        )}
      </div>

      {/* ---- Case tags ---- */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 40 }}>
        <h2 style={{ margin: 0 }}>Case tags</h2>
        <span className="muted" style={{ fontSize: 13 }}>
          Group names that mark a rule as production/case-managed (feeds "Production Rules" counts).
        </span>
      </div>
      <div className="card" style={{ marginTop: 16 }}>
        {caseTags.map(tag => (
          <div key={tag} style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '6px 0' }}>
            <span className="chip" style={{ flex: 1, width: 'fit-content' }}>{tag}</span>
            <button className="icon-btn danger" onClick={() => saveCaseTags(caseTags.filter(t => t !== tag))}>
              <IconTrash size={13} />
            </button>
          </div>
        ))}
        {caseTags.length === 0 && (
          <p className="faint" style={{ margin: '4px 0 10px' }}>
            No case tags configured — Production Rules will be 0.
          </p>
        )}
        <div style={{ display: 'flex', gap: 8 }}>
          <input type="text" style={{ flex: 1 }} placeholder="e.g. soar-alert"
            value={newCaseTag} onChange={e => setNewCaseTag(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && newCaseTag.trim()) {
                saveCaseTags([...caseTags, newCaseTag.trim()]); setNewCaseTag('');
              }
            }} />
          <button onClick={() => {
            if (newCaseTag.trim()) { saveCaseTags([...caseTags, newCaseTag.trim()]); setNewCaseTag(''); }
          }}><IconPlus size={13} /> Add tag</button>
        </div>
      </div>

      {/* ---- Managers ---- */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 40 }}>
        <h2 style={{ margin: 0 }}>Wazuh managers</h2>
        <span className="muted" style={{ fontSize: 13 }}>Fetch rules live from the Wazuh API. Scoped to this tenant.</span>
        <div style={{ marginLeft: 'auto' }}>
          <button className="primary" onClick={() => setEditManager(null)}>
            <IconPlus size={13} /> Add manager
          </button>
        </div>
      </div>

      <div className="grid cards-3" style={{ marginTop: 16 }}>
        {managers.map(m => (
          <div key={m.id} className="card product-card">
            <div className="head">
              <div className="product-icon" style={{ background: 'var(--green-soft)' }}><IconServer size={18} /></div>
              <div style={{ minWidth: 0 }}>
                <h3>{m.name || m.url}</h3>
                <span className="muted mono" style={{ fontSize: 11.5 }}>{m.url}</span>
              </div>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                <button onClick={() => setEditManager(m)}>Edit</button>
                <button className="icon-btn danger" title="Delete"
                  onClick={async () => { await api.deleteManager(m.id); reload(); }}>
                  <IconTrash size={13} />
                </button>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <button onClick={() => testManager(m)}>Test connection</button>
              <button className="primary" disabled={busy === `fetch-${m.id}`} onClick={() => fetchManager(m)}>
                {busy === `fetch-${m.id}` ? 'Syncing…' : 'Sync now'}
              </button>
              {m.include && <span className="badge green">in workspace</span>}
              {m.auto_sync && (
                <span className="badge accent" title={m.last_synced_at ? `Last synced ${new Date(m.last_synced_at).toLocaleString()}` : ''}>
                  auto-sync every {m.sync_interval_minutes ?? 60}m
                </span>
              )}
              {m.last_sync_status === 'failed' && (
                <span className="badge red" title={m.last_sync_error ?? ''}>last sync failed</span>
              )}
            </div>
            {mgrStatus[m.id] && (
              <div className={`mgr-status ${mgrStatus[m.id].startsWith('error') ? 'err' : 'ok'}`}>
                {mgrStatus[m.id]}
              </div>
            )}
          </div>
        ))}
        {managers.length === 0 && (
          <div className="empty" style={{ gridColumn: '1 / -1' }}>
            No managers connected for this tenant.
          </div>
        )}
      </div>

      {/* ---- GitHub sources ---- */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 40 }}>
        <h2 style={{ margin: 0 }}>GitHub sources</h2>
        <span className="muted" style={{ fontSize: 13 }}>Fetch rule files from a GitHub repository. Scoped to this tenant.</span>
        <div style={{ marginLeft: 'auto' }}>
          <button className="primary" onClick={() => setEditGithubSource(null)}>
            <IconPlus size={13} /> Add GitHub source
          </button>
        </div>
      </div>

      <div className="grid cards-3" style={{ marginTop: 16 }}>
        {githubSources.map(s => (
          <div key={s.id} className="card product-card">
            <div className="head">
              <div className="product-icon" style={{ background: 'var(--violet-soft)' }}><IconGitBranch size={18} /></div>
              <div style={{ minWidth: 0 }}>
                <h3>{s.name || s.repo}</h3>
                <span className="muted mono" style={{ fontSize: 11.5 }}>
                  {s.repo}@{s.branch}{s.path ? `/${s.path}` : ''}
                </span>
              </div>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                <button onClick={() => setEditGithubSource(s)}>Edit</button>
                <button className="icon-btn danger" title="Delete"
                  onClick={async () => { await api.deleteGithubSource(s.id); reload(); }}>
                  <IconTrash size={13} />
                </button>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <button onClick={() => testGithubSource(s)}>Test connection</button>
              <button className="primary" disabled={busy === `gh-fetch-${s.id}`} onClick={() => fetchGithubSource(s)}>
                {busy === `gh-fetch-${s.id}` ? 'Fetching…' : 'Fetch rules'}
              </button>
              {s.include && <span className="badge green">in workspace</span>}
              {s.auto_sync && (
                <span className="badge accent" title={s.last_synced_at ? `Last synced ${new Date(s.last_synced_at).toLocaleString()}` : ''}>
                  auto-sync every {s.sync_interval_minutes ?? 60}m
                </span>
              )}
              {s.last_sync_status === 'failed' && (
                <span className="badge red" title={s.last_sync_error ?? ''}>last sync failed</span>
              )}
            </div>
            {ghStatus[s.id] && (
              <div className={`mgr-status ${ghStatus[s.id].startsWith('error') ? 'err' : 'ok'}`}>
                {ghStatus[s.id]}
              </div>
            )}
          </div>
        ))}
        {githubSources.length === 0 && (
          <div className="empty" style={{ gridColumn: '1 / -1' }}>
            No GitHub sources yet for this tenant.
          </div>
        )}
      </div>

      {/* ---- Upload ---- */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 40 }}>
        <h2 style={{ margin: 0 }}>Upload rules</h2>
        <span className="muted" style={{ fontSize: 13 }}>Manually add rule XML files to this tenant's workspace.</span>
      </div>
      <div className="card" style={{ marginTop: 16 }}>
        <label className="upload-drop" htmlFor="rule-upload-input"
          onDragOver={e => e.preventDefault()}
          onDrop={e => { e.preventDefault(); uploadFiles(e.dataTransfer.files); }}>
          <IconUpload size={20} />
          <span>{busy === 'upload' ? 'Uploading…' : 'Click to choose .xml files, or drag them here'}</span>
        </label>
        <input id="rule-upload-input" type="file" accept=".xml" multiple
          style={{ display: 'none' }} disabled={busy === 'upload'}
          onChange={e => { uploadFiles(e.target.files ?? []); e.target.value = ''; }} />
      </div>

      {/* ---- Paths ---- */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 40 }}>
        <h2 style={{ margin: 0 }}>Local rule paths</h2>
        <span className="muted" style={{ fontSize: 13 }}>Directories scanned for rule XML files.</span>
        <div style={{ marginLeft: 'auto' }}>
          <button disabled={busy === 'rebuild'} onClick={rebuild}>
            <IconRefresh size={13} /> {busy === 'rebuild' ? 'Rebuilding…' : 'Rebuild workspace'}
          </button>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        {paths.map(p => (
          <div key={p} style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '6px 0' }}>
            <span className="mono" style={{ flex: 1 }}>{p}</span>
            <button className="icon-btn danger" onClick={() => savePaths(paths.filter(x => x !== p))}>
              <IconTrash size={13} />
            </button>
          </div>
        ))}
        {paths.length === 0 && <p className="faint" style={{ margin: '4px 0 10px' }}>
          No configured paths (CLI --path directories are used if given).</p>}
        <div style={{ display: 'flex', gap: 8 }}>
          <input type="text" style={{ flex: 1 }} placeholder="C:\path\to\rules"
            value={newPath} onChange={e => setNewPath(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && newPath.trim()) { savePaths([...paths, newPath.trim()]); setNewPath(''); }
            }} />
          <button onClick={() => {
            if (newPath.trim()) { savePaths([...paths, newPath.trim()]); setNewPath(''); }
          }}><IconPlus size={13} /> Add path</button>
        </div>
      </div>

      {editProduct !== undefined && (
        <ProductEditor product={editProduct} files={files}
          onClose={() => setEditProduct(undefined)}
          onSaved={() => { setEditProduct(undefined); notify('Product saved.'); reload(); }} />
      )}
      {editManager !== undefined && (
        <ManagerEditor manager={editManager}
          onClose={() => setEditManager(undefined)}
          onSaved={() => { setEditManager(undefined); notify('Manager saved.'); reload(); }} />
      )}
      {editGithubSource !== undefined && (
        <GithubSourceEditor source={editGithubSource}
          onClose={() => setEditGithubSource(undefined)}
          onSaved={() => { setEditGithubSource(undefined); notify('GitHub source saved.'); reload(); }} />
      )}
      {viewFilesProduct && (
        <ProductFilesModal product={viewFilesProduct} onClose={() => setViewFilesProduct(null)} />
      )}
    </div>
  );
}
