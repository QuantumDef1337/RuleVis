import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../../lib/api';
import type { FileInfo, Product } from '../../lib/types';
import { IconSearch } from '../../icons';
import { ProductEditor } from './editors';

export default function UnmappedFilesTab({ notify }: { notify: (m: string) => void }) {
  const { tenantId } = useParams();
  const navigate = useNavigate();
  const [files, setFiles] = useState<FileInfo[]>([]);
  const [q, setQ] = useState('');
  const [editProduct, setEditProduct] = useState<Partial<Product> | null | undefined>(undefined);

  const reload = () => { api.files().then(r => setFiles(r.files)); };
  useEffect(reload, []);

  const unmapped = useMemo(
    () => files
      .filter(f => !f.product)
      .filter(f => f.file.toLowerCase().includes(q.toLowerCase()))
      .sort((a, b) => b.rule_count - a.rule_count),
    [files, q]);

  const totalUnmapped = files.filter(f => !f.product).length;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div>
          <h2 style={{ margin: '0 0 4px' }}>Unmapped rule files</h2>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            {totalUnmapped} file{totalUnmapped !== 1 ? 's' : ''} not assigned to a product. Map them so
            they appear as products in the Rules catalog.
          </p>
        </div>
        <div className="grow" style={{ flex: 1 }} />
        <div className="search-wrap">
          <IconSearch />
          <input placeholder="Filter files…" value={q} onChange={e => setQ(e.target.value)} />
        </div>
      </div>

      <div className="card" style={{ padding: 0, marginTop: 18, maxHeight: '65vh', overflowY: 'auto' }}>
        <table className="data">
          <thead>
            <tr><th>File</th><th>Rules</th><th>Origin</th><th></th></tr>
          </thead>
          <tbody>
            {unmapped.map(f => (
              <tr key={f.file} className="clickable"
                onClick={() => navigate(`/t/${tenantId}/visualizer?file=${encodeURIComponent(f.file)}`)}>
                <td className="mono">{f.file}</td>
                <td>{f.rule_count}</td>
                <td>{f.builtin
                  ? <span className="badge">built-in</span>
                  : <span className="badge green">custom</span>}</td>
                <td style={{ textAlign: 'right' }}>
                  <button style={{ fontSize: 12 }} onClick={e => {
                    e.stopPropagation();
                    setEditProduct({ files: [f.file] });
                  }}>map to product →</button>
                </td>
              </tr>
            ))}
            {unmapped.length === 0 && (
              <tr><td colSpan={4}><div className="empty" style={{ border: 0 }}>
                {totalUnmapped === 0 ? 'All rule files are mapped to products. 🎉' : 'No files match your filter.'}
              </div></td></tr>
            )}
          </tbody>
        </table>
      </div>

      {editProduct !== undefined && (
        <ProductEditor product={editProduct} files={files}
          onClose={() => setEditProduct(undefined)}
          onSaved={() => { setEditProduct(undefined); notify('Product saved.'); reload(); }} />
      )}
    </div>
  );
}
