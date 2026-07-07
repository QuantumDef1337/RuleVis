import { useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api';
import type { Heatmap } from '../lib/types';
import { IconX } from '../icons';

const BLOCK_SIZES = [100, 250, 500, 1000];

export default function HeatmapModal(props: { onClose: () => void }) {
  const [blockSize, setBlockSize] = useState(500);
  const [data, setData] = useState<Heatmap | null>(null);
  const [hover, setHover] = useState('');

  useEffect(() => {
    setData(null);
    api.heatmap(blockSize).then(setData);
  }, [blockSize]);

  const maxCount = useMemo(
    () => Math.max(1, ...(data?.blocks ?? []).map(b => b.count)),
    [data]);

  const color = (count: number) => {
    if (count === 0) return 'var(--panel-2)';
    const t = Math.sqrt(count / maxCount); // sqrt scale for better spread
    const alpha = 0.15 + t * 0.85;
    return `rgba(244, 63, 94, ${alpha.toFixed(2)})`;
  };

  return (
    <div className="modal-overlay" onClick={props.onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <h3 style={{ margin: 0 }}>Rule ID heatmap</h3>
          <select value={blockSize} onChange={e => setBlockSize(+e.target.value)}>
            {BLOCK_SIZES.map(b => <option key={b} value={b}>blocks of {b}</option>)}
          </select>
          <span className="muted" style={{ fontSize: 12, flex: 1 }}>
            {hover || 'Dark blocks are free ID ranges for custom rules; red = densely used.'}
          </span>
          <button className="icon-btn" onClick={props.onClose}><IconX /></button>
        </div>
        <div style={{ marginTop: 16 }}>
          {!data && <p className="muted">Loading…</p>}
          {data?.blocks && (
            <div className="heatmap-grid">
              {data.blocks.map(b => (
                <div
                  key={b.id}
                  className="hm-cell"
                  style={{ background: color(b.count), border: '1px solid var(--border)' }}
                  onMouseEnter={() => setHover(`IDs ${b.id}: ${b.count} rule${b.count !== 1 ? 's' : ''}`)}
                  onMouseLeave={() => setHover('')}
                  title={`${b.id}: ${b.count}`}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
