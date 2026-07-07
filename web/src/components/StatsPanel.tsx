import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import type { Stats } from '../lib/types';
import { IconX } from '../icons';

function TopList(props: { title: string; items: { id: string; count?: number }[]; onJump: (id: string) => void }) {
  return (
    <>
      <h4 style={{ margin: '16px 0 6px' }}>{props.title}</h4>
      {props.items.length === 0 && <p className="faint" style={{ margin: 0 }}>No data.</p>}
      <div className="rel-list">
        {props.items.map(it => (
          <div key={it.id} className="rel" onClick={() => props.onJump(it.id)}>
            <span className="rid">{it.id}</span>
            {it.count !== undefined && <span className="badge">{it.count}</span>}
          </div>
        ))}
      </div>
    </>
  );
}

export default function StatsPanel(props: {
  product?: string;
  onClose: () => void;
  onJump: (id: string) => void;
  onHighlightCycle: (ids: string[]) => void;
}) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    api.stats(props.product).then(setStats).catch(e => setErr(String(e.message ?? e)));
  }, [props.product]);

  const selfLoops = stats?.self_loops ?? [];
  const cycles = stats?.cycles ?? [];

  return (
    <div className="panel-inner">
      <div className="close-row">
        <h3>Statistics{props.product ? ` — ${props.product}` : ''}</h3>
        <button className="icon-btn" onClick={props.onClose}><IconX /></button>
      </div>
      {err && <p style={{ color: 'var(--red)' }}>{err}</p>}
      {!stats && !err && <p className="muted">Calculating…</p>}
      {stats && (
        <div className="stats-columns">
          <TopList title="Most direct children (foundational)" items={stats.top_direct_descendants} onJump={props.onJump} />
          <TopList title="Highest impact (total descendants)" items={stats.top_indirect_descendants} onJump={props.onJump} />
          <TopList title="Most direct parents" items={stats.top_direct_ancestors} onJump={props.onJump} />
          <TopList title="Most complex dependencies (total ancestors)" items={stats.top_indirect_ancestors} onJump={props.onJump} />
          <TopList title="Isolated rules" items={stats.isolated_rules} onJump={props.onJump} />

          <div>
            <h4 style={{ margin: '16px 0 6px', color: (selfLoops.length + cycles.length) ? 'var(--red)' : undefined }}>
              Cycles {selfLoops.length + cycles.length > 0 && `(${selfLoops.length + cycles.length})`}
            </h4>
            {selfLoops.length + cycles.length === 0 && (
              <p style={{ color: 'var(--green)', margin: 0, fontSize: 13 }}>
                No cycles — the ruleset is a clean DAG.
              </p>
            )}
            {selfLoops.map(l => (
              <div key={l.id} className="rel" onClick={() => props.onJump(l.id)}>
                <span className="rid">{l.id}</span>
                <span className="badge red">self-loop</span>
              </div>
            ))}
            {cycles.map((cycle, i) => (
              <div key={i} className="rel" onClick={() => props.onHighlightCycle([...new Set(cycle)])}>
                <span className="rd mono" style={{ whiteSpace: 'normal' }}>{cycle.join(' → ')}</span>
                <span className="badge red">cycle</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
