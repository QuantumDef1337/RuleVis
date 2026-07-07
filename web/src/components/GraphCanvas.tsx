import * as d3 from 'd3';
import { useEffect, useRef } from 'react';
import type { GraphEdge, GraphNode } from '../lib/types';

export type LayoutMode = 'force' | 'hierarchical' | 'radial';

export interface SimNode extends GraphNode, d3.SimulationNodeDatum {
  __radius?: number;
  __depth?: number;
}
interface SimLink extends d3.SimulationLinkDatum<SimNode> {
  relation_type: string;
  source: SimNode;
  target: SimNode;
}

export interface GraphFilter {
  group?: string;
  minLevel?: number;
  maxLevel?: number;
  pattern?: string;
}

interface EngineCallbacks {
  onSelect: (id: string | null) => void;
  onExpand: (id: string) => void;
  onMultiSelectChange: (ids: Set<string>) => void;
}

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || '#888';
}

/**
 * Canvas + d3-force graph engine. Rendering is batched by color for
 * performance (10k+ nodes). React wraps it thinly; all hot-path state
 * lives here, outside React's render cycle.
 */
export class GraphEngine {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;
  private sim: d3.Simulation<SimNode, SimLink>;
  private zoom: d3.ZoomBehavior<HTMLCanvasElement, unknown>;
  private transform = d3.zoomIdentity;
  private nodes: SimNode[] = [];
  private links: SimLink[] = [];
  private nodeMap = new Map<string, SimNode>();
  private linkKeys = new Set<string>();
  public displayed = new Set<string>();
  private width = 0;
  private height = 0;
  private dpr = window.devicePixelRatio || 1;
  private needsRender = true;
  private raf = 0;
  private destroyed = false;

  public selectedId: string | null = null;
  public multiSelected = new Set<string>();
  public focusMode = true;
  private focusContext = new Set<string>();
  public filter: GraphFilter = {};
  private filterActive = false;
  private matchCache = new Map<string, boolean>();
  public layout: LayoutMode = 'force';

  // box select state
  private boxStart: [number, number] | null = null;
  private boxEnd: [number, number] | null = null;

  private colors!: Record<string, string>;

  constructor(canvas: HTMLCanvasElement, private cb: EngineCallbacks) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d')!;
    this.readColors();

    this.sim = d3.forceSimulation<SimNode>()
      .force('link', d3.forceLink<SimNode, SimLink>().id(d => d.id).distance(70).strength(0.6))
      .force('charge', d3.forceManyBody().strength(-180))
      .force('collide', d3.forceCollide(16))
      .force('x', d3.forceX().strength(0.02))
      .force('y', d3.forceY().strength(0.02))
      .alphaDecay(0.025)
      .alphaMin(0.0001)
      .velocityDecay(0.75)
      .on('tick', () => { this.needsRender = true; });

    this.zoom = d3.zoom<HTMLCanvasElement, unknown>()
      .scaleExtent([0.02, 6])
      .filter((event: MouseEvent | WheelEvent) => !(event as MouseEvent).shiftKey)
      .on('zoom', e => { this.transform = e.transform; this.needsRender = true; });

    d3.select(canvas)
      .call(this.zoom)
      .call(d3.drag<HTMLCanvasElement, unknown>()
        .container(canvas)
        .filter((event: MouseEvent) => event.shiftKey || !!this.findNodeAt(event.offsetX, event.offsetY))
        .subject((event) => {
          const src = event.sourceEvent as MouseEvent;
          if (src.shiftKey) return { x: event.x, y: event.y };
          return this.findNodeAt(src.offsetX, src.offsetY) ?? undefined;
        })
        .on('start', (e) => this.dragStart(e))
        .on('drag', (e) => this.dragMove(e))
        .on('end', (e) => this.dragEnd(e)));

    canvas.addEventListener('click', this.handleClick);
    canvas.addEventListener('dblclick', this.handleDblClick);

    const loop = () => {
      if (this.destroyed) return;
      if (this.needsRender) { this.render(); this.needsRender = false; }
      this.raf = requestAnimationFrame(loop);
    };
    this.raf = requestAnimationFrame(loop);
  }

  readColors() {
    this.colors = {
      node: cssVar('--g-node'),
      expandable: cssVar('--g-node-expandable'),
      external: cssVar('--g-node-external'),
      selected: cssVar('--g-node-selected'),
      multi: cssVar('--g-node-multiselect'),
      label: cssVar('--g-label'),
      if_sid: cssVar('--g-edge-if_sid'),
      if_matched_sid: cssVar('--g-edge-if_matched_sid'),
      if_group: cssVar('--g-edge-if_group'),
      if_matched_group: cssVar('--g-edge-if_matched_group'),
      no_parent: cssVar('--g-edge-no_parent'),
      root: cssVar('--g-edge-root'),
      unknown: cssVar('--g-edge-unknown'),
    };
    this.needsRender = true;
  }

  resize(w: number, h: number) {
    const first = this.width === 0 && w > 0;
    this.width = w; this.height = h;
    this.dpr = window.devicePixelRatio || 1;
    this.canvas.width = w * this.dpr;
    this.canvas.height = h * this.dpr;
    if (first) {
      // world origin (where the force layout gravitates) starts at canvas center
      d3.select(this.canvas).call(
        this.zoom.transform, d3.zoomIdentity.translate(w / 2, h / 2));
    }
    this.needsRender = true;
  }

  destroy() {
    this.destroyed = true;
    cancelAnimationFrame(this.raf);
    this.sim.stop();
    this.canvas.removeEventListener('click', this.handleClick);
    this.canvas.removeEventListener('dblclick', this.handleDblClick);
  }

  // ---------------- data ----------------
  setData(nodes: GraphNode[], edges: GraphEdge[], replace: boolean) {
    if (replace) {
      this.nodes = []; this.links = [];
      this.nodeMap.clear(); this.linkKeys.clear(); this.displayed.clear();
      this.selectedId = null; this.multiSelected.clear(); this.focusContext.clear();
    }
    this.merge(nodes, edges);
  }

  merge(newNodes: GraphNode[], newEdges: GraphEdge[]) {
    const cx = this.nodes.length
      ? d3.mean(this.nodes, n => n.x ?? 0)! : 0;
    const cy = this.nodes.length
      ? d3.mean(this.nodes, n => n.y ?? 0)! : 0;

    for (const n of newNodes) {
      const existing = this.nodeMap.get(n.id);
      if (existing) {
        Object.assign(existing, n);
      } else {
        const sn: SimNode = {
          ...n,
          x: cx + (Math.random() - 0.5) * 300,
          y: cy + (Math.random() - 0.5) * 300,
        };
        this.nodeMap.set(n.id, sn);
        this.nodes.push(sn);
        this.displayed.add(n.id);
      }
    }
    for (const e of newEdges) {
      const key = `${e.source}->${e.target}`;
      if (this.linkKeys.has(key)) continue;
      const s = this.nodeMap.get(e.source);
      const t = this.nodeMap.get(e.target);
      if (!s || !t) continue;
      this.linkKeys.add(key);
      this.links.push({ source: s, target: t, relation_type: e.relation_type });
    }
    this.refreshExpandable();
    this.matchCache.clear();
    this.applyLayout(false);
    this.sim.nodes(this.nodes);
    (this.sim.force('link') as d3.ForceLink<SimNode, SimLink>).links(this.links);
    this.sim.alpha(0.9).restart();
    this.needsRender = true;
  }

  private refreshExpandable() {
    for (const n of this.nodes) {
      const kids = n.children_ids ?? [];
      n.expandable = kids.length > 0 && !kids.every(k => this.displayed.has(k));
    }
  }

  get nodeCount() { return this.nodes.length; }
  get edgeCount() { return this.links.length; }
  getNode(id: string) { return this.nodeMap.get(id); }
  allGroups(): string[] {
    const gs = new Set<string>();
    for (const n of this.nodes) for (const g of n.groups ?? []) gs.add(g);
    gs.delete('__meta__');
    return Array.from(gs).sort();
  }

  // ---------------- layouts ----------------
  setLayout(mode: LayoutMode) {
    this.layout = mode;
    this.applyLayout(true);
  }

  private computeDepths(): number {
    // BFS from roots (nodes with no displayed parents)
    const inDeg = new Map<string, number>();
    for (const n of this.nodes) inDeg.set(n.id, 0);
    for (const l of this.links) {
      if (l.source.id === '0') continue;
      inDeg.set(l.target.id, (inDeg.get(l.target.id) ?? 0) + 1);
    }
    const queue: SimNode[] = [];
    for (const n of this.nodes) {
      if (n.id === '0') { n.__depth = -1; continue; }
      if ((inDeg.get(n.id) ?? 0) === 0) { n.__depth = 0; queue.push(n); }
      else n.__depth = undefined;
    }
    const childrenOf = new Map<string, SimNode[]>();
    for (const l of this.links) {
      if (l.source.id === '0') continue;
      const arr = childrenOf.get(l.source.id) ?? [];
      arr.push(l.target);
      childrenOf.set(l.source.id, arr);
    }
    let maxDepth = 0;
    while (queue.length) {
      const n = queue.shift()!;
      for (const c of childrenOf.get(n.id) ?? []) {
        const nd = (n.__depth ?? 0) + 1;
        if (c.__depth === undefined || nd < c.__depth) {
          c.__depth = nd;
          maxDepth = Math.max(maxDepth, nd);
          queue.push(c);
        }
      }
    }
    for (const n of this.nodes) if (n.__depth === undefined) { n.__depth = maxDepth + 1; }
    return maxDepth + 1;
  }

  applyLayout(reheat: boolean) {
    const link = this.sim.force('link') as d3.ForceLink<SimNode, SimLink>;
    if (this.layout === 'force') {
      this.sim.force('x', d3.forceX(0).strength(0.02));
      this.sim.force('y', d3.forceY(0).strength(0.02));
      this.sim.force('r', null);
      link.distance(70);
    } else if (this.layout === 'hierarchical') {
      this.computeDepths();
      const gap = 140;
      this.sim.force('y', d3.forceY<SimNode>(d => (d.__depth ?? 0) * gap).strength(0.55));
      this.sim.force('x', d3.forceX(0).strength(0.015));
      this.sim.force('r', null);
      link.distance(90);
    } else {
      const depths = this.computeDepths();
      const ring = Math.max(160, 900 / Math.max(1, depths));
      this.sim.force('r', d3.forceRadial<SimNode>(
        d => Math.max(0, (d.__depth ?? 0)) * ring + (d.id === '0' ? 0 : 60), 0, 0).strength(0.8));
      this.sim.force('x', d3.forceX(0).strength(0.01));
      this.sim.force('y', d3.forceY(0).strength(0.01));
      link.distance(60);
    }
    if (reheat) this.sim.alpha(0.9).restart();
  }

  // ---------------- selection / focus ----------------
  select(id: string | null, center = false) {
    this.selectedId = id;
    this.updateFocus();
    if (id && center) this.centerOn(id);
    this.needsRender = true;
  }

  private updateFocus() {
    this.focusContext.clear();
    if (!this.selectedId) return;
    this.focusContext.add(this.selectedId);
    for (const l of this.links) {
      if (l.source.id === this.selectedId) this.focusContext.add(l.target.id);
      if (l.target.id === this.selectedId) this.focusContext.add(l.source.id);
    }
  }

  setFocusMode(on: boolean) {
    this.focusMode = on;
    this.needsRender = true;
  }

  centerOn(id: string) {
    const n = this.nodeMap.get(id);
    if (!n || n.x === undefined) return;
    const k = Math.max(this.transform.k, 1.1);
    const t = d3.zoomIdentity
      .translate(this.width / 2, this.height / 2)
      .scale(k)
      .translate(-n.x!, -n.y!);
    d3.select(this.canvas).transition().duration(650)
      .call(this.zoom.transform, t);
  }

  resetZoom() {
    d3.select(this.canvas).transition().duration(400)
      .call(this.zoom.transform, d3.zoomIdentity);
  }

  clearMultiSelect() {
    this.multiSelected.clear();
    this.cb.onMultiSelectChange(this.multiSelected);
    this.needsRender = true;
  }

  /** Expand multi-selection to the whole family (ancestors + descendants among displayed). */
  selectFamily() {
    const seeds = new Set(this.multiSelected);
    if (this.selectedId) seeds.add(this.selectedId);
    if (!seeds.size) return;
    const parentsOf = new Map<string, string[]>();
    const childrenOf = new Map<string, string[]>();
    for (const l of this.links) {
      if (l.source.id === '0') continue;
      (childrenOf.get(l.source.id) ?? childrenOf.set(l.source.id, []).get(l.source.id)!)
        .push(l.target.id);
      (parentsOf.get(l.target.id) ?? parentsOf.set(l.target.id, []).get(l.target.id)!)
        .push(l.source.id);
    }
    const family = new Set<string>(seeds);
    const walk = (start: string, map: Map<string, string[]>) => {
      const stack = [start];
      while (stack.length) {
        const cur = stack.pop()!;
        for (const nxt of map.get(cur) ?? []) {
          if (!family.has(nxt)) { family.add(nxt); stack.push(nxt); }
        }
      }
    };
    for (const s of seeds) { walk(s, parentsOf); walk(s, childrenOf); }
    this.multiSelected = family;
    this.cb.onMultiSelectChange(this.multiSelected);
    this.needsRender = true;
  }

  // ---------------- filters ----------------
  setFilter(f: GraphFilter) {
    this.filter = f;
    this.filterActive = !!(f.group || f.pattern
      || f.minLevel !== undefined || f.maxLevel !== undefined);
    this.matchCache.clear();
    this.needsRender = true;
  }

  private matchesFilter(n: SimNode): boolean {
    if (!this.filterActive) return true;
    const cached = this.matchCache.get(n.id);
    if (cached !== undefined) return cached;
    let ok = true;
    const f = this.filter;
    if (ok && f.group) ok = (n.groups ?? []).includes(f.group);
    if (ok && (f.minLevel !== undefined || f.maxLevel !== undefined)) {
      const lvl = parseInt(n.level ?? '', 10);
      if (Number.isNaN(lvl)) ok = false;
      else ok = lvl >= (f.minLevel ?? 0) && lvl <= (f.maxLevel ?? 99);
    }
    if (ok && f.pattern) {
      const p = f.pattern.toLowerCase();
      ok = n.id.toLowerCase().includes(p)
        || (n.description ?? '').toLowerCase().includes(p)
        || (n.file ?? '').toLowerCase().includes(p);
    }
    this.matchCache.set(n.id, ok);
    return ok;
  }

  // ---------------- interactions ----------------
  private findNodeAt(px: number, py: number): SimNode | null {
    const [ix, iy] = this.transform.invert([px, py]);
    const rSq = 144 / (this.transform.k * this.transform.k);
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      const dx = ix - (n.x ?? 0), dy = iy - (n.y ?? 0);
      if (dx * dx + dy * dy < Math.max(rSq, (n.__radius ?? 10) ** 2)) return n;
    }
    return null;
  }

  private handleClick = (e: MouseEvent) => {
    if (this.boxJustFinished) { this.boxJustFinished = false; return; }
    const n = this.findNodeAt(e.offsetX, e.offsetY);
    if (!n) {
      if (!e.shiftKey) { this.select(null); this.cb.onSelect(null); }
      return;
    }
    if (e.shiftKey) {
      if (this.multiSelected.has(n.id)) this.multiSelected.delete(n.id);
      else this.multiSelected.add(n.id);
      this.cb.onMultiSelectChange(this.multiSelected);
      this.needsRender = true;
      return;
    }
    this.select(n.id);
    this.cb.onSelect(n.id);
  };

  private handleDblClick = (e: MouseEvent) => {
    const n = this.findNodeAt(e.offsetX, e.offsetY);
    if (n && n.expandable) this.cb.onExpand(n.id);
  };

  private dragged = false;
  private boxJustFinished = false;

  private dragStart(e: d3.D3DragEvent<HTMLCanvasElement, unknown, SimNode>) {
    const src = e.sourceEvent as MouseEvent;
    if (src.shiftKey) {
      this.boxStart = [src.offsetX, src.offsetY];
      this.boxEnd = this.boxStart;
      return;
    }
    if (!e.active) this.sim.alphaTarget(0.25).restart();
    const s = e.subject as SimNode;
    s.fx = s.x; s.fy = s.y;
    this.dragged = false;
  }

  private dragMove(e: d3.D3DragEvent<HTMLCanvasElement, unknown, SimNode>) {
    const src = e.sourceEvent as MouseEvent;
    if (this.boxStart) {
      this.boxEnd = [src.offsetX, src.offsetY];
      this.needsRender = true;
      return;
    }
    const s = e.subject as SimNode;
    const [ix, iy] = this.transform.invert([src.offsetX, src.offsetY]);
    s.fx = ix; s.fy = iy;
    this.dragged = true;
  }

  private dragEnd(e: d3.D3DragEvent<HTMLCanvasElement, unknown, SimNode>) {
    if (this.boxStart && this.boxEnd) {
      const [x0, y0] = this.transform.invert(this.boxStart);
      const [x1, y1] = this.transform.invert(this.boxEnd);
      const [minX, maxX] = [Math.min(x0, x1), Math.max(x0, x1)];
      const [minY, maxY] = [Math.min(y0, y1), Math.max(y0, y1)];
      for (const n of this.nodes) {
        if (n.id === '0') continue;
        if ((n.x ?? 0) >= minX && (n.x ?? 0) <= maxX && (n.y ?? 0) >= minY && (n.y ?? 0) <= maxY) {
          this.multiSelected.add(n.id);
        }
      }
      this.cb.onMultiSelectChange(this.multiSelected);
      this.boxStart = this.boxEnd = null;
      this.boxJustFinished = true;
      this.needsRender = true;
      return;
    }
    if (!e.active) this.sim.alphaTarget(0);
    const s = e.subject as SimNode;
    if (!this.dragged) { s.fx = null; s.fy = null; }
    // keep dragged nodes pinned; release un-dragged
  }

  // ---------------- render ----------------
  private render() {
    const ctx = this.ctx;
    ctx.save();
    ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
    ctx.scale(this.dpr, this.dpr);
    ctx.translate(this.transform.x, this.transform.y);
    ctx.scale(this.transform.k, this.transform.k);
    const k = this.transform.k;

    const focusOn = this.focusMode && this.focusContext.size > 0;
    const dimmed = (id: string) => {
      const n = this.nodeMap.get(id);
      if (n && !this.matchesFilter(n)) return true;
      if (focusOn && !this.focusContext.has(id)) return true;
      return false;
    };

    // --- edges, batched by color+dim ---
    const edgeBatches = new Map<string, SimLink[]>();
    for (const l of this.links) {
      const dim = dimmed(l.source.id) || dimmed(l.target.id);
      const key = `${l.relation_type}|${dim ? 1 : 0}`;
      (edgeBatches.get(key) ?? edgeBatches.set(key, []).get(key)!).push(l);
    }
    ctx.lineWidth = 1.4 / k;
    for (const [key, batch] of edgeBatches) {
      const [rel, dim] = key.split('|');
      ctx.globalAlpha = dim === '1' ? 0.06 : 0.75;
      ctx.strokeStyle = this.colors[rel] ?? this.colors.unknown;
      ctx.beginPath();
      for (const l of batch) {
        ctx.moveTo(l.source.x ?? 0, l.source.y ?? 0);
        ctx.lineTo(l.target.x ?? 0, l.target.y ?? 0);
      }
      ctx.stroke();
    }

    // arrowheads when zoomed in
    if (k > 0.55) {
      for (const l of this.links) {
        if (dimmed(l.source.id) || dimmed(l.target.id)) continue;
        ctx.globalAlpha = 0.85;
        ctx.fillStyle = this.colors[l.relation_type] ?? this.colors.unknown;
        this.arrowhead(l.source, l.target);
      }
    }

    // --- nodes, batched ---
    const batches = new Map<string, SimNode[]>();
    for (const n of this.nodes) {
      const dim = dimmed(n.id);
      let style = 'node';
      if (n.id === '0') style = 'external';
      else if (n.external) style = 'external';
      else if (n.expandable) style = 'expandable';
      n.__radius = n.id === '0' ? 14 : n.external ? 7 : dim ? 5 : 10;
      const key = `${style}|${dim ? 1 : 0}`;
      (batches.get(key) ?? batches.set(key, []).get(key)!).push(n);
    }
    for (const [key, batch] of batches) {
      const [style, dim] = key.split('|');
      ctx.globalAlpha = dim === '1' ? 0.12 : 1;
      ctx.fillStyle = this.colors[style] ?? this.colors.node;
      ctx.beginPath();
      for (const n of batch) {
        ctx.moveTo((n.x ?? 0) + n.__radius!, n.y ?? 0);
        ctx.arc(n.x ?? 0, n.y ?? 0, n.__radius!, 0, 2 * Math.PI);
      }
      ctx.fill();
    }
    ctx.globalAlpha = 1;

    // selection rings
    if (this.multiSelected.size) {
      ctx.strokeStyle = this.colors.multi;
      ctx.lineWidth = 2.5 / k;
      ctx.beginPath();
      for (const id of this.multiSelected) {
        const n = this.nodeMap.get(id);
        if (!n) continue;
        ctx.moveTo((n.x ?? 0) + (n.__radius ?? 10) + 4 / k, n.y ?? 0);
        ctx.arc(n.x ?? 0, n.y ?? 0, (n.__radius ?? 10) + 4 / k, 0, 2 * Math.PI);
      }
      ctx.stroke();
    }
    if (this.selectedId) {
      const n = this.nodeMap.get(this.selectedId);
      if (n) {
        ctx.strokeStyle = this.colors.selected;
        ctx.lineWidth = 3 / k;
        ctx.beginPath();
        ctx.arc(n.x ?? 0, n.y ?? 0, (n.__radius ?? 10) + 3 / k, 0, 2 * Math.PI);
        ctx.stroke();
      }
    }

    // labels
    if (k >= 0.4) {
      ctx.fillStyle = this.colors.label;
      ctx.font = `${k >= 1 ? 12 / k : 11}px 'Segoe UI', sans-serif`;
      for (const n of this.nodes) {
        if (n.id === '0' || dimmed(n.id)) continue;
        ctx.fillText(n.id, (n.x ?? 0) + (n.__radius ?? 10) + 4, (n.y ?? 0) + 4);
      }
    }
    ctx.restore();

    // box-select rect (screen space)
    if (this.boxStart && this.boxEnd) {
      ctx.save();
      ctx.scale(this.dpr, this.dpr);
      ctx.strokeStyle = this.colors.multi;
      ctx.fillStyle = this.colors.multi + '18';
      ctx.lineWidth = 1;
      const [x0, y0] = this.boxStart;
      const [x1, y1] = this.boxEnd;
      ctx.fillRect(Math.min(x0, x1), Math.min(y0, y1), Math.abs(x1 - x0), Math.abs(y1 - y0));
      ctx.strokeRect(Math.min(x0, x1), Math.min(y0, y1), Math.abs(x1 - x0), Math.abs(y1 - y0));
      ctx.restore();
    }
  }

  private arrowhead(s: SimNode, t: SimNode) {
    const ctx = this.ctx;
    const head = 6, r = (t.__radius ?? 10) + 1;
    const angle = Math.atan2((t.y ?? 0) - (s.y ?? 0), (t.x ?? 0) - (s.x ?? 0));
    const tx = (t.x ?? 0) - r * Math.cos(angle);
    const ty = (t.y ?? 0) - r * Math.sin(angle);
    ctx.beginPath();
    ctx.moveTo(tx, ty);
    ctx.lineTo(tx - head * Math.cos(angle - Math.PI / 6), ty - head * Math.sin(angle - Math.PI / 6));
    ctx.lineTo(tx - head * Math.cos(angle + Math.PI / 6), ty - head * Math.sin(angle + Math.PI / 6));
    ctx.closePath();
    ctx.fill();
  }

  requestRender() { this.needsRender = true; }
  pauseToggle(): boolean {
    const running = this.sim.alpha() > this.sim.alphaMin();
    if (running) this.sim.stop(); else this.sim.alpha(0.5).restart();
    return !running;
  }
}

// ---------------- React wrapper ----------------
export default function GraphCanvas(props: {
  engineRef: (e: GraphEngine | null) => void;
  onSelect: (id: string | null) => void;
  onExpand: (id: string) => void;
  onMultiSelectChange: (ids: Set<string>) => void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const cbRef = useRef(props);
  cbRef.current = props;

  useEffect(() => {
    const canvas = canvasRef.current!;
    const wrap = wrapRef.current!;
    const engine = new GraphEngine(canvas, {
      onSelect: id => cbRef.current.onSelect(id),
      onExpand: id => cbRef.current.onExpand(id),
      onMultiSelectChange: ids => cbRef.current.onMultiSelectChange(new Set(ids)),
    });
    cbRef.current.engineRef(engine);

    const ro = new ResizeObserver(() => {
      engine.resize(wrap.clientWidth, wrap.clientHeight);
    });
    ro.observe(wrap);
    engine.resize(wrap.clientWidth, wrap.clientHeight);

    const mo = new MutationObserver(() => engine.readColors());
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    return () => {
      cbRef.current.engineRef(null);
      ro.disconnect();
      mo.disconnect();
      engine.destroy();
    };
  }, []);

  return (
    <div ref={wrapRef} className="viz-canvas-wrap">
      <canvas ref={canvasRef} />
    </div>
  );
}
