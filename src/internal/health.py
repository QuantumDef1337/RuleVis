"""
Ruleset health and dependency intelligence.

Everything here is derived from the graph itself — no fabricated numbers:

  * Broken dependencies: a rule's <if_sid>/<if_group> can reference an ID that
    is never actually defined by any loaded rule. networkx.add_edge()
    auto-creates the missing node as a bare id with no attributes, so any
    node lacking the 'conditions' key (always present on real rules) is a
    phantom — a reference to a rule that doesn't exist in this workspace.
  * Duplicate rule IDs: captured by GraphGenerator while parsing and stored
    on G.graph['duplicate_rule_ids'].
  * Non-alerting parents: level="0" rules that have children — Wazuh has no
    "disabled" flag, so this is the closest real proxy (grouping/decoding
    rules that never raise an alert themselves).
  * Compliance tags: inferred from the standard Wazuh group-name prefixes
    used across the built-in ruleset (pci_dss, gdpr, hipaa, nist_800_53,
    gpg13, tsc).
  * Dependency chain: longest path length via dag_longest_path (best-effort;
    falls back to empty if the ruleset contains cycles).
"""

from collections import deque
from typing import Any

import networkx as nx
from networkx import MultiDiGraph

COMPLIANCE_PREFIXES: dict[str, str] = {
    "pci_dss": "PCI DSS",
    "gdpr": "GDPR",
    "hipaa": "HIPAA",
    "nist_800_53": "NIST 800-53",
    "gpg13": "GPG13",
    "tsc": "TSC",
}


def _compliance_tags(groups: list[str]) -> set[str]:
    tags: set[str] = set()
    for g in groups or []:
        for prefix, label in COMPLIANCE_PREFIXES.items():
            if g.startswith(prefix):
                tags.add(label)
    return tags


def _is_real_rule(G: MultiDiGraph, n: str) -> bool:
    return "conditions" in G.nodes[n]


def compute_health(G: MultiDiGraph) -> dict[str, Any]:
    real_nodes = [n for n in G.nodes if n != "0"]
    real_count = len(real_nodes)

    broken: list[dict[str, Any]] = []
    for n in real_nodes:
        if not _is_real_rule(G, n):
            broken.append({"id": n, "referenced_by": sorted(G.successors(n))})

    duplicates = G.graph.get("duplicate_rule_ids", [])

    non_alerting_parents = [
        n for n in real_nodes
        if _is_real_rule(G, n) and G.out_degree(n) > 0
        and str(G.nodes[n].get("level", "")) == "0"
    ]

    without_mitre = [
        n for n in real_nodes if _is_real_rule(G, n) and not G.nodes[n].get("mitre")]

    mitre_ids: set[str] = set()
    for n in real_nodes:
        for t in G.nodes[n].get("mitre", []) or []:
            mitre_ids.add(t)

    without_compliance: list[str] = []
    compliance_counts: dict[str, int] = {}
    for n in real_nodes:
        if not _is_real_rule(G, n):
            continue
        tags = _compliance_tags(G.nodes[n].get("groups", []))
        if not tags:
            without_compliance.append(n)
        for t in tags:
            compliance_counts[t] = compliance_counts.get(t, 0) + 1

    orphans = [
        n for n in real_nodes
        if _is_real_rule(G, n) and G.out_degree(n) == 0
        and set(G.predecessors(n)) <= {"0"}
    ]

    # Shortest-hop depth from top-level rules (no real parent) down through
    # children. Wazuh rulesets can legitimately contain self-loops (a rule
    # whose own <group> overlaps its own <if_group>) and multi-node cycles
    # (see Analyzer's self_loops/cycles stats) — a relax-until-stable BFS
    # would spin forever on those, so each node is visited at most once.
    top_level = [n for n in real_nodes if set(G.predecessors(n)) <= {"0"}]
    depth: dict[str, int] = {n: 0 for n in top_level}
    queue: deque[str] = deque(top_level)
    while queue:
        cur = queue.popleft()
        for child in G.successors(cur):
            if child == "0" or child in depth:
                continue
            depth[child] = depth[cur] + 1
            queue.append(child)
    max_depth = max(depth.values()) if depth else 0
    avg_depth = round(sum(depth.values()) / len(depth), 2) if depth else 0.0

    # Longest dependency chain: self-loops are stripped (they never
    # contribute to a "chain") before asking for the DAG longest path; any
    # remaining multi-node cycle makes the ruleset not a DAG, in which case
    # we fall back to no chain rather than raise.
    longest_chain: list[str] = []
    try:
        dag = nx.DiGraph()
        dag.add_nodes_from(real_nodes)
        for u, v in G.subgraph(real_nodes).edges():
            if u != v:
                dag.add_edge(u, v)
        longest_chain = nx.dag_longest_path(dag)
    except Exception:
        longest_chain = []

    def pct(count: int) -> float:
        return round(count / real_count * 100, 1) if real_count else 0.0

    return {
        "broken_dependencies": {"count": len(broken), "items": broken[:25]},
        "duplicate_rule_ids": {"count": len(duplicates), "items": duplicates[:25]},
        "non_alerting_parents": {"count": len(non_alerting_parents), "items": non_alerting_parents[:25]},
        "rules_without_mitre": {"count": len(without_mitre), "pct": pct(len(without_mitre))},
        "rules_without_compliance": {"count": len(without_compliance), "pct": pct(len(without_compliance))},
        "orphan_rules": {"count": len(orphans), "items": orphans[:25]},
        "mitre_technique_count": len(mitre_ids),
        "mitre_covered_rules": real_count - len(without_mitre),
        "compliance_frameworks": compliance_counts,
        "dependency": {
            "max_depth": max_depth,
            "avg_depth": avg_depth,
            "longest_chain": longest_chain,
            "longest_chain_length": max(0, len(longest_chain) - 1),
        },
    }
