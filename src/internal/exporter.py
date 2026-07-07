"""
Export the rule graph (full or product-scoped) as JSON, CSV or GraphML.

GraphML attribute values must be scalars, so list/dict node attributes are
serialized to JSON strings. The heavyweight 'raw' XML snippets are dropped
from exports to keep files lean and importable in tools like Gephi/yEd.
"""

import csv
import io
import json
from typing import Any, Optional

import networkx as nx
from networkx import MultiDiGraph

# node attributes excluded from exports (internal/bulky)
EXCLUDED_ATTRS = {"raw", "raw_overwrite", "children_ids", "expandable"}

CSV_RULE_COLUMNS = [
    "id", "level", "description", "groups", "file", "product", "source",
    "mitre", "frequency", "timeframe", "parents", "children",
]


def _subgraph(G: MultiDiGraph, node_ids: Optional[set[str]]) -> MultiDiGraph:
    if node_ids is None:
        return G
    return G.subgraph(node_ids)


def _clean_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in attrs.items()
            if k not in EXCLUDED_ATTRS and v is not None}


def to_json(G: MultiDiGraph, node_ids: Optional[set[str]] = None) -> str:
    sub = _subgraph(G, node_ids)
    nodes = [{"id": n, **_clean_attrs(sub.nodes[n])} for n in sub.nodes]
    edges = [{"source": u, "target": v,
              "relation_type": d.get("relation_type", "unknown")}
             for u, v, d in sub.edges(data=True)]
    return json.dumps({"nodes": nodes, "edges": edges}, indent=2)


def to_csv(G: MultiDiGraph, node_ids: Optional[set[str]] = None) -> str:
    """Rules table; multi-valued fields are joined with '|'."""
    sub = _subgraph(G, node_ids)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_RULE_COLUMNS, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for n in sub.nodes:
        if n == "0":
            continue
        attrs = sub.nodes[n]
        writer.writerow({
            "id": n,
            "level": attrs.get("level", ""),
            "description": attrs.get("description", ""),
            "groups": "|".join(attrs.get("groups", [])),
            "file": attrs.get("file", ""),
            "product": attrs.get("product", "") or "",
            "source": attrs.get("source", "") or "",
            "mitre": "|".join(attrs.get("mitre", [])),
            "frequency": attrs.get("frequency", ""),
            "timeframe": attrs.get("timeframe", ""),
            "parents": "|".join(p for p in sub.predecessors(n) if p != "0"),
            "children": "|".join(sub.successors(n)),
        })
    return buf.getvalue()


def to_graphml(G: MultiDiGraph, node_ids: Optional[set[str]] = None) -> str:
    sub = _subgraph(G, node_ids)
    # GraphML requires scalar attribute values: copy + stringify
    out = nx.MultiDiGraph()
    for n in sub.nodes:
        attrs = _clean_attrs(sub.nodes[n])
        scalar_attrs: dict[str, Any] = {}
        for k, v in attrs.items():
            if isinstance(v, (list, dict)):
                scalar_attrs[k] = json.dumps(v)
            else:
                scalar_attrs[k] = v
        out.add_node(n, **scalar_attrs)
    for u, v, d in sub.edges(data=True):
        out.add_edge(u, v, relation_type=d.get("relation_type", "unknown"))
    buf = io.BytesIO()
    nx.write_graphml(out, buf)
    return buf.getvalue().decode("utf-8")


EXPORTERS = {
    "json": (to_json, "application/json", "json"),
    "csv": (to_csv, "text/csv", "csv"),
    "graphml": (to_graphml, "application/xml", "graphml"),
}
