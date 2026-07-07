"""
Ruleset comparison.

Compares two rule collections — e.g. custom vs built-in, product vs product,
or manager vs manager — and reports added, removed and changed rules with
per-field change details (level, description, groups, conditions).
"""

import hashlib
import json
from typing import Any, Optional

from networkx import MultiDiGraph

COMPARED_FIELDS = ("level", "description", "groups", "mitre")


def _conditions_hash(conditions: Optional[list[dict[str, Any]]]) -> str:
    if not conditions:
        return ""
    canon = json.dumps(conditions, sort_keys=True)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]


def _rule_summary(G: MultiDiGraph, n: str) -> dict[str, Any]:
    attrs = G.nodes[n]
    return {
        "id": n,
        "level": attrs.get("level"),
        "description": attrs.get("description"),
        "file": attrs.get("file"),
        "product": attrs.get("product"),
        "groups": attrs.get("groups", []),
    }


def diff_rule_sets(G: MultiDiGraph, left_ids: set[str], right_ids: set[str],
                   left_label: str = "left", right_label: str = "right") -> dict[str, Any]:
    """
    Diff two sets of rule ids within a single graph (product vs product,
    custom files vs built-in files, etc.).
    """
    left_ids = {n for n in left_ids if n != "0"}
    right_ids = {n for n in right_ids if n != "0"}

    added = sorted(right_ids - left_ids, key=_id_key)
    removed = sorted(left_ids - right_ids, key=_id_key)
    common = left_ids & right_ids

    # Same rule id present on both sides can only differ if the two sides
    # loaded it from different files (e.g. overwrite scenario) — with a single
    # shared graph the attributes are identical, so "changed" only applies to
    # two-graph comparisons. Kept for symmetry.
    return {
        "left": left_label,
        "right": right_label,
        "added": [_rule_summary(G, n) for n in added],
        "removed": [_rule_summary(G, n) for n in removed],
        "changed": [],
        "unchanged_count": len(common),
    }


def diff_graphs(G_left: MultiDiGraph, G_right: MultiDiGraph,
                left_label: str = "left", right_label: str = "right",
                left_ids: Optional[set[str]] = None,
                right_ids: Optional[set[str]] = None) -> dict[str, Any]:
    """
    Diff two independently built graphs (e.g. two managers, or local dir vs
    manager). Reports added/removed rule ids and field-level changes for
    rules present in both.
    """
    lids = {n for n in (left_ids or set(G_left.nodes)) if n != "0"}
    rids = {n for n in (right_ids or set(G_right.nodes)) if n != "0"}

    added = sorted(rids - lids, key=_id_key)
    removed = sorted(lids - rids, key=_id_key)
    common = lids & rids

    changed: list[dict[str, Any]] = []
    for n in sorted(common, key=_id_key):
        la, ra = G_left.nodes[n], G_right.nodes[n]
        field_changes: list[dict[str, Any]] = []
        for field in COMPARED_FIELDS:
            lv, rv = la.get(field), ra.get(field)
            if lv != rv:
                field_changes.append({"field": field, "left": lv, "right": rv})
        lh = _conditions_hash(la.get("conditions"))
        rh = _conditions_hash(ra.get("conditions"))
        if lh != rh:
            field_changes.append({
                "field": "conditions",
                "left": la.get("conditions", []),
                "right": ra.get("conditions", []),
            })
        if field_changes:
            changed.append({
                "id": n,
                "description": ra.get("description") or la.get("description"),
                "file_left": la.get("file"),
                "file_right": ra.get("file"),
                "changes": field_changes,
            })

    return {
        "left": left_label,
        "right": right_label,
        "added": [_rule_summary(G_right, n) for n in added],
        "removed": [_rule_summary(G_left, n) for n in removed],
        "changed": changed,
        "unchanged_count": len(common) - len(changed),
        "summary": {
            "left_total": len(lids),
            "right_total": len(rids),
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
    }


def _id_key(n: str) -> tuple[int, str]:
    return (int(n), "") if n.isdigit() else (10**12, n)
