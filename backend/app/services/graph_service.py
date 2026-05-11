"""Lightweight threat relationship graph from stored report evidence."""

from __future__ import annotations


def _add_node(nodes: dict, node_id: str, node_type: str, label: str, metadata: dict | None = None):
    nodes[node_id] = {
        "id": node_id,
        "type": node_type,
        "label": label,
        "metadata": metadata or {},
    }


def _add_edge(edges: list, source: str, target: str, edge_type: str, weight: float = 1.0, evidence: list | None = None):
    edges.append({
        "source": source,
        "target": target,
        "type": edge_type,
        "weight": weight,
        "evidence": evidence or [],
    })


def _behavior_profile(report) -> dict:
    static_data = report.static_data or {}
    return static_data.get("behavior_profile") or {}


def _ioc_values(report) -> list[tuple[str, str]]:
    values = []
    for category, items in (report.iocs or {}).items():
        for item in items or []:
            values.append((category, str(item)))
    return values


def build_relationship_graph(entity_type: str, entity_id: str, depth: int, reports: list) -> dict:
    nodes = {}
    edges = []
    entity_key = entity_id.lower()

    if entity_type == "file":
        report = reports[0] if reports else None
        if report:
            file_id = f"file:{report.file_hash_sha256}"
            _add_node(nodes, file_id, "file", report.file_hash_sha256[:12], {
                "verdict": report.verdict,
                "severity_score": report.severity_score,
            })

            for capability in _behavior_profile(report).get("capabilities") or []:
                behavior_id = f"behavior:{capability.get('name')}"
                _add_node(nodes, behavior_id, "behavior", capability.get("label") or capability.get("name"), {
                    "confidence": capability.get("confidence"),
                    "mitre": capability.get("mitre") or [],
                })
                _add_edge(
                    edges,
                    file_id,
                    behavior_id,
                    "exhibits_behavior",
                    capability.get("confidence") or 1.0,
                    capability.get("evidence") or [],
                )

            for category, value in _ioc_values(report):
                ioc_id = f"ioc:{value.lower()}"
                _add_node(nodes, ioc_id, "ioc", value, {"category": category})
                _add_edge(edges, file_id, ioc_id, "contains_ioc", 1.0, [value])

            cross_reference = (report.static_data or {}).get("cross_reference") or {}
            for match in cross_reference.get("top_matches") or []:
                match_hash = match.get("file_hash_sha256")
                if not match_hash:
                    continue
                match_id = f"file:{match_hash}"
                _add_node(nodes, match_id, "file", match.get("file_name") or match_hash[:12], {
                    "verdict": match.get("verdict"),
                    "severity_score": match.get("severity_score"),
                    "similarity_score": match.get("similarity_score"),
                })
                _add_edge(
                    edges,
                    file_id,
                    match_id,
                    "similar_to",
                    (match.get("similarity_score") or 0) / 100,
                    match.get("matched_behaviors") or [],
                )

    if entity_type == "behavior":
        behavior_id = f"behavior:{entity_key}"
        _add_node(nodes, behavior_id, "behavior", entity_id)
        for report in reports:
            profile = _behavior_profile(report)
            capability_names = {name.lower() for name in profile.get("capability_names") or []}
            if entity_key not in capability_names:
                continue
            file_id = f"file:{report.file_hash_sha256}"
            _add_node(nodes, file_id, "file", report.file_hash_sha256[:12], {
                "verdict": report.verdict,
                "severity_score": report.severity_score,
            })
            _add_edge(edges, file_id, behavior_id, "exhibits_behavior")

    if entity_type == "ioc":
        ioc_id = f"ioc:{entity_key}"
        _add_node(nodes, ioc_id, "ioc", entity_id)
        for report in reports:
            matching_iocs = [value for _, value in _ioc_values(report) if value.lower() == entity_key]
            if not matching_iocs:
                continue
            file_id = f"file:{report.file_hash_sha256}"
            _add_node(nodes, file_id, "file", report.file_hash_sha256[:12], {
                "verdict": report.verdict,
                "severity_score": report.severity_score,
            })
            _add_edge(edges, file_id, ioc_id, "contains_ioc", 1.0, matching_iocs)

    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "depth": depth,
        "method": "report-json:v1",
        "nodes": list(nodes.values()),
        "edges": edges,
    }
