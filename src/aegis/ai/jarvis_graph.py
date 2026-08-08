"""Persistent adapter for ``agentic_os.SecurityKnowledgeGraph``.

``aegis.graph`` remains the asset/observation normalization graph. This module persists the
*different* security-reasoning graph (program -> repository -> finding -> evidence/weakness)
through the already-existing Jarvis SQLite store. No second graph model or database is created.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from .agentic_os import GraphEdge, SecurityKnowledgeGraph
from .jarvis.state_store import JarvisStateStore, MissionSnapshot
from .jarvis_persistence import state_db_path

_PREFIX = "security-graph::"


def _graph_id(repository: str) -> str:
    return _PREFIX + repository.strip().lower().replace("/", "__")


def graph_from_report(report: dict) -> SecurityKnowledgeGraph:
    graph = SecurityKnowledgeGraph()
    scan = report.get("scan") or {}
    repository = str(scan.get("repository") or "unknown")
    repo_id = f"repository:{repository.lower()}"
    graph.upsert_node(repo_id, "repository", repository=repository)

    rows = report.get("vulnerabilities") or []
    for row in rows:
        state = row.get("jarvis") or {}
        answer = row.get("json_answer") or {}
        program_id = str(state.get("program_id") or "")
        if program_id:
            pnode = f"program:{program_id.lower()}"
            graph.upsert_node(pnode, "program", program_id=program_id,
                              platform=state.get("source_platform", ""))
            graph.connect(GraphEdge(pnode, "authorizes", repo_id, "authorization-ledger", 1.0))

        weakness = str(answer.get("vulnerability_type") or "unspecified")
        wnode = f"weakness:{weakness.lower()}"
        graph.upsert_node(wnode, "weakness", weakness=weakness)

        finding_id = str(state.get("finding_id") or "")
        if not finding_id:
            continue
        fnode = finding_id
        graph.upsert_node(
            fnode,
            "finding",
            stage=str(state.get("stage") or "candidate"),
            summary=str(answer.get("summary") or "")[:240],
            file_path=str(answer.get("file_path") or ""),
            line=int(answer.get("line") or 0),
            economics=state.get("economics") or {},
            skeptic=(state.get("council") or {}).get("skeptic") or {},
            reproduction=(state.get("council") or {}).get("reproduction") or {},
        )
        graph.connect(GraphEdge(repo_id, "contains_finding", fnode, "live-hunt", 1.0))
        graph.connect(GraphEdge(fnode, "instance_of", wnode, "finding-normalization", 1.0))
        for evidence_id in state.get("evidence") or []:
            enode = str(evidence_id)
            graph.upsert_node(enode, "evidence")
            graph.connect(GraphEdge(fnode, "supported_by", enode, "jarvis-lifecycle", 1.0))
    return graph


def persist_graph(report: dict, *, path: str | Path | None = None) -> None:
    scan = report.get("scan") or {}
    repository = str(scan.get("repository") or "")
    if not repository:
        return
    graph = graph_from_report(report)
    payload = {
        "nodes": graph.nodes,
        "edges": [asdict(edge) for edge in graph.edges],
    }
    db = str(path or state_db_path())
    if db != ":memory:":
        Path(db).parent.mkdir(parents=True, exist_ok=True)
    with JarvisStateStore(db) as store:
        store.save_mission(MissionSnapshot(
            mission_id=_graph_id(repository),
            scope_digest=str(next((
                (r.get("jarvis") or {}).get("scope_digest")
                for r in (report.get("vulnerabilities") or [])
                if (r.get("jarvis") or {}).get("scope_digest")
            ), "source-review")),
            objective=f"persistent security reasoning graph for {repository}",
            state="current",
            payload=payload,
            cursor=len(graph.edges),
        ))


def load_graph(repository: str, *, path: str | Path | None = None) -> SecurityKnowledgeGraph:
    db = str(path or state_db_path())
    graph = SecurityKnowledgeGraph()
    if db != ":memory:" and not Path(db).is_file():
        return graph
    with JarvisStateStore(db) as store:
        snap = store.load_mission(_graph_id(repository))
    if snap is None:
        return graph
    for node_id, attrs in (snap.payload.get("nodes") or {}).items():
        attrs = dict(attrs)
        kind = str(attrs.pop("kind", "unknown"))
        graph.upsert_node(node_id, kind, **attrs)
    for raw in snap.payload.get("edges") or []:
        try:
            graph.connect(GraphEdge(**raw))
        except (TypeError, ValueError):
            continue
    return graph
