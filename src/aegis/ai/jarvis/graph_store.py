"""SQLite persistence adapter for the canonical ``agentic_os`` security graph.

``aegis.graph`` remains the asset/observation normalization graph.  This module persists
Jarvis *reasoning* relationships (repository -> finding -> weakness/evidence/mission) and
implements the same basic node/connect/neighbors contract as
:class:`aegis.ai.agentic_os.SecurityKnowledgeGraph`.

The adapter may share the exact ``jarvis_state.sqlite3`` file used by
:class:`JarvisStateStore`; table names are namespaced and SQLite/WAL safely coordinates the
short transactions.  This avoids another JSON store or a third graph model.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from ..agentic_os import GraphEdge, SecurityKnowledgeGraph


class SqliteSecurityKnowledgeGraph:
    """Durable security-reasoning graph with the ``agentic_os`` graph interface."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS security_graph_nodes (
                node_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS security_graph_edges (
                source TEXT NOT NULL,
                relation TEXT NOT NULL,
                target TEXT NOT NULL,
                provenance TEXT NOT NULL,
                confidence REAL NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (source, relation, target, provenance)
            );

            CREATE INDEX IF NOT EXISTS idx_security_graph_edges_source
                ON security_graph_edges(source, relation);
            CREATE INDEX IF NOT EXISTS idx_security_graph_edges_target
                ON security_graph_edges(target, relation);
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SqliteSecurityKnowledgeGraph:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def upsert_node(self, node_id: str, kind: str, **attributes: Any) -> None:
        if not node_id.strip() or not kind.strip():
            raise ValueError("graph node id and kind are required")
        existing = self.node(node_id)
        merged = dict(existing.get("attributes", {})) if existing else {}
        merged.update(attributes)
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO security_graph_nodes(node_id, kind, attributes_json)
                VALUES (?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    kind = excluded.kind,
                    attributes_json = excluded.attributes_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (node_id, kind, json.dumps(merged, sort_keys=True, default=str)),
            )

    def node(self, node_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT node_id, kind, attributes_json FROM security_graph_nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            attributes = json.loads(row["attributes_json"] or "{}")
        except json.JSONDecodeError:
            attributes = {}
        return {"node_id": row["node_id"], "kind": row["kind"], "attributes": attributes}

    def connect(self, edge: GraphEdge) -> None:
        if not 0.0 <= edge.confidence <= 1.0:
            raise ValueError("edge confidence must be in [0, 1]")
        if self.node(edge.source) is None or self.node(edge.target) is None:
            raise ValueError("graph edges require existing source and target nodes")
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO security_graph_edges(source, relation, target, provenance, confidence)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source, relation, target, provenance) DO UPDATE SET
                    confidence = MAX(security_graph_edges.confidence, excluded.confidence),
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    edge.source,
                    edge.relation,
                    edge.target,
                    edge.provenance,
                    float(edge.confidence),
                ),
            )

    def neighbors(self, node_id: str, relation: str | None = None) -> tuple[str, ...]:
        if relation is None:
            rows = self._conn.execute(
                "SELECT DISTINCT target FROM security_graph_edges WHERE source = ? ORDER BY target",
                (node_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT DISTINCT target FROM security_graph_edges
                WHERE source = ? AND relation = ? ORDER BY target
                """,
                (node_id, relation),
            ).fetchall()
        return tuple(str(row["target"]) for row in rows)

    def edges(self, *, source: str | None = None, target: str | None = None) -> tuple[GraphEdge, ...]:
        clauses: list[str] = []
        values: list[str] = []
        if source is not None:
            clauses.append("source = ?")
            values.append(source)
        if target is not None:
            clauses.append("target = ?")
            values.append(target)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self._conn.execute(
            "SELECT source, relation, target, provenance, confidence FROM security_graph_edges"
            + where
            + " ORDER BY source, relation, target",
            tuple(values),
        ).fetchall()
        return tuple(
            GraphEdge(
                source=str(row["source"]),
                relation=str(row["relation"]),
                target=str(row["target"]),
                provenance=str(row["provenance"]),
                confidence=float(row["confidence"]),
            )
            for row in rows
        )

    def persist(self, graph: SecurityKnowledgeGraph) -> None:
        """Persist an in-memory canonical graph without changing its semantics."""
        for node_id, data in graph.nodes.items():
            attributes = dict(data)
            kind = str(attributes.pop("kind", "unknown"))
            self.upsert_node(node_id, kind, **attributes)
        for edge in graph.edges:
            self.connect(edge)

    def load(self) -> SecurityKnowledgeGraph:
        """Rehydrate the canonical in-memory graph for agents that expect it."""
        graph = SecurityKnowledgeGraph()
        rows = self._conn.execute(
            "SELECT node_id, kind, attributes_json FROM security_graph_nodes ORDER BY node_id"
        ).fetchall()
        for row in rows:
            try:
                attributes = json.loads(row["attributes_json"] or "{}")
            except json.JSONDecodeError:
                attributes = {}
            graph.upsert_node(str(row["node_id"]), str(row["kind"]), **attributes)
        for edge in self.edges():
            graph.connect(edge)
        return graph

    def upsert_edges(self, edges: Iterable[GraphEdge]) -> None:
        for edge in edges:
            self.connect(edge)
