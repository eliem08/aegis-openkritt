from __future__ import annotations

from aegis.ai.agentic_os import GraphEdge, SecurityKnowledgeGraph
from aegis.ai.jarvis.graph_store import SqliteSecurityKnowledgeGraph


def test_security_graph_roundtrip(tmp_path):
    db = tmp_path / "jarvis.sqlite3"
    memory = SecurityKnowledgeGraph()
    memory.upsert_node("repository:acme/repo", "repository", repository="acme/repo")
    memory.upsert_node("finding:1", "finding", stage="source_supported")
    memory.connect(
        GraphEdge(
            "repository:acme/repo",
            "HAS_FINDING",
            "finding:1",
            "test",
            0.9,
        )
    )

    with SqliteSecurityKnowledgeGraph(db) as store:
        store.persist(memory)
        assert store.neighbors("repository:acme/repo", "HAS_FINDING") == ("finding:1",)
        loaded = store.load()

    assert loaded.neighbors("repository:acme/repo", "HAS_FINDING") == ("finding:1",)
    assert loaded.nodes["finding:1"]["stage"] == "source_supported"
