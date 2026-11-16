"""Container communication graph API (FR-2.2 / ARCHITECTURE.md §3.6).

Returns the live container communication graph built from the Neo4j graph
client (with automatic in-memory cache fallback if Neo4j is unavailable).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter

from app.db.neo4j_client import get_graph_client

logger = logging.getLogger("api.graph")

router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("")
async def get_graph() -> dict:
    """Return the live container communication graph.

    Builds a ``{ "nodes": [...], "links": [...] }`` structure from the Neo4j
    graph (or in-memory fallback when Neo4j is unavailable).  Each node
    represents a container; each link is a directed edge with port, protocol,
    and anomaly status.

    Returns an empty graph (``nodes=[], links=[]``) when no data is available
    or the graph client raises an unexpected exception.
    """
    try:
        client = get_graph_client()
        edges = await client.get_all_edges()
    except Exception:
        logger.warning("graph API: failed to read edges — returning empty graph")
        edges = {}

    node_ids: set[str] = set()
    links: list[dict] = []
    for (src, dst, port), meta in edges.items():
        node_ids.add(src)
        node_ids.add(dst)
        links.append(
            {
                "source": src,
                "target": dst,
                "port": port,
                "protocol": meta.get("protocol", "tcp"),
                "is_anomalous": meta.get("is_anomalous", False),
                "first_seen": meta.get("first_seen"),
                "last_seen": meta.get("last_seen"),
            }
        )

    nodes = [{"id": cid, "label": cid} for cid in sorted(node_ids)]
    return {"nodes": nodes, "links": links}
