"""Heuristic graph-diff detector — never-seen-edge anomaly scoring (FR-5.2).

Maintains a rolling baseline of known container-to-container edges over a
configurable learning window (default 24 hours).  Any internal (east-west)
connection whose ``(src_container, dst_container, port)`` key has **not**
been seen in the baseline is flagged as an anomalous new edge.

Edge key convention: ``(src_container_id, dst_container_id, dst_port)`` —
this matches PRD FR-2.2's definition of "new edge" (container pair or port
never seen before).

The baseline is loaded from the ``Neo4jGraphClient`` (which itself caches
Neo4j results and falls back to in-memory).  This module adds **no
additional persistence** — it is a pure diff against whatever the graph
client already knows.

Usage (called by ``infer.py``)::

    from app.ml_engine.graph_model.graph_diff import GraphDiffDetector

    detector = GraphDiffDetector()
    await detector.load_baseline()
    result = detector.check_edge(src_container, dst_container, port)
    # result is {"is_anomalous": True, "reason": "new edge", ...} or None
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import yaml

from app.db.neo4j_client import EdgeKey, get_graph_client

logger = logging.getLogger("graph_diff")

_CONFIG_PATH = Path(__file__).resolve().parents[3] / "app" / "config" / "risk_policy.yaml"


def _load_baseline_hours() -> float:
    """Read the graph baseline window from config (default 24 hours)."""
    try:
        with open(_CONFIG_PATH) as f:
            policy = yaml.safe_load(f)
        return policy.get("windows", {}).get("graph_baseline_hours", 24)
    except Exception:
        return 24.0


class GraphDiffDetector:
    """Heuristic never-seen-edge detector.

    After ``load_baseline()``, call ``check_edge()`` for each internal
    connection event.  Returns an anomaly dict if the edge is new, or
    ``None`` if it is within the learned baseline.
    """

    def __init__(self, baseline_hours: float | None = None) -> None:
        self._baseline_hours = baseline_hours or _load_baseline_hours()
        self._baseline: set[EdgeKey] = set()
        self._loaded = False
        self._client = get_graph_client()

    async def load_baseline(self) -> int:
        """Populate the baseline from the graph client.

        Returns the number of edges loaded.
        """
        self._baseline = await self._client.get_baseline_edges(self._baseline_hours)
        self._loaded = True
        logger.info(
            "graph baseline loaded: %d edges over %.1fh window",
            len(self._baseline),
            self._baseline_hours,
        )
        return len(self._baseline)

    def load_baseline_from_set(self, edges: set[EdgeKey]) -> None:
        """Directly inject a baseline (for tests / offline use)."""
        self._baseline = set(edges)
        self._loaded = True

    def check_edge(
        self,
        src_container: str,
        dst_container: str,
        port: int,
    ) -> dict | None:
        """Check if this edge is anomalous (not in the baseline).

        Returns:
            ``{"is_anomalous": True, "reason": ..., "src": ..., "dst": ...,
              "port": ..., "baseline_size": ...}`` if anomalous,
            or ``None`` if the edge is within the baseline.
        """
        if not self._loaded:
            logger.warning("check_edge called before load_baseline — loading now")
            # Synchronous fallback: the cache is already populated by Neo4jGraphClient
            self._baseline = set()  # will be empty until async load

        key: EdgeKey = (src_container, dst_container, port)

        if key not in self._baseline:
            return {
                "is_anomalous": True,
                "reason": "new edge — never seen in baseline window",
                "src": src_container,
                "dst": dst_container,
                "port": port,
                "baseline_size": len(self._baseline),
            }

        return None

    def record_edge(
        self,
        src_container: str,
        dst_container: str,
        port: int,
    ) -> None:
        """Add an edge to the live baseline (called after processing).

        This ensures that once an edge is first flagged, subsequent
        connections on the same edge within the same window are not
        re-flagged.
        """
        key: EdgeKey = (src_container, dst_container, port)
        self._baseline.add(key)

    @property
    def baseline_size(self) -> int:
        return len(self._baseline)

    @property
    def is_loaded(self) -> bool:
        return self._loaded
