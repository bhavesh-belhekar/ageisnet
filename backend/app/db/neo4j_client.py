"""Neo4j client for the live container communication graph.

Provides async CRUD for container nodes and CONNECTS_TO edges, plus a
local in-memory cache that acts as a fallback when Neo4j is unavailable
(e.g. during offline testing or if the Neo4j container is down).

Edge key convention: ``(src_container_id, dst_container_id, port)`` —
this matches the PRD FR-2.2 definition of "new edge" (container pair or
port never seen before).

Usage::

    from app.db.neo4j_client import get_graph_client

    client = get_graph_client()
    await client.connect()
    await client.merge_edge("aaa", "bbb", port=80, protocol="tcp", ts=now)
    edges = await client.get_baseline_edges(hours=24)
    await client.close()
"""

from __future__ import annotations

import logging
import time
from typing import Any

from app.config.settings import get_settings

logger = logging.getLogger("neo4j_client")

# Type alias for the edge tuple key used throughout the graph model.
EdgeKey = tuple[str, str, int]  # (src_container_id, dst_container_id, port)


class Neo4jGraphClient:
    """Async Neo4j driver with an in-memory edge cache.

    The cache is always kept in sync: every ``merge_edge`` call updates
    both Neo4j (if connected) and the local dict.  Reads fall back to
    the cache if Neo4j is unreachable.
    """

    def __init__(self) -> None:
        self._driver: Any = None
        self._connected: bool = False
        # Local cache: edge_key → {"first_seen": float, "last_seen": float,
        #                           "protocol": str, "is_anomalous": bool}
        self._edge_cache: dict[EdgeKey, dict[str, Any]] = {}

    async def connect(self) -> None:
        """Open the Neo4j driver.  Falls back gracefully on failure."""
        try:
            from neo4j import AsyncGraphDatabase

            settings = get_settings()
            uri = f"bolt://{settings.neo4j_host}:{settings.neo4j_port}"
            self._driver = AsyncGraphDatabase.driver(
                uri, auth=(settings.neo4j_user, settings.neo4j_password)
            )
            # Verify connectivity
            async with self._driver.session() as session:
                await session.run("RETURN 1")
            self._connected = True
            logger.info("Neo4j connected at %s", uri)
        except Exception:
            self._connected = False
            logger.warning(
                "Neo4j unavailable — graph model will use in-memory cache only"
            )

    async def close(self) -> None:
        """Close the Neo4j driver if open."""
        if self._driver:
            await self._driver.close()
            self._driver = None
            self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    # ------------------------------------------------------------------
    # Edge CRUD
    # ------------------------------------------------------------------

    async def merge_edge(
        self,
        src_container: str,
        dst_container: str,
        port: int,
        protocol: str = "tcp",
        timestamp: float | None = None,
    ) -> None:
        """MERGE a CONNECTS_TO edge, updating first_seen / last_seen.

        Updates both Neo4j (if connected) and the local cache.
        """
        ts = timestamp or time.time()
        key: EdgeKey = (src_container, dst_container, port)

        # Local cache update
        existing = self._edge_cache.get(key)
        if existing is None:
            self._edge_cache[key] = {
                "first_seen": ts,
                "last_seen": ts,
                "protocol": protocol,
                "is_anomalous": False,
            }
        else:
            existing["last_seen"] = ts
            existing["protocol"] = protocol

        # Neo4j update
        if self._connected:
            try:
                async with self._driver.session() as session:
                    await session.run(
                        """
                        MERGE (src:Container {id: $src})
                        MERGE (dst:Container {id: $dst})
                        MERGE (src)-[e:CONNECTS_TO {port: $port}]->(dst)
                        ON CREATE SET e.first_seen = $ts,
                                      e.last_seen = $ts,
                                      e.protocol = $protocol,
                                      e.is_anomalous = false
                        ON MATCH SET e.last_seen = $ts,
                                      e.protocol = $protocol
                        """,
                        src=src_container,
                        dst=dst_container,
                        port=port,
                        ts=ts,
                        protocol=protocol,
                    )
            except Exception:
                logger.warning(
                    "Neo4j merge_edge failed for %s→%s:%d — cache only",
                    src_container,
                    dst_container,
                    port,
                )

    async def mark_edge_anomalous(
        self,
        src_container: str,
        dst_container: str,
        port: int,
    ) -> None:
        """Flag an edge as anomalous in Neo4j and the local cache."""
        key: EdgeKey = (src_container, dst_container, port)
        if key in self._edge_cache:
            self._edge_cache[key]["is_anomalous"] = True

        if self._connected:
            try:
                async with self._driver.session() as session:
                    await session.run(
                        """
                        MATCH (src:Container {id: $src})-[e:CONNECTS_TO {port: $port}]->(dst:Container {id: $dst})
                        SET e.is_anomalous = true
                        """,
                        src=src_container,
                        dst=dst_container,
                        port=port,
                    )
            except Exception:
                logger.warning("Neo4j mark_anomalous failed for %s→%s:%d", src_container, dst_container, port)

    async def get_baseline_edges(self, hours: float = 24.0) -> set[EdgeKey]:
        """Return the set of edge keys seen in the last *hours* hours.

        Reads from Neo4j if connected, otherwise from the local cache.
        """
        if self._connected:
            return await self._get_baseline_from_neo4j(hours)
        return self._get_baseline_from_cache(hours)

    async def _get_baseline_from_neo4j(self, hours: float) -> set[EdgeKey]:
        cutoff = time.time() - (hours * 3600)
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """
                    MATCH (src:Container)-[e:CONNECTS_TO]->(dst:Container)
                    WHERE e.last_seen >= $cutoff
                    RETURN src.id AS src, dst.id AS dst, e.port AS port
                    """,
                    cutoff=cutoff,
                )
                keys: set[EdgeKey] = set()
                async for record in result:
                    keys.add((record["src"], record["dst"], record["port"]))
                return keys
        except Exception:
            logger.warning("Neo4j get_baseline_edges failed — falling back to cache")
            return self._get_baseline_from_cache(hours)

    def _get_baseline_from_cache(self, hours: float) -> set[EdgeKey]:
        cutoff = time.time() - (hours * 3600)
        return {
            key
            for key, meta in self._edge_cache.items()
            if meta["last_seen"] >= cutoff
        }

    async def get_all_edges(self) -> dict[EdgeKey, dict[str, Any]]:
        """Return the full edge cache (for debugging / inspection)."""
        if self._connected:
            return await self._get_all_from_neo4j()
        return dict(self._edge_cache)

    async def _get_all_from_neo4j(self) -> dict[EdgeKey, dict[str, Any]]:
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """
                    MATCH (src:Container)-[e:CONNECTS_TO]->(dst:Container)
                    RETURN src.id AS src, dst.id AS dst, e.port AS port,
                           e.first_seen AS first_seen, e.last_seen AS last_seen,
                           e.protocol AS protocol, e.is_anomalous AS is_anomalous
                    """
                )
                edges: dict[EdgeKey, dict[str, Any]] = {}
                async for record in result:
                    key = (record["src"], record["dst"], record["port"])
                    edges[key] = {
                        "first_seen": record["first_seen"],
                        "last_seen": record["last_seen"],
                        "protocol": record["protocol"],
                        "is_anomalous": record["is_anomalous"],
                    }
                return edges
        except Exception:
            return dict(self._edge_cache)

    def load_from_events(self, events: list[dict]) -> int:
        """Bootstrap the local cache from a list of event dicts.

        Useful for tests or cold-starting the baseline from historical data.
        Returns the number of unique edges loaded.
        """
        for ev in events:
            if ev.get("direction") != "internal":
                continue
            src = ev.get("container_id", "")
            dst_container = ev.get("dst_container_id", ev.get("src_container_id", ""))
            port = ev.get("dst_port", 0)
            ts = ev.get("timestamp", time.time())
            if isinstance(ts, str):
                from datetime import datetime
                try:
                    ts = datetime.fromisoformat(ts).timestamp()
                except ValueError:
                    ts = time.time()
            if src and dst_container and port:
                self._edge_cache[(src, dst_container, port)] = {
                    "first_seen": ts,
                    "last_seen": ts,
                    "protocol": ev.get("protocol", "tcp"),
                    "is_anomalous": False,
                }
        return len(self._edge_cache)


# ------------------------------------------------------------------
# Module-level singleton
# ------------------------------------------------------------------

_client: Neo4jGraphClient | None = None


def get_graph_client() -> Neo4jGraphClient:
    """Return (and lazily create) the module-level graph client."""
    global _client
    if _client is None:
        _client = Neo4jGraphClient()
    return _client
