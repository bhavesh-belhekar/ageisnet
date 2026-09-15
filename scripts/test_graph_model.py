#!/usr/bin/env python3
"""Standalone test for the graph-diff detector.

Demonstrates detection of lateral-movement traffic by:
1.  Building a baseline of known internal edges (normal traffic).
2.  Injecting synthetic lateral-movement edges (new container pairs / ports).
3.  Showing which edges are flagged as anomalous.

Run from the repo root::

    python scripts/test_graph_model.py

No Neo4j or Redis required — uses the local cache path only.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Ensure the repo root is on the path
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.db.neo4j_client import Neo4jGraphClient, EdgeKey
from app.ml_engine.graph_model.graph_diff import GraphDiffDetector


def make_edge(
    src: str, dst: str, port: int, ts: float | None = None
) -> dict:
    """Create a minimal event dict for graph testing."""
    return {
        "container_id": src,
        "dst_container_id": dst,
        "dst_port": port,
        "direction": "internal",
        "protocol": "tcp",
        "timestamp": ts or time.time(),
    }


def main() -> None:
    now = time.time()
    one_hour_ago = now - 3600

    # ------------------------------------------------------------------
    # 1. Define the "normal" baseline — edges that have been seen before
    # ------------------------------------------------------------------
    normal_edges: list[dict] = [
        # demo-web → demo-api on port 8080 (the standard API call path)
        make_edge("demo-web", "demo-api", 8080, ts=one_hour_ago),
        # demo-api → demo-db on port 5432 (the standard DB query path)
        make_edge("demo-api", "demo-db", 5432, ts=one_hour_ago),
        # demo-web → demo-db on port 5432 (偶尔 direct DB check)
        make_edge("demo-web", "demo-db", 5432, ts=one_hour_ago),
        # demo-api → demo-web on port 80 (callback / webhook)
        make_edge("demo-api", "demo-web", 80, ts=one_hour_ago),
    ]

    print("=" * 68)
    print("GRAPH MODEL — LATERAL MOVEMENT DETECTION TEST")
    print("=" * 68)

    # ------------------------------------------------------------------
    # 2. Build the baseline in the local cache
    # ------------------------------------------------------------------
    client = Neo4jGraphClient()
    loaded = client.load_from_events(normal_edges)
    print(f"\n[1] Baseline loaded: {loaded} known edges")
    for key in sorted(client._edge_cache.keys()):
        src, dst, port = key
        print(f"      {src} → {dst}:{port}")

    # ------------------------------------------------------------------
    # 3. Initialise the detector and load the baseline
    # ------------------------------------------------------------------
    import asyncio

    detector = GraphDiffDetector(baseline_hours=24)
    asyncio.get_event_loop().run_until_complete(
        _load_baseline(detector, client)
    )

    # ------------------------------------------------------------------
    # 4. Inject lateral-movement edges (attacks)
    # ------------------------------------------------------------------
    attack_edges = [
        # ATTACK 1: demo-web reaches demo-db on SSH port 22
        # (never seen before — new port on known pair)
        make_edge("demo-web", "demo-db", 22, ts=now),
        # ATTACK 2: demo-web reaches demo-api on MySQL port 3306
        # (never seen before — new port on known pair)
        make_edge("demo-web", "demo-api", 3306, ts=now),
        # ATTACK 3: demo-db reaches demo-web on port 4444
        # (never seen before — reversed direction + new port)
        make_edge("demo-db", "demo-web", 4444, ts=now),
        # ATTACK 4: compromised container "evil-app" reaches demo-db
        # (never seen before — entirely new container pair)
        make_edge("evil-app", "demo-db", 5432, ts=now),
        # ATTACK 5: evil-app scans demo-api on port 8080
        make_edge("evil-app", "demo-api", 8080, ts=now),
    ]

    known_edges = [
        # Normal traffic — should NOT be flagged
        make_edge("demo-web", "demo-api", 8080, ts=now),
        make_edge("demo-api", "demo-db", 5432, ts=now),
    ]

    print(f"\n[2] Injecting {len(attack_edges)} attack edges + {len(known_edges)} normal edges")

    # ------------------------------------------------------------------
    # 5. Run detection
    # ------------------------------------------------------------------
    print("\n" + "-" * 68)
    print("DETECTION RESULTS")
    print("-" * 68)

    all_edges = attack_edges + known_edges
    detections = 0
    for ev in all_edges:
        src = ev["container_id"]
        dst = ev["dst_container_id"]
        port = ev["dst_port"]
        result = detector.check_edge(src, dst, port)
        is_attack = ev in attack_edges
        status = "ANOMALOUS" if result else "known"
        marker = "  ✓ DETECTED" if result and is_attack else (
            "  ✗ MISSED" if not result and is_attack else ""
        )
        print(f"  {src} → {dst}:{port:5d}  [{status:>9}]{marker}")
        if result:
            detections += 1

    # ------------------------------------------------------------------
    # 6. Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 68)
    attack_detected = sum(
        1 for ev in attack_edges
        if detector.check_edge(ev["container_id"], ev["dst_container_id"], ev["dst_port"]) is not None
    )
    # Re-check known edges (they were already recorded above, so re-check
    # would show None — but let's check the ones that were NOT recorded yet
    # by running check_edge before record_edge).  Since we already ran
    # check_edge on all edges above, the known edges that were NOT flagged
    # returned None.  The attack edges that WERE flagged also got recorded.
    # For a clean count: re-run only on the original known edges.
    known_correct = 0
    for ev in known_edges:
        result = detector.check_edge(ev["container_id"], ev["dst_container_id"], ev["dst_port"])
        if result is None:
            known_correct += 1

    print(f"  Attack edges:   {len(attack_edges)} injected, {detections} detected")
    print(f"  Normal edges:   {len(known_edges)} injected, {known_correct} correctly passed")
    print(f"  Baseline size:  {detector.baseline_size} edges")
    print("=" * 68)

    # Exit code: 0 if all attacks detected and no false positives
    if detections == len(attack_edges) and known_correct == len(known_edges):
        print("\n  RESULT: ALL ATTACKS DETECTED, NO FALSE POSITIVES")
        return 0
    else:
        print("\n  RESULT: DETECTION INCOMPLETE — review above")
        return 1


async def _load_baseline(detector: GraphDiffDetector, client: Neo4jGraphClient) -> None:
    """Load the baseline into the detector from the populated client."""
    baseline = client._get_baseline_from_cache(24)
    detector.load_baseline_from_set(baseline)


if __name__ == "__main__":
    sys.exit(main())
