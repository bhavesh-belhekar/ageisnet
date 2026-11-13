/**
 * Hook for fetching and managing container communication graph data (GET /api/graph).
 *
 * Provides:
 * - Real-time graph data with auto-refresh (default 30s)
 * - Loading, empty, and error state tracking
 * - Manual refresh capability
 * - Safe lifecycle management (no stale state updates on unmount)
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { type GraphData, getGraph } from "../api/client";

const DEFAULT_REFRESH_INTERVAL_MS = 30000;

export interface UseGraphDataReturn {
  graphData: GraphData;
  isLoading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

export function useGraphData(refreshIntervalMs = DEFAULT_REFRESH_INTERVAL_MS): UseGraphDataReturn {
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const mountedRef = useRef<boolean>(true);
  const isFetchingRef = useRef<boolean>(false);

  const fetchGraph = useCallback(async (isInitial = false) => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;

    if (isInitial) {
      setIsLoading(true);
    }

    try {
      const data = await getGraph();
      if (!mountedRef.current) return;

      const safeNodes = Array.isArray(data?.nodes) ? data.nodes : [];
      const safeLinks = Array.isArray(data?.links) ? data.links : [];

      setGraphData({ nodes: safeNodes, links: safeLinks });
      setError(null);
    } catch (err: unknown) {
      if (!mountedRef.current) return;
      const message = err instanceof Error ? err.message : String(err);
      setError(message || "Failed to load communication graph");
    } finally {
      isFetchingRef.current = false;
      if (mountedRef.current) {
        setIsLoading(false);
      }
    }
  }, []);

  const refresh = useCallback(() => fetchGraph(false), [fetchGraph]);

  useEffect(() => {
    mountedRef.current = true;
    void fetchGraph(true);

    if (refreshIntervalMs > 0) {
      const timer = setInterval(() => {
        void fetchGraph(false);
      }, refreshIntervalMs);

      return () => {
        mountedRef.current = false;
        clearInterval(timer);
      };
    }

    return () => {
      mountedRef.current = false;
    };
  }, [fetchGraph, refreshIntervalMs]);

  return {
    graphData,
    isLoading,
    error,
    refresh,
  };
}

