/**
 * NetworkGraph — container topology visualization (FR-8, RULES.md §2.3).
 *
 * Connected to GET /api/graph to display live Neo4j communication topology.
 * Supports zoom, pan, hover tooltips, anomalous edge highlighting,
 * and loading / empty / error states.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { ForceGraphMethods } from "react-force-graph-2d";
import { useGraphData } from "../../hooks/useGraphData";

interface ContainerNode {
  id: string;
  label: string;
  color: string;
  severity: "low" | "medium" | "high";
  [key: string]: unknown;
}

interface ConnectionLink {
  source: string;
  target: string;
  port: number;
  protocol: string;
  is_anomalous: boolean;
  label: string;
  isNew: boolean;
  [key: string]: unknown;
}

const NODE_SIZE = 8;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyNode = any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyLink = any;

export default function NetworkGraph() {
  const fgRef = useRef<ForceGraphMethods>();
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 600, height: 400 });
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  const { graphData, isLoading, error, refresh } = useGraphData();

  useEffect(() => {
    if (!containerRef.current) return;
    const obs = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        setDimensions({ width, height });
      }
    });
    obs.observe(containerRef.current);
    return () => obs.disconnect();
  }, []);

  // Process raw graphData into reconciled nodes and links for ForceGraph2D
  const processedGraph = useMemo(() => {
    const rawNodes = graphData?.nodes ?? [];
    const rawLinks = graphData?.links ?? [];

    const anomalousNodeIds = new Set<string>();
    for (const link of rawLinks) {
      if (link.is_anomalous) {
        if (link.source) anomalousNodeIds.add(String(link.source));
        if (link.target) anomalousNodeIds.add(String(link.target));
      }
    }

    const nodeMap = new Map<string, ContainerNode>();
    for (const n of rawNodes) {
      const id = String(n?.id ?? "");
      if (!id) continue;
      const isAnomalous = anomalousNodeIds.has(id);
      nodeMap.set(id, {
        id,
        label: String(n.label ?? id),
        color: isAnomalous ? "#ef4444" : "#22c55e",
        severity: isAnomalous ? "high" : "low",
      });
    }

    const processedLinks: ConnectionLink[] = [];
    for (const link of rawLinks) {
      const src = String(link?.source ?? "");
      const dst = String(link?.target ?? "");
      if (!src || !dst) continue;

      // Ensure any endpoint not in rawNodes is safely added to nodeMap
      if (!nodeMap.has(src)) {
        const isAnom = anomalousNodeIds.has(src);
        nodeMap.set(src, {
          id: src,
          label: src,
          color: isAnom ? "#ef4444" : "#94a3b8",
          severity: isAnom ? "high" : "low",
        });
      }
      if (!nodeMap.has(dst)) {
        const isAnom = anomalousNodeIds.has(dst);
        nodeMap.set(dst, {
          id: dst,
          label: dst,
          color: isAnom ? "#ef4444" : "#94a3b8",
          severity: isAnom ? "high" : "low",
        });
      }

      const port = Number(link.port) || 0;
      const protocol = String(link.protocol || "tcp").toLowerCase();
      const isAnomalous = Boolean(link.is_anomalous);
      const label = `${protocol.toUpperCase()}/${port}${isAnomalous ? " [ANOMALOUS]" : ""}`;

      processedLinks.push({
        source: src,
        target: dst,
        port,
        protocol,
        is_anomalous: isAnomalous,
        label,
        isNew: isAnomalous,
      });
    }

    return {
      nodes: Array.from(nodeMap.values()),
      links: processedLinks,
    };
  }, [graphData]);

  useEffect(() => {
    if (fgRef.current && processedGraph.nodes.length > 0) {
      const timer = setTimeout(() => fgRef.current?.zoomToFit(400, 60), 500);
      return () => clearTimeout(timer);
    }
  }, [processedGraph.nodes.length]);

  const nodeCanvasObject = useCallback(
    (node: AnyNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const size = NODE_SIZE / globalScale;
      const x = node.x ?? 0;
      const y = node.y ?? 0;

      if (hoveredNode === node.id) {
        ctx.beginPath();
        ctx.arc(x, y, size * 2, 0, 2 * Math.PI);
        ctx.fillStyle = `${node.color}33`;
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(x, y, size, 0, 2 * Math.PI);
      ctx.fillStyle = node.color;
      ctx.fill();

      ctx.strokeStyle = node.color;
      ctx.lineWidth = 1.5 / globalScale;
      ctx.stroke();

      const fontSize = 10 / globalScale;
      ctx.font = `${fontSize}px monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      ctx.fillStyle = "#e2e8f0";
      ctx.fillText(node.label, x, y + size + 2 / globalScale);
    },
    [hoveredNode],
  );

  const linkCanvasObject = useCallback(
    (link: AnyLink, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const sx = (typeof link.source === "object" ? link.source.x : 0) ?? 0;
      const sy = (typeof link.source === "object" ? link.source.y : 0) ?? 0;
      const tx = (typeof link.target === "object" ? link.target.x : 0) ?? 0;
      const ty = (typeof link.target === "object" ? link.target.y : 0) ?? 0;

      ctx.beginPath();
      ctx.moveTo(sx, sy);
      ctx.lineTo(tx, ty);
      const isAnomalous = link.is_anomalous || link.isNew;
      ctx.strokeStyle = isAnomalous ? "#ef444488" : "#475569";
      ctx.lineWidth = isAnomalous ? 2 / globalScale : 1 / globalScale;
      if (isAnomalous) {
        ctx.setLineDash([4 / globalScale, 2 / globalScale]);
      } else {
        ctx.setLineDash([]);
      }
      ctx.stroke();
      ctx.setLineDash([]);
    },
    [],
  );

  const hasNodes = processedGraph.nodes.length > 0;

  return (
    <div ref={containerRef} className="flex h-full w-full flex-col bg-slate-900">
      {/* Top bar with status and refresh */}
      <div className="flex items-center justify-between border-b border-slate-700 px-4 py-2">
        <h2 className="text-sm font-semibold">Container Topology</h2>
        <div className="flex items-center gap-2">
          {error && !hasNodes ? (
            <span className="rounded bg-red-900/60 px-2 py-0.5 text-xs text-red-300">
              API Error
            </span>
          ) : isLoading && !hasNodes ? (
            <span className="rounded bg-amber-900/60 px-2 py-0.5 text-xs text-amber-200">
              Loading…
            </span>
          ) : (
            <span className="rounded bg-slate-700 px-2 py-0.5 text-xs text-slate-300 font-mono">
              /api/graph ({processedGraph.nodes.length} nodes, {processedGraph.links.length} links)
            </span>
          )}
          <button
            onClick={() => void refresh()}
            disabled={isLoading}
            className="rounded bg-slate-800 hover:bg-slate-700 border border-slate-600 px-2.5 py-0.5 text-xs text-slate-300 transition-colors disabled:opacity-50"
            title="Refresh graph data from /api/graph"
          >
            {isLoading ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 px-4 py-1.5 text-xs text-slate-400">
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-green-500" /> healthy
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-amber-500" /> medium
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-red-500" /> high / alert
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-0.5 w-4 border-t border-dashed border-red-500" /> anomalous edge
        </span>
      </div>

      {/* Transient error notification when nodes already exist */}
      {error && hasNodes && (
        <div className="border-b border-red-800 bg-red-900/30 px-4 py-1.5 text-xs text-red-300 flex items-center justify-between">
          <span>Failed to refresh graph: {error}</span>
          <button onClick={() => void refresh()} className="underline hover:text-red-200">
            Retry
          </button>
        </div>
      )}

      {/* Main visualization area with state handling */}
      <div className="flex flex-1 flex-col">
        {isLoading && !hasNodes ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 text-slate-400">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-slate-600 border-t-cyan-400" />
            <span className="text-sm">Loading container topology…</span>
          </div>
        ) : error && !hasNodes ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 p-6 text-center text-slate-400">
            <div className="text-sm font-medium text-red-400">Failed to load graph data</div>
            <div className="max-w-sm text-xs text-slate-500">{error}</div>
            <button
              onClick={() => void refresh()}
              className="mt-2 rounded bg-slate-700 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-600 transition-colors"
            >
              Retry Connection
            </button>
          </div>
        ) : !hasNodes ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 p-6 text-center text-slate-400">
            <p className="text-sm font-medium text-slate-300">No container connections recorded yet</p>
            <p className="max-w-sm text-xs text-slate-500">
              When containers communicate, the live topology graph will automatically display active connections and anomalies.
            </p>
            <button
              onClick={() => void refresh()}
              className="mt-2 rounded bg-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-600 transition-colors"
            >
              Check Again
            </button>
          </div>
        ) : (
          <div className="flex-1">
            <ForceGraph2D
              ref={fgRef as React.MutableRefObject<ForceGraphMethods | undefined>}
              graphData={processedGraph}
              width={dimensions.width}
              height={dimensions.height - 60}
              backgroundColor="#0f172a"
              nodeCanvasObject={nodeCanvasObject}
              nodePointerAreaPaint={(node: AnyNode, color: string, ctx: CanvasRenderingContext2D, globalScale: number) => {
                const size = NODE_SIZE / globalScale;
                ctx.beginPath();
                ctx.arc(node.x ?? 0, node.y ?? 0, size * 1.5, 0, 2 * Math.PI);
                ctx.fillStyle = color;
                ctx.fill();
              }}
              linkCanvasObject={linkCanvasObject}
              linkDirectionalArrowLength={4}
              linkDirectionalArrowRelPos={0.9}
              linkDirectionalArrowColor={() => "#94a3b8"}
              linkDirectionalParticles={1}
              linkDirectionalParticleWidth={1.5}
              linkDirectionalParticleColor={() => "#60a5fa"}
              linkDirectionalParticleSpeed={0.005}
              linkLabel={(link: AnyLink) => link.label ?? ""}
              nodeLabel={(node: AnyNode) => `${node.label} (${node.severity})`}
              onNodeHover={(node: AnyNode | null) => setHoveredNode(node?.id ?? null)}
              cooldownTicks={100}
              warmupTicks={50}
              d3AlphaDecay={0.02}
              d3VelocityDecay={0.3}
              enableNodeDrag={true}
              enableZoomInteraction={true}
              enablePanInteraction={true}
            />
          </div>
        )}
      </div>
    </div>
  );
}
