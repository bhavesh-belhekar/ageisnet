/**
 * NetworkGraph — container topology visualization (FR-8, RULES.md §2.3).
 *
 * Phase 6b: renders realistic mock data with react-force-graph-2d.
 * Will wire to GET /api/graph once that endpoint is implemented (Phase 7).
 *
 * Mock data represents the containers visible in our live Postgres alerts:
 * web-server, db-conn, demo-web, redis, neo4j — with edges derived from
 * the alerts we've been generating.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { ForceGraphMethods } from "react-force-graph-2d";

// ---- Mock topology data (realistic, matches our test environment) ----

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
  label: string;
  isNew: boolean;
  [key: string]: unknown;
}

const MOCK_NODES: ContainerNode[] = [
  { id: "web-server", label: "web-server", color: "#f59e0b", severity: "medium" },
  { id: "db-conn", label: "db-conn", color: "#22c55e", severity: "low" },
  { id: "demo-web", label: "demo-web", color: "#ef4444", severity: "high" },
  { id: "redis", label: "redis", color: "#22c55e", severity: "low" },
  { id: "neo4j", label: "neo4j", color: "#22c55e", severity: "low" },
  { id: "postgres", label: "postgres", color: "#22c55e", severity: "low" },
  { id: "ebpf-agent", label: "ebpf-agent", color: "#6366f1", severity: "low" },
];

const MOCK_LINKS: ConnectionLink[] = [
  { source: "web-server", target: "redis", port: 6379, label: "cache", isNew: false },
  { source: "web-server", target: "postgres", port: 5432, label: "query", isNew: false },
  { source: "db-conn", target: "postgres", port: 3306, label: "mysql", isNew: true },
  { source: "demo-web", target: "redis", port: 6379, label: "cache", isNew: false },
  { source: "neo4j", target: "postgres", port: 5432, label: "sync", isNew: false },
  { source: "ebpf-agent", target: "redis", port: 6379, label: "publish", isNew: false },
  { source: "web-server", target: "185.220.100.252", port: 8080, label: "external (alert #223)", isNew: true },
  { source: "demo-web", target: "10.0.0.3", port: 22, label: "SSH (alert #226)", isNew: true },
];

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

  useEffect(() => {
    if (fgRef.current) {
      setTimeout(() => fgRef.current?.zoomToFit(400, 60), 500);
    }
  }, []);

  const graphData = { nodes: MOCK_NODES, links: MOCK_LINKS };

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
      const sx = link.source.x ?? 0;
      const sy = link.source.y ?? 0;
      const tx = link.target.x ?? 0;
      const ty = link.target.y ?? 0;

      ctx.beginPath();
      ctx.moveTo(sx, sy);
      ctx.lineTo(tx, ty);
      ctx.strokeStyle = link.isNew ? "#ef444488" : "#475569";
      ctx.lineWidth = link.isNew ? 2 / globalScale : 1 / globalScale;
      if (link.isNew) {
        ctx.setLineDash([4 / globalScale, 2 / globalScale]);
      } else {
        ctx.setLineDash([]);
      }
      ctx.stroke();
      ctx.setLineDash([]);
    },
    [],
  );

  return (
    <div ref={containerRef} className="flex h-full w-full flex-col bg-slate-900">
      <div className="flex items-center justify-between border-b border-slate-700 px-4 py-2">
        <h2 className="text-sm font-semibold">Container Topology</h2>
        <span className="rounded bg-slate-700 px-2 py-0.5 text-xs text-slate-400">
          MOCK DATA — /api/graph
        </span>
      </div>

      <div className="flex items-center gap-4 px-4 py-1.5 text-xs text-slate-400">
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-green-500" /> healthy
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-amber-500" /> medium
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-red-500" /> high
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-0.5 w-4 border-t border-dashed border-red-500" /> new/alert edge
        </span>
      </div>

      <div className="flex-1">
        <ForceGraph2D
          ref={fgRef as React.MutableRefObject<ForceGraphMethods | undefined>}
          graphData={graphData}
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
    </div>
  );
}
