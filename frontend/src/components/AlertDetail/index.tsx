/**
 * AlertDetail — full detail view for a selected alert (FR-8.2, FR-8.3, FR-11).
 *
 * Shows container, timestamps, detection type, severity, MITRE technique,
 * description, explanation panel, and acknowledge button.
 * Discriminates between "shap" and "rule_based" explanation types (FR-11).
 */

import { useEffect, useState } from "react";
import type { Alert } from "../../api/client";

interface AlertDetailProps {
  alert: Alert;
  onClose: () => void;
}

const SEVERITY_BADGE: Record<string, string> = {
  low: "bg-slate-600 text-slate-200",
  medium: "bg-amber-600 text-white",
  high: "bg-red-600 text-white",
};

const DETECTION_LABEL: Record<string, string> = {
  rule: "Rule-Based",
  ml: "ML Anomaly",
};

function formatTime(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

// ---- Explanation panels (discriminated union on explanation_type) ----

interface FeatureBarProps {
  feature: string;
  shap: number;
  value: number;
  direction: "anomaly_push" | "normalizing";
  maxAbs: number;
}

function FeatureBar({ feature, shap, value: _value, direction, maxAbs }: FeatureBarProps) {
  void _value; // value is in the data but not rendered in the bar
  const pct = maxAbs > 0 ? (Math.abs(shap) / maxAbs) * 100 : 0;
  const color = direction === "anomaly_push" ? "bg-red-500" : "bg-green-500";
  const arrow = direction === "anomaly_push" ? "\u2191" : "\u2193";

  return (
    <div className="grid grid-cols-[140px_1fr_60px] items-center gap-2 text-xs">
      <span className="truncate font-mono text-slate-300">{feature}</span>
      <div className="relative h-3 overflow-hidden rounded bg-slate-700">
        <div
          className={`absolute inset-y-0 left-0 ${color}`}
          style={{ width: `${Math.min(pct, 100)}%` }}
        />
      </div>
      <span className="text-right text-slate-400">
        {arrow} {shap.toFixed(4)}
      </span>
    </div>
  );
}

function ShapFlowPanel({ explanation }: { explanation: Record<string, unknown> }) {
  const topFeatures = explanation.top_features as
    | Array<{ feature: string; value: number; shap: number; direction: string }>
    | undefined;

  if (!topFeatures || topFeatures.length === 0) {
    return (
      <div className="rounded border border-emerald-800 bg-emerald-900/20 p-3 text-sm text-slate-400">
        No feature contributions available.
      </div>
    );
  }

  const maxAbs = Math.max(...topFeatures.map((f) => Math.abs(f.shap)));

  return (
    <div className="rounded border border-emerald-800 bg-emerald-900/20 p-4">
      <p className="mb-3 font-medium text-emerald-300">SHAP Explanation — Flow Model</p>
      <p className="mb-3 text-xs text-slate-400">
        Model: {String(explanation.model ?? "isolation_forest")}
      </p>
      <div className="space-y-1.5">
        {topFeatures.map((f) => (
          <FeatureBar
            key={f.feature}
            feature={f.feature}
            shap={f.shap}
            value={f.value}
            direction={f.direction as "anomaly_push" | "normalizing"}
            maxAbs={maxAbs}
          />
        ))}
      </div>
    </div>
  );
}

function ShapGraphPanel({ explanation }: { explanation: Record<string, unknown> }) {
  return (
    <div className="rounded border border-blue-800 bg-blue-900/20 p-4">
      <p className="mb-3 font-medium text-blue-300">Explanation — Graph Diff Model</p>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
        <dt className="text-slate-400">Trigger</dt>
        <dd className="font-medium text-slate-200">{String(explanation.trigger ?? "—")}</dd>

        <dt className="text-slate-400">Source</dt>
        <dd className="font-mono text-slate-200">{String(explanation.src_container ?? "—")}</dd>

        <dt className="text-slate-400">Destination</dt>
        <dd className="font-mono text-slate-200">{String(explanation.dst_container ?? "—")}</dd>

        <dt className="text-slate-400">Port</dt>
        <dd className="font-mono text-slate-200">{String(explanation.port ?? "—")}</dd>

        <dt className="text-slate-400">Baseline edges seen</dt>
        <dd className="text-slate-200">{String(explanation.baseline_edges_seen ?? "0")}</dd>

        <dt className="text-slate-400">Reason</dt>
        <dd className="col-span-2 text-slate-200">{String(explanation.reason ?? "—")}</dd>
      </dl>
    </div>
  );
}

function ExplanationPanel({ explanation }: { explanation: Alert["shap_explanation"] }) {
  if (!explanation) {
    return (
      <div className="rounded border border-slate-600 bg-slate-700/30 p-3 text-sm text-slate-400">
        No explanation available. (Only ML detections generate explanations.)
      </div>
    );
  }

  if (explanation.explanation_type === "shap") {
    return <ShapFlowPanel explanation={explanation as Record<string, unknown>} />;
  }

  if (explanation.explanation_type === "rule_based") {
    return <ShapGraphPanel explanation={explanation as Record<string, unknown>} />;
  }

  return (
    <div className="rounded border border-slate-600 bg-slate-700/30 p-3 text-sm text-slate-400">
      Unknown explanation type: {explanation.explanation_type}
    </div>
  );
}

export default function AlertDetail({ alert, onClose }: AlertDetailProps) {
  const [ackState, setAckState] = useState(alert.acknowledged);
  const [ackLoading, setAckLoading] = useState(false);

  // Sync ack state when alert prop changes
  useEffect(() => {
    setAckState(alert.acknowledged);
  }, [alert.acknowledged]);

  const handleAck = async () => {
    setAckLoading(true);
    try {
      const { ackAlert } = await import("../../api/client");
      await ackAlert(alert.alert_id, !ackState);
      setAckState(!ackState);
    } catch (err) {
      console.error("Ack failed:", err);
    } finally {
      setAckLoading(false);
    }
  };

  return (
    <section className="flex h-full flex-col overflow-y-auto bg-slate-800/30 p-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold">Alert #{alert.alert_id}</h2>
          <p className="mt-1 text-sm text-slate-400">
            Event #{alert.event_id} &middot; {alert.container_id}
          </p>
        </div>
        <button
          onClick={onClose}
          className="rounded border border-slate-600 px-3 py-1 text-sm text-slate-300 hover:bg-slate-700"
        >
          Close
        </button>
      </div>

      {/* Metadata grid */}
      <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
        <div>
          <dt className="text-slate-400">Severity</dt>
          <dd className="mt-0.5">
            <span
              className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${SEVERITY_BADGE[alert.severity]}`}
            >
              {alert.severity}
            </span>
          </dd>
        </div>
        <div>
          <dt className="text-slate-400">Detection Type</dt>
          <dd className="mt-0.5 font-medium">
            {DETECTION_LABEL[alert.detection_type] ?? alert.detection_type}
          </dd>
        </div>
        <div>
          <dt className="text-slate-400">MITRE Technique</dt>
          <dd className="mt-0.5 font-mono text-xs">{alert.mitre_technique_id ?? "\u2014"}</dd>
        </div>
        <div>
          <dt className="text-slate-400">Timestamp</dt>
          <dd className="mt-0.5 text-xs">{formatTime(alert.timestamp)}</dd>
        </div>
      </dl>

      {/* Description */}
      <div className="mt-4">
        <h3 className="text-sm font-medium text-slate-300">Description</h3>
        <p className="mt-1 rounded bg-slate-700/50 p-3 text-sm text-slate-200">
          {alert.description}
        </p>
      </div>

      {/* Explanation */}
      <div className="mt-4">
        <h3 className="text-sm font-medium text-slate-300">Explainability</h3>
        <div className="mt-1">
          <ExplanationPanel explanation={alert.shap_explanation} />
        </div>
      </div>

      {/* Acknowledge button */}
      <div className="mt-6">
        <button
          onClick={handleAck}
          disabled={ackLoading}
          className={`rounded border px-4 py-2 text-sm font-medium transition-colors ${
            ackState
              ? "border-green-700 bg-green-900/30 text-green-300 hover:bg-green-900/50"
              : "border-slate-600 bg-slate-700 text-slate-200 hover:bg-slate-600"
          } ${ackLoading ? "opacity-50" : ""}`}
        >
          {ackLoading ? "Saving..." : ackState ? "Acknowledged" : "Acknowledge"}
        </button>
      </div>
    </section>
  );
}
