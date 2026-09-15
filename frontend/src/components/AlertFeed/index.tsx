/**
 * AlertFeed — real-time + historical alert list (FR-8.1, FR-8.4).
 *
 * Displays alerts newest-first, filterable by severity and container.
 * Receives alerts and connection state from the parent (via useAlertsSocket).
 * Highlights newly-arrived alerts and supports click-to-select.
 */

import { useState } from "react";
import type { Alert, Severity } from "../../api/client";
import type { ConnectionState } from "../../hooks/useAlertsSocket";

interface AlertFeedProps {
  alerts: Alert[];
  connectionState: ConnectionState;
  lastError: string | null;
  selectedAlertId: number | null;
  onSelectAlert: (id: number | null) => void;
}

const SEVERITY_COLORS: Record<Severity, string> = {
  low: "bg-slate-600",
  medium: "bg-amber-600",
  high: "bg-red-600",
};

const SEVERITY_BORDER: Record<Severity, string> = {
  low: "border-slate-600",
  medium: "border-amber-500",
  high: "border-red-500",
};

const CONNECTION_BADGE: Record<ConnectionState, { label: string; color: string }> = {
  connecting: { label: "Connecting…", color: "bg-yellow-600" },
  connected: { label: "Live", color: "bg-green-600" },
  disconnected: { label: "Disconnected", color: "bg-red-600" },
  reconnecting: { label: "Reconnecting…", color: "bg-yellow-600" },
};

function formatTime(ts: string): string {
  try {
    return new Date(ts).toLocaleTimeString();
  } catch {
    return ts;
  }
}

export default function AlertFeed({
  alerts,
  connectionState,
  lastError,
  selectedAlertId,
  onSelectAlert,
}: AlertFeedProps) {
  const [severityFilter, setSeverityFilter] = useState<Severity | "">("");
  const [containerFilter, setContainerFilter] = useState("");

  // Derive unique container IDs for the filter dropdown
  const containerIds = [...new Set(alerts.map((a) => a.container_id))].sort();

  // Apply filters
  const filtered = alerts.filter((a) => {
    if (severityFilter && a.severity !== severityFilter) return false;
    if (containerFilter && !a.container_id.includes(containerFilter)) return false;
    return true;
  });

  const badge = CONNECTION_BADGE[connectionState];

  return (
    <section className="flex h-full flex-col rounded-lg border border-slate-700 bg-slate-800/50">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-700 px-4 py-3">
        <h2 className="text-lg font-semibold">Alert Feed</h2>
        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${badge.color}`}>
          {badge.label}
        </span>
      </div>

      {/* Error banner */}
      {lastError && (
        <div className="border-b border-red-800 bg-red-900/30 px-4 py-2 text-sm text-red-300">
          {lastError}
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-2 border-b border-slate-700 px-4 py-2">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Severity | "")}
          className="rounded border border-slate-600 bg-slate-700 px-2 py-1 text-sm text-slate-200"
        >
          <option value="">All severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={containerFilter}
          onChange={(e) => setContainerFilter(e.target.value)}
          className="rounded border border-slate-600 bg-slate-700 px-2 py-1 text-sm text-slate-200"
        >
          <option value="">All containers</option>
          {containerIds.map((id) => (
            <option key={id} value={id}>
              {id}
            </option>
          ))}
        </select>
        <span className="ml-auto self-center text-xs text-slate-500">
          {filtered.length} alert{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Alert list */}
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <p className="p-4 text-center text-sm text-slate-500">
            {alerts.length === 0 ? "No alerts yet." : "No alerts match filters."}
          </p>
        ) : (
          <ul>
            {filtered.map((alert) => (
              <li key={alert.alert_id}>
                <button
                  onClick={() =>
                    onSelectAlert(selectedAlertId === alert.alert_id ? null : alert.alert_id)
                  }
                  className={`w-full border-l-4 px-4 py-3 text-left transition-colors hover:bg-slate-700/50 ${
                    selectedAlertId === alert.alert_id
                      ? "bg-slate-700"
                      : "bg-transparent"
                  } ${SEVERITY_BORDER[alert.severity]}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span
                          className={`inline-block h-2 w-2 rounded-full ${SEVERITY_COLORS[alert.severity]}`}
                        />
                        <span className="truncate text-sm font-medium text-slate-100">
                          {alert.container_id}
                        </span>
                        <span className="shrink-0 rounded px-1.5 py-0.5 text-xs font-mono text-slate-400">
                          {alert.severity}
                        </span>
                        {alert.mitre_technique_id && (
                          <span className="shrink-0 rounded bg-slate-600 px-1.5 py-0.5 text-xs font-mono text-slate-300">
                            {alert.mitre_technique_id}
                          </span>
                        )}
                      </div>
                      <p className="mt-1 truncate text-sm text-slate-300">
                        {alert.description}
                      </p>
                    </div>
                    <span className="shrink-0 text-xs text-slate-500">
                      {formatTime(alert.timestamp)}
                    </span>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
