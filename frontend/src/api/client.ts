/** Typed API client for the AegisNet backend.

All REST calls go through ``request<T>()``, which returns the parsed JSON
as type ``T`` and throws on non-2xx responses with a structured error.

Base URL defaults to ``http://localhost:8000`` (the backend container in
Docker Compose).  Override via ``VITE_API_BASE_URL`` env var for local dev.
 */

const BASE_URL: string =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

// ------------------------------------------------------------------
// Types matching the backend Pydantic models
// ------------------------------------------------------------------

export type Severity = "low" | "medium" | "high";
export type DetectionType = "rule" | "ml";

export interface Alert {
  alert_id: number;
  event_id: number;
  container_id: string;
  timestamp: string;
  detection_type: DetectionType;
  severity: Severity;
  mitre_technique_id: string | null;
  description: string;
  shap_explanation: ShapExplanation | null;
  acknowledged: boolean;
}

// Discriminated union for the two explanation shapes (FR-11)
export interface ShapExplanation {
  explanation_type: "shap" | "rule_based";
  [key: string]: unknown; // allow shape-specific fields
}

export interface ShapExplanationFlow extends ShapExplanation {
  explanation_type: "shap";
  model: string;
  top_features: FeatureContribution[];
  all_contributions: Record<string, FeatureData>;
}

export interface ShapExplanationGraph extends ShapExplanation {
  explanation_type: "rule_based";
  trigger: string;
  src_container: string;
  dst_container: string;
  port: number;
  reason: string;
  baseline_edges_seen: number;
}

export interface FeatureContribution {
  feature: string;
  value: number;
  shap: number;
  direction: "anomaly_push" | "normalizing";
}

export interface FeatureData {
  value: number;
  shap: number;
  direction: "anomaly_push" | "normalizing";
}

export interface Event {
  event_id: number;
  container_id: string;
  timestamp: string;
  event_type: "open" | "close";
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  bytes_sent: number;
  bytes_received: number;
  direction: "internal" | "external";
}

// ------------------------------------------------------------------
// WebSocket message shapes
// ------------------------------------------------------------------

/** New alert pushed in real time (FR-7.2). */
export interface WsAlertMessage extends Alert {
  alert_id: number;
}

/** SHAP follow-up pushed after async computation (FR-11.2). */
export interface WsShapUpdate {
  alert_id: number;
  event_id: number;
  shap_explanation: ShapExplanation;
  update_type: "shap_attachment";
}

export type WsMessage = WsAlertMessage | WsShapUpdate;

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

export class ApiError extends Error {
  constructor(
    public status: number,
    public body: unknown,
  ) {
    super(`API ${status}: ${JSON.stringify(body)}`);
    this.name = "ApiError";
  }
}

/** Type-safe fetch wrapper.  Throws ``ApiError`` on non-2xx. */
export async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });

  if (!res.ok) {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = await res.text();
    }
    throw new ApiError(res.status, body);
  }

  return res.json() as Promise<T>;
}

// ------------------------------------------------------------------
// Convenience query functions
// ------------------------------------------------------------------

export interface ListAlertsParams {
  severity?: Severity;
  container_id?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

export function listAlerts(params: ListAlertsParams = {}): Promise<Alert[]> {
  const qs = new URLSearchParams();
  if (params.severity) qs.set("severity", params.severity);
  if (params.container_id) qs.set("container_id", params.container_id);
  if (params.since) qs.set("since", params.since);
  if (params.until) qs.set("until", params.until);
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return request<Alert[]>(`/api/alerts${query ? `?${query}` : ""}`);
}

export function getAlert(alertId: number): Promise<Alert> {
  return request<Alert>(`/api/alerts/${alertId}`);
}

export function ackAlert(alertId: number, acknowledged: boolean): Promise<Alert> {
  return request<Alert>(`/api/alerts/${alertId}/ack`, {
    method: "PATCH",
    body: JSON.stringify({ acknowledged }),
  });
}

/** Build the WebSocket URL for the alerts stream. */
export function wsAlertsUrl(): string {
  const base = BASE_URL.replace(/^http/, "ws");
  return `${base}/ws/alerts`;
}
