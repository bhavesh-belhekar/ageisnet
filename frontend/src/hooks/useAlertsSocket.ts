/**
 * WebSocket hook for the real-time alert feed.
 *
 * Handles:
 *  - Connection to /ws/alerts with auto-reconnect + exponential backoff
 *    (RULES.md §4.4: reconnect without page refresh, backoff 1s→30s cap).
 *  - Initial REST fetch via GET /api/alerts to populate historical alerts.
 *  - Reconciliation: deduplicates by alert_id, merges SHAP follow-ups,
 *    re-fetches on reconnect to catch alerts missed during disconnect.
 *
 * Returns: { alerts, connectionState, lastError, selectedAlertId, setSelectedAlertId }
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  type Alert,
  type WsMessage,
  listAlerts,
  wsAlertsUrl,
} from "../api/client";

const BACKOFF_INITIAL_MS = 1000;
const BACKOFF_MAX_MS = 30000;
const INITIAL_FETCH_LIMIT = 100;

export type ConnectionState = "connecting" | "connected" | "disconnected" | "reconnecting";

export interface UseAlertsSocketReturn {
  alerts: Alert[];
  connectionState: ConnectionState;
  lastError: string | null;
  selectedAlertId: number | null;
  setSelectedAlertId: (id: number | null) => void;
}

export function useAlertsSocket(): UseAlertsSocketReturn {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connectionState, setConnectionState] = useState<ConnectionState>("connecting");
  const [lastError, setLastError] = useState<string | null>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const backoffRef = useRef(BACKOFF_INITIAL_MS);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  // ---- Merge helpers (operate on prev state to avoid stale closures) ----

  /** Insert or update an alert, deduplicating by alert_id. */
  const mergeAlert = useCallback((prev: Alert[], alert: Alert): Alert[] => {
    const idx = prev.findIndex((a) => a.alert_id === alert.alert_id);
    if (idx >= 0) {
      const next = [...prev];
      next[idx] = { ...next[idx], ...alert };
      return next;
    }
    return [alert, ...prev];
  }, []);

  /** Apply a SHAP follow-up update to an existing alert. */
  const mergeShap = useCallback(
    (prev: Alert[], alertId: number, shapExplanation: Alert["shap_explanation"]): Alert[] => {
      const idx = prev.findIndex((a) => a.alert_id === alertId);
      if (idx < 0) return prev;
      const next = [...prev];
      next[idx] = { ...next[idx], shap_explanation: shapExplanation };
      return next;
    },
    [],
  );

  // ---- Initial REST fetch ----

  useEffect(() => {
    mountedRef.current = true;

    listAlerts({ limit: INITIAL_FETCH_LIMIT })
      .then((data) => {
        if (mountedRef.current) setAlerts(data);
      })
      .catch((err) => {
        if (mountedRef.current) {
          setLastError(`Initial fetch failed: ${err.message}`);
          setConnectionState("disconnected");
        }
      });

    return () => {
      mountedRef.current = false;
    };
  }, []);

  // ---- WebSocket connection with reconnect ----

  // Use a ref to hold connect so scheduleReconnect doesn't need it in deps.
  const connectRef = useRef<() => void>(() => {});

  const scheduleReconnect = useCallback(() => {
    if (!mountedRef.current) return;
    if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);

    const delay = backoffRef.current;
    backoffRef.current = Math.min(backoffRef.current * 2, BACKOFF_MAX_MS);

    setConnectionState("reconnecting");
    reconnectTimerRef.current = setTimeout(() => {
      connectRef.current();
    }, delay);
  }, []);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setConnectionState((prev) => (prev === "connected" ? "reconnecting" : "connecting"));

    const ws = new WebSocket(wsAlertsUrl());
    wsRef.current = ws;

    ws.onopen = () => {
      if (!mountedRef.current) return;
      setConnectionState("connected");
      setLastError(null);
      backoffRef.current = BACKOFF_INITIAL_MS;

      listAlerts({ limit: INITIAL_FETCH_LIMIT })
        .then((data) => {
          if (mountedRef.current) setAlerts(data);
        })
        .catch((err) => {
          if (mountedRef.current) setLastError(`Re-fetch failed: ${err.message}`);
        });
    };

    ws.onmessage = (event: MessageEvent) => {
      if (!mountedRef.current) return;

      let msg: WsMessage;
      try {
        msg = JSON.parse(event.data) as WsMessage;
      } catch {
        setLastError("Malformed WebSocket message");
        return;
      }

      if ("update_type" in msg && msg.update_type === "shap_attachment") {
        setAlerts((prev) => mergeShap(prev, msg.alert_id, msg.shap_explanation));
        return;
      }

      setAlerts((prev) => mergeAlert(prev, msg as Alert));
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      wsRef.current = null;
      setConnectionState("disconnected");
      scheduleReconnect();
    };

    ws.onerror = () => {
      if (!mountedRef.current) return;
      setLastError("WebSocket error — will reconnect");
    };
  }, [mergeAlert, mergeShap, scheduleReconnect]);

  // Keep connectRef current so the scheduleReconnect timer calls latest connect.
  connectRef.current = connect;

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, [connect]);

  return {
    alerts,
    connectionState,
    lastError,
    selectedAlertId,
    setSelectedAlertId,
  };
}
