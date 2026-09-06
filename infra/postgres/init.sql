CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS events (
    event_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    container_id    TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    src_ip          INET NOT NULL,
    dst_ip          INET NOT NULL,
    src_port        INTEGER NOT NULL,
    dst_port        INTEGER NOT NULL,
    protocol        TEXT NOT NULL,
    bytes_sent      BIGINT NOT NULL DEFAULT 0,
    bytes_received  BIGINT NOT NULL DEFAULT 0,
    direction       TEXT NOT NULL CHECK (direction IN ('internal', 'external'))
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id           BIGINT REFERENCES events (event_id),
    container_id       TEXT NOT NULL,
    timestamp          TIMESTAMPTZ NOT NULL,
    detection_type     TEXT NOT NULL CHECK (detection_type IN ('rule', 'ml')),
    severity           TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    mitre_technique_id TEXT,
    description        TEXT NOT NULL,
    shap_explanation   JSONB,
    acknowledged       BOOLEAN NOT NULL DEFAULT FALSE
);

SELECT create_hypertable('events', 'timestamp', if_not_exists => TRUE);
SELECT create_hypertable('alerts', 'timestamp', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_events_container_time
    ON events (container_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_container_time
    ON alerts (container_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_severity_time
    ON alerts (severity, timestamp DESC);