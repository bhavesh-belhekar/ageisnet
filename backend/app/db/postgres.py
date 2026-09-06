"""PostgreSQL persistence — asyncpg-based, matching health.py conventions.

Creates the ``raw_events`` table on first start.  Designed for Phase 3
ingestion: insert-only, no dedup logic (belongs to the rule engine layer).
"""

from __future__ import annotations

import logging

import asyncpg

from app.config.settings import get_settings

logger = logging.getLogger("postgres")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS raw_events (
    event_id        BIGINT PRIMARY KEY,
    container_id    VARCHAR(12)  NOT NULL,
    event_timestamp TIMESTAMPTZ  NOT NULL,
    event_type      VARCHAR(8)   NOT NULL,
    src_ip          VARCHAR(45)  NOT NULL,
    dst_ip          VARCHAR(45)  NOT NULL,
    src_port        INTEGER      NOT NULL,
    dst_port        INTEGER      NOT NULL,
    protocol        VARCHAR(8)   NOT NULL,
    bytes_sent      BIGINT       NOT NULL DEFAULT 0,
    bytes_received  BIGINT       NOT NULL DEFAULT 0,
    direction       VARCHAR(8)   NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_raw_events_ts         ON raw_events (event_timestamp);
CREATE INDEX IF NOT EXISTS idx_raw_events_container  ON raw_events (container_id);
CREATE INDEX IF NOT EXISTS idx_raw_events_direction  ON raw_events (direction);
CREATE INDEX IF NOT EXISTS idx_raw_events_type       ON raw_events (event_type);
"""

ALERT_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS raw_alerts (
    alert_id            BIGSERIAL PRIMARY KEY,
    event_id            BIGINT       NOT NULL,
    container_id        VARCHAR(12)  NOT NULL,
    timestamp           TIMESTAMPTZ  NOT NULL,
    detection_type      VARCHAR(8)   NOT NULL,
    severity            VARCHAR(8)   NOT NULL,
    mitre_technique_id  VARCHAR(16),
    description         TEXT         NOT NULL,
    acknowledged        BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_raw_alerts_event    ON raw_alerts (event_id);
CREATE INDEX IF NOT EXISTS idx_raw_alerts_container ON raw_alerts (container_id);
CREATE INDEX IF NOT EXISTS idx_raw_alerts_severity ON raw_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_raw_alerts_mitre    ON raw_alerts (mitre_technique_id);
"""

INSERT_SQL = """
INSERT INTO raw_events (
    event_id, container_id, event_timestamp, event_type,
    src_ip, dst_ip, src_port, dst_port, protocol,
    bytes_sent, bytes_received, direction
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (event_id) DO NOTHING
"""

INSERT_ALERT_SQL = """
INSERT INTO raw_alerts (
    event_id, container_id, timestamp, detection_type,
    severity, mitre_technique_id, description, acknowledged
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING alert_id
"""


def _connect_kwargs() -> dict:
    s = get_settings()
    return dict(
        host=s.postgres_host,
        port=s.postgres_port,
        user=s.postgres_user,
        password=s.postgres_password,
        database=s.postgres_db,
    )


async def create_pool() -> asyncpg.Pool:
    """Create and return an asyncpg connection pool."""
    return await asyncpg.create_pool(**_connect_kwargs(), min_size=2, max_size=5)


async def ensure_schema(pool: asyncpg.Pool) -> None:
    """Create the raw_events and raw_alerts tables and indexes if missing."""
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_SQL)
        await conn.execute(ALERT_SCHEMA_SQL)
    logger.info("raw_events + raw_alerts schema ensured")


async def save_alert(pool: asyncpg.Pool, alert: dict) -> int:
    """Persist one alert dict to raw_alerts, returning the generated alert_id."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            INSERT_ALERT_SQL,
            alert["event_id"],
            alert["container_id"],
            alert["timestamp"],
            alert["detection_type"],
            alert["severity"],
            alert.get("mitre_technique_id"),
            alert["description"],
            alert.get("acknowledged", False),
        )
    return row["alert_id"]


async def save_event(pool: asyncpg.Pool, event: dict) -> None:
    """Persist one validated event dict to raw_events.  Raises on failure."""
    async with pool.acquire() as conn:
        await conn.execute(
            INSERT_SQL,
            event["event_id"],
            event["container_id"],
            event["timestamp"],
            event["event_type"],
            event["src_ip"],
            event["dst_ip"],
            event["src_port"],
            event["dst_port"],
            event["protocol"],
            event["bytes_sent"],
            event["bytes_received"],
            event["direction"],
        )
