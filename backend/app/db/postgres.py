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
    shap_explanation    JSONB,
    acknowledged        BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_raw_alerts_event    ON raw_alerts (event_id);
CREATE INDEX IF NOT EXISTS idx_raw_alerts_container ON raw_alerts (container_id);
CREATE INDEX IF NOT EXISTS idx_raw_alerts_severity ON raw_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_raw_alerts_mitre    ON raw_alerts (mitre_technique_id);
CREATE INDEX IF NOT EXISTS idx_raw_alerts_ts       ON raw_alerts (timestamp);
"""

MIGRATIONS = """
ALTER TABLE raw_alerts ADD COLUMN IF NOT EXISTS shap_explanation JSONB;
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
    """Create the raw_events and raw_alerts tables, indexes, and apply migrations."""
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_SQL)
        await conn.execute(ALERT_SCHEMA_SQL)
        await conn.execute(MIGRATIONS)
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


class DatabaseUnavailableError(RuntimeError):
    """Raised when the Postgres pool is unavailable / not initialized."""


def _event_row(record: asyncpg.Record) -> dict:
    """Map a raw_events row to the frozen Event schema (event_timestamp→timestamp)."""
    row = dict(record)
    row["timestamp"] = row.pop("event_timestamp")
    return row


def _build_where(
    columns: dict[str, str],
    values: dict[str, object],
) -> tuple[str, list[object]]:
    """Build a parameterized WHERE clause for whitelisted column:value pairs."""
    clauses = []
    params: list[object] = []
    for field, column in columns.items():
        value = values.get(field)
        if value is None:
            continue
        params.append(value)
        clauses.append(f"{column} = ${len(params)}")
    return ("WHERE " + " AND ".join(clauses)) if clauses else "", params


def _append_range(
    where_sql: str, params: list[object], column: str, op: str, value: object
) -> tuple[str, int]:
    """Append a ``column op $N`` clause and its value; returns (where, param_count)."""
    param_count = len(params) + 1
    clause = f"{column} {op} ${param_count}"
    params.append(value)
    where_sql = f"{where_sql} AND {clause}" if where_sql else f"WHERE {clause}"
    return where_sql, param_count


async def list_events(
    pool: asyncpg.Pool,
    *,
    container_id: str | None = None,
    direction: str | None = None,
    event_type: str | None = None,
    since: object | None = None,
    until: object | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Return raw events, newest first, filtered by the given criteria."""
    filtered = dict(container_id=container_id, direction=direction, event_type=event_type)
    where_sql, params = _build_where(
        {
            "container_id": "container_id",
            "direction": "direction",
            "event_type": "event_type",
        },
        filtered,
    )
    if since is not None:
        where_sql, param_count = _append_range(where_sql, params, "event_timestamp", ">=", since)
    else:
        param_count = len(params)
    if until is not None:
        where_sql, param_count = _append_range(where_sql, params, "event_timestamp", "<=", until)
    params.extend([limit, offset])
    sql = f"""
        SELECT * FROM raw_events
        {where_sql}
        ORDER BY event_id DESC
        LIMIT ${param_count + 1} OFFSET ${param_count + 2}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *params)
    return [_event_row(r) for r in rows]


async def list_alerts(
    pool: asyncpg.Pool,
    *,
    severity: str | None = None,
    container_id: str | None = None,
    since: object | None = None,
    until: object | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Return alerts, newest first, filtered by the given criteria."""
    where_sql, params = _build_where(
        {"severity": "severity", "container_id": "container_id"},
        {"severity": severity, "container_id": container_id},
    )
    if since is not None:
        where_sql, param_count = _append_range(where_sql, params, "timestamp", ">=", since)
    else:
        param_count = len(params)
    if until is not None:
        where_sql, param_count = _append_range(where_sql, params, "timestamp", "<=", until)
    params.extend([limit, offset])
    sql = f"""
        SELECT * FROM raw_alerts
        {where_sql}
        ORDER BY alert_id DESC
        LIMIT ${param_count + 1} OFFSET ${param_count + 2}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *params)
    return [dict(r) for r in rows]


async def get_alert(pool: asyncpg.Pool, alert_id: int) -> dict | None:
    """Return one alert by id, or None."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM raw_alerts WHERE alert_id = $1", alert_id)
    return dict(row) if row else None


async def ack_alert(pool: asyncpg.Pool, alert_id: int, acknowledged: bool) -> dict | None:
    """Set the acknowledged flag on an alert; return the updated row or None."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE raw_alerts SET acknowledged = $2 WHERE alert_id = $1 RETURNING *",
            alert_id,
            acknowledged,
        )
    return dict(row) if row else None
