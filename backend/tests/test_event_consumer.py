"""Focused tests for event_consumer reliability and recovery (Stage 3B)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis.asyncio as aioredis
from app.consumers.event_consumer import (
    CONSUMER,
    DEAD_LETTER,
    GROUP,
    MAX_DELIVERIES,
    STREAM,
    _check_and_dead_letter_if_exceeded,
    _dead_letter_message,
    _drain_pending,
    _sweep_dead_letters,
    consumer_loop,
)


@pytest.fixture()
def fake_pool() -> MagicMock:
    return MagicMock()


@pytest.fixture()
def mock_redis() -> AsyncMock:
    redis = AsyncMock()
    redis.xadd = AsyncMock(return_value=b"123-0")
    redis.xack = AsyncMock(return_value=1)
    redis.xpending = AsyncMock(return_value={"pending": 0})
    redis.xpending_range = AsyncMock(return_value=[])
    redis.xrange = AsyncMock(return_value=[])
    redis.xreadgroup = AsyncMock(return_value=[])
    return redis


@pytest.mark.asyncio
async def test_dead_letter_message_writes_and_acks(mock_redis: AsyncMock) -> None:
    """_dead_letter_message must write to DEAD_LETTER stream and ACK the original message."""
    raw_id = b"1690000000000-0"
    fields = {b"event": b"invalid json content"}

    await _dead_letter_message(
        mock_redis,
        raw_id=raw_id,
        fields=fields,
        deliveries=5,
        consumer=CONSUMER,
        reason="malformed_event",
    )

    mock_redis.xadd.assert_awaited_once()
    call_args = mock_redis.xadd.await_args
    assert call_args[0][0] == DEAD_LETTER
    assert call_args[0][1]["deliveries"] == 5
    assert call_args[0][1]["dead_letter_reason"] == "malformed_event"

    mock_redis.xack.assert_awaited_once_with(STREAM, GROUP, raw_id)


@pytest.mark.asyncio
async def test_check_and_dead_letter_exceeded(mock_redis: AsyncMock) -> None:
    """When message delivery attempts reach MAX_DELIVERIES, it is dead-lettered and ACKed."""
    raw_id = b"1690000000000-0"
    fields = {b"event": b"bad json"}

    # Mock xpending_range returning an entry with times_delivered = MAX_DELIVERIES
    mock_redis.xpending_range.return_value = [
        {"message_id": "1690000000000-0", "times_delivered": MAX_DELIVERIES, "consumer": CONSUMER}
    ]

    exceeded = await _check_and_dead_letter_if_exceeded(
        mock_redis, raw_id, fields, reason="malformed_event"
    )
    assert exceeded is True
    mock_redis.xadd.assert_awaited_once()
    mock_redis.xack.assert_awaited_once_with(STREAM, GROUP, raw_id)


@pytest.mark.asyncio
async def test_check_and_dead_letter_under_limit(mock_redis: AsyncMock) -> None:
    """When message delivery attempts are under MAX_DELIVERIES, it is NOT dead-lettered."""
    raw_id = b"1690000000000-0"
    fields = {b"event": b"bad json"}

    # Mock xpending_range returning times_delivered = 2 (< MAX_DELIVERIES)
    mock_redis.xpending_range.return_value = [
        {"message_id": "1690000000000-0", "times_delivered": 2, "consumer": CONSUMER}
    ]

    exceeded = await _check_and_dead_letter_if_exceeded(mock_redis, raw_id, fields)
    assert exceeded is False
    mock_redis.xadd.assert_not_awaited()
    mock_redis.xack.assert_not_awaited()


@pytest.mark.asyncio
async def test_pending_drain_does_not_loop_infinitely_on_malformed_messages(
    mock_redis: AsyncMock, fake_pool: MagicMock
) -> None:
    """_drain_pending must advance past un-ACKed malformed messages without infinite loop."""
    mock_redis.xpending.return_value = {"pending": 2}
    mock_redis.xpending_range.return_value = []

    # Stream returns two malformed messages on first read, and empty on subsequent read
    call_count = 0

    async def fake_xreadgroup(group, consumer, streams, count):
        nonlocal call_count
        call_count += 1
        stream_id = streams[STREAM]
        if stream_id == "0":
            return [
                (
                    STREAM,
                    [
                        (b"1001-0", {b"event": b"invalid json 1"}),
                        (b"1002-0", {b"event": b"invalid json 2"}),
                    ],
                )
            ]
        # On subsequent read (streams={"events:raw": "1002-0"}), no more pending messages
        return []

    mock_redis.xreadgroup.side_effect = fake_xreadgroup

    # Run with timeout to verify it terminates promptly and doesn't hang
    await asyncio.wait_for(_drain_pending(mock_redis, fake_pool), timeout=2.0)

    # Must have read twice: once for "0", once for "1002-0", then stopped
    assert call_count == 2


@pytest.mark.asyncio
async def test_sweep_dead_letters_moves_expired_pending_entries(mock_redis: AsyncMock) -> None:
    """_sweep_dead_letters properly moves entries exceeding MAX_DELIVERIES to dead letter."""
    mock_redis.xpending.return_value = {"pending": 1}
    mock_redis.xpending_range.return_value = [
        {"message_id": "9999-0", "times_delivered": 6, "consumer": "backend-1"}
    ]
    mock_redis.xrange.return_value = [("9999-0", {b"event": b"expired event payload"})]

    await _sweep_dead_letters(mock_redis)

    mock_redis.xadd.assert_awaited_once()
    mock_redis.xack.assert_awaited_once_with(STREAM, GROUP, "9999-0")


@pytest.mark.asyncio
async def test_consumer_loop_reconnects_on_redis_connection_error(
    mock_redis: AsyncMock, fake_pool: MagicMock
) -> None:
    """consumer_loop catches Redis connection errors, waits with backoff, and reconnects."""
    attempts = 0

    async def fake_ensure_group(r):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise aioredis.ConnectionError("Connection to Redis refused (test)")
        # On second attempt, let it succeed and then cancel the task
        raise asyncio.CancelledError()

    with patch("app.consumers.event_consumer._ensure_group", side_effect=fake_ensure_group):
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            with pytest.raises(asyncio.CancelledError):
                await consumer_loop(mock_redis, fake_pool)

            # Verified that it slept for backoff before reconnecting
            mock_sleep.assert_awaited_once()
            assert attempts == 2
