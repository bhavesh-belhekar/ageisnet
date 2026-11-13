import json

import pytest

from app.ml_engine.flow_model import features


class FakeRedis:
    def __init__(self, entries):
        self.entries = entries

    async def xrevrange(self, stream, count):
        return self.entries


@pytest.mark.asyncio
async def test_window_seconds_with_newest_first_events(monkeypatch):
    now = 2_000_000_000.0
    monkeypatch.setattr(features.time, "time", lambda: now)

    def make_entry(timestamp, event_id, dst_port):
        event = {
            "container_id": "abc123",
            "direction": "external",
            "event_type": "close",
            "bytes_sent": 100,
            "bytes_received": 200,
            "dst_port": dst_port,
            "dst_ip": "8.8.8.8",
        }
        stream_id = f"{int(timestamp * 1000)}-0".encode()
        fields = {
            b"event": json.dumps({"event": json.dumps(event)}).encode()
        }
        return stream_id, fields

    # Redis XREVRANGE returns newest event first.
    entries = [
        make_entry(now - 10, 2, 443),
        make_entry(now - 110, 1, 80),
    ]

    redis = FakeRedis(entries)

    result = await features.extract_flow_features(
        redis, container_id="abc123", window_minutes=5
    )

    assert result is not None
    assert result["window_seconds"] == 100.0
    assert result["total_bytes_sent"] == 200
    assert result["total_bytes_received"] == 400
    assert result["connection_count"] == 2
    assert result["unique_dst_ports"] == 2
    assert result["unique_dst_ips"] == 1
