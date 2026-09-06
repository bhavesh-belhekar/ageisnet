"""Build, spawn and feed the CO-RE capture binary; publish events to Redis.

The loader:
  1. Builds src/capture once at startup (make -C src capture, generating
     vmlinux.h from the host BTF) — if the build fails it logs an
     actionable error and exits non-zero (RULES.md Section 4.2: never run
     half-working).
  2. Spawns src/capture and parses its EVTO|/EVTC| pipe lines.
  3. Maps socket-owner netns inode -> container ID (cgroup scope + host
     /proc, agent runs with pid: host) and derives direction via the
     documented IP-map heuristic (ARCHITECTURE.md Section 3.1).
  4. Publishes matching events to Redis Streams with exponential backoff
     retries (max ~5), dropping only after retries are exhausted and
     logging a WARNING with the event's summary.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from glob import glob

import redis

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT_SRC = os.path.join(AGENT_DIR, "src")
AGENT_BIN = os.path.join(AGENT_SRC, "capture")
EVENTS_STREAM = "events:raw"
NETNS_RE = re.compile(r"^net:\[(\d+)\]$")
NETNS_REFRESH_SECONDS = 10
MAX_PUBLISH_ATTEMPTS = 6

logger = logging.getLogger("ebpf-agent")


def _netns_inode(pid: str) -> int | None:
    try:
        target = os.readlink(f"/proc/{pid}/ns/net")
    except OSError:
        return None
    match = NETNS_RE.match(target)
    return int(match.group(1)) if match else None


def _local_ips(pid: str) -> set[str]:
    ips: set[str] = set()
    try:
        with open(f"/proc/{pid}/net/fib_trie") as handle:
            in_local = False
            pending: str | None = None
            for line in handle:
                stripped = line.strip()
                if stripped == "Local:":
                    in_local = True
                    continue
                if not in_local:
                    continue
                if stripped.endswith(":") and stripped != "Local:":
                    break
                branch = re.match(r"(?:[+|]--\s*)?([0-9.]+)(/\d+)?$", stripped)
                if branch:
                    addr, subnet = branch.group(1), branch.group(2)
                    if subnet == "/32" and not addr.startswith("127.") and addr != "0.0.0.0":
                        ips.add(addr)
                    else:
                        pending = addr
                    continue
                if stripped.startswith("/32") and pending is not None:
                    if not pending.startswith("127.") and pending != "0.0.0.0":
                        ips.add(pending)
                    pending = None
    except OSError:
        return ips
    return ips


def build_container_info() -> tuple[dict[int, str], dict[str, str]]:
    netns_map: dict[int, str] = {}
    ip_map: dict[str, str] = {}
    patterns = [
        "/sys/fs/cgroup/system.slice/docker-*.scope",
        "/sys/fs/cgroup/docker-*.scope",
        "/sys/fs/cgroup/docker-*/",
    ]
    for pattern in patterns:
        for path in glob(pattern):
            scope = os.path.basename(path.rstrip("/"))
            cid = re.sub(r"^docker-", "", scope)
            cid = re.sub(r"\.scope$", "", cid)
            if len(cid) < 12:
                continue
            procs_path = os.path.join(path, "cgroup.procs")
            try:
                with open(procs_path) as handle:
                    for line in handle:
                        pid = line.strip()
                        inode = _netns_inode(pid)
                        if inode is not None:
                            netns_map[inode] = cid[:12]
                            for ip in _local_ips(pid):
                                ip_map[ip] = cid[:12]
                            break
            except OSError:
                continue
    return netns_map, ip_map


def read_stream(handle) -> str:
    line = handle.readline()
    if line:
        return line.strip()
    return ""


def event_summary(event: dict) -> str:
    return (
        f"{event['event_type']} {event['container_id']} "
        f"{event['src_ip']}:{event['src_port']}->{event['dst_ip']}:{event['dst_port']} "
        f"({event['direction']}, sent/recv {event['bytes_sent']}/{event['bytes_received']})"
    )


def publish(client: redis.Redis, event: dict) -> bool:
    payload = json.dumps(event)
    delay = 1.0
    for attempt in range(MAX_PUBLISH_ATTEMPTS):
        try:
            client.xadd(EVENTS_STREAM, {"event": payload})
            return True
        except redis.RedisError as exc:
            remaining = MAX_PUBLISH_ATTEMPTS - 1 - attempt
            if remaining == 0:
                logger.warning(
                    "dropping event after %d retries (%s): %s",
                    MAX_PUBLISH_ATTEMPTS - 1,
                    exc,
                    event_summary(event),
                )
                return False
            logger.warning("redis publish failed (%s); %d retries left", exc, remaining)
            time.sleep(delay)
            delay *= 2
    return False


class Loader:
    def __init__(self) -> None:
        self.redis_client = redis.Redis(
            host=os.environ.get("REDIS_HOST", "redis"),
            port=int(os.environ.get("REDIS_PORT", "6379")),
            password=os.environ.get("REDIS_PASSWORD") or None,
            decode_responses=True,
        )
        self.netns_map: dict[int, str] = {}
        self.ip_map: dict[str, str] = {}
        self._stop = threading.Event()

    def refresh_netns_map(self) -> None:
        self.netns_map, self.ip_map = build_container_info()

    def _refresh_loop(self) -> None:
        while not self._stop.wait(NETNS_REFRESH_SECONDS):
            try:
                self.refresh_netns_map()
            except OSError as exc:
                logger.warning("netns map refresh failed: %s", exc)

    def container_id(self, netns: int) -> str | None:
        return self.netns_map.get(netns)

    def build_event(self, event_type: str, fields: list[str]) -> dict | None:
        netns, src_ip, dst_ip, sport, dport, sent, recv, pid = fields
        netns_id = int(netns)
        container = self.container_id(netns_id)
        if container is None:
            return None
        other = self.ip_map.get(dst_ip)
        if other == container:
            other = None
        direction = "internal" if other is not None else "external"
        return {
            "event_id": self.redis_client.incr("events:id"),
            "container_id": container,
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(sport),
            "dst_port": int(dport),
            "protocol": "tcp",
            "bytes_sent": int(sent),
            "bytes_received": int(recv),
            "direction": direction,
        }

    def ensure_capture(self) -> bool:
        result = subprocess.run(
            ["make", "-C", AGENT_SRC, "capture"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if result.returncode != 0:
            tail = result.stdout[-2000:].strip() or "(no build output)"
            logger.error("CO-RE capture build failed (rc=%d):\n%s", result.returncode, tail)
            logger.error(
                "requires clang, llvm, libbpf-dev, bpftool and a host BTF "
                "at /sys/kernel/btf/vmlinux mounted into the container"
            )
            return False
        return True

    def run_capture(self, binary: str) -> None:
        process = subprocess.Popen(
            ["stdbuf", "-oL", binary],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        printed_containers: set[str] = set()
        while True:
            line = read_stream(process.stdout)
            if not line:
                if process.poll() is not None:
                    error = "".join(process.stderr.readlines()).strip()
                    logger.warning("capture stderr:\n%s", error)
                    if process.returncode == 0:
                        logger.info("capture exited cleanly (rc=0)")
                        sys.exit(0)
                    logger.error(
                        "capture exited rc=%d; refusing to run half-working",
                        process.returncode,
                    )
                    sys.exit(process.returncode)
                continue
            if not line.startswith("EVTO|") and not line.startswith("EVTC|"):
                continue
            prefix = line[:4]
            fields = line.split("|")[1:]
            if len(fields) != 8:
                continue
            try:
                event = self.build_event(
                    "open" if prefix == "EVTO" else "close",
                    fields,
                )
            except ValueError:
                continue
            except redis.RedisError as exc:
                logger.warning(
                    "redis unavailable while building event (%s); "
                    "backing off, dropping this raw event: %s",
                    exc,
                    "|".join(fields),
                )
                time.sleep(1)
                continue
            if event is None:
                continue
            if event["container_id"] not in printed_containers:
                printed_containers.add(event["container_id"])
                logger.info(
                    "capture active in netns of %s (%s)",
                    event["container_id"],
                    event["src_ip"],
                )
            publish(self.redis_client, event)

    def run(self) -> None:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )
        logger.info("building CO-RE capture (%s)", AGENT_BIN)
        if not self.ensure_capture():
            logger.error("capture build failed; exposing error and exiting non-zero")
            sys.exit(1)
        self.refresh_netns_map()
        logger.info("netns map: %d containers found", len(self.netns_map))
        threading.Thread(target=self._refresh_loop, daemon=True).start()
        self.run_capture(AGENT_BIN)


def main() -> None:
    Loader().run()


if __name__ == "__main__":
    main()
