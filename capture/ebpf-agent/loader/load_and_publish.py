"""Load eBPF programs and publish captured raw events to Redis Streams.

Attribution: netns inode to container mapping is rebuilt from cgroup scope
paths and host /proc (agent runs with pid: host). Only events whose netns
belongs to a known container are published, in the frozen Event schema
(PRD.md Section 9).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import UTC, datetime
from glob import glob

import redis

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT_BT = os.path.join(AGENT_DIR, "src", "agent.bt")
EVENTS_STREAM = "events:raw"
NETNS_RE = re.compile(r"^net:\[(\d+)\]$")
NETNS_REFRESH_SECONDS = 10
BPTRACE_RESTART_DELAY_SECONDS = 2


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


def publish(client: redis.Redis, event: dict) -> None:
    payload = json.dumps(event)
    client.xadd(EVENTS_STREAM, {"event": payload})


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

    def refresh_netns_map(self) -> None:
        self.netns_map, self.ip_map = build_container_info()

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

    def run_btrace(self) -> None:
        process = subprocess.Popen(
            ["stdbuf", "-oL", "bpftrace", AGENT_BT],
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
                    print(f"bpftrace exited rc={process.returncode}: {error}", flush=True)
                    time.sleep(BPTRACE_RESTART_DELAY_SECONDS)
                    return
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
            if event is None:
                continue
            if event["container_id"] not in printed_containers:
                printed_containers.add(event["container_id"])
                print(
                    f"capture active in netns of {event['container_id']} " f"({event['src_ip']})",
                    flush=True,
                )
            publish(self.redis_client, event)

    def run(self) -> None:
        self.refresh_netns_map()
        print(f"netns map: {len(self.netns_map)} containers found", flush=True)
        while True:
            self.refresh_netns_map()
            self.run_btrace()


def main() -> None:
    Loader().run()


if __name__ == "__main__":
    main()
