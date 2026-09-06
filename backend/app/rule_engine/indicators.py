"""Known-bad indicator loading from threat-intel CSV and risk_policy.yaml."""

from __future__ import annotations

import csv
import logging
import socket
from functools import lru_cache
from pathlib import Path

import yaml

logger = logging.getLogger("rule_engine.indicators")

_CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
_DATA_DIR = Path(__file__).resolve().parents[3] / "data" / "threat_intel"


@lru_cache
def _load_policy() -> dict:
    with open(_CONFIG_DIR / "risk_policy.yaml") as f:
        return yaml.safe_load(f)


@lru_cache
def _load_threat_intel() -> set[str]:
    path = _DATA_DIR / "known_bad_indicators.csv"
    ips: set[str] = set()
    try:
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["type"] == "ip":
                    ips.add(row["indicator"].strip())
        logger.info("loaded %d known-bad IPs from threat intel", len(ips))
    except FileNotFoundError:
        logger.warning("threat intel CSV not found at %s — empty indicator set", path)
    return ips


def _resolve_container_ips(name: str) -> set[str]:
    """Resolve a service/hostname to its container IPs (docker network DNS)."""
    try:
        results = socket.getaddrinfo(name, 5432, type=socket.SOCK_STREAM)
    except OSError as exc:
        logger.warning(
            "could not resolve restricted container %r (%s) — " "rule will not fire against it",
            name,
            exc,
        )
        return set()
    return {info[4][0] for info in results}


def get_known_bad_ips() -> set[str]:
    return _load_threat_intel()


def get_known_bad_ports() -> set[int]:
    return set(_load_policy().get("rules", {}).get("known_bad_ports", []))


def get_restricted_ports() -> set[int]:
    return set(_load_policy().get("rules", {}).get("restricted_ports", []))


def get_restricted_connections() -> list[dict]:
    """Return restricted-connection rules with ``dst_ips`` resolved via DNS."""
    return _resolve_restricted_connections()


@lru_cache
def _resolve_restricted_connections() -> list[dict]:
    rules = _load_policy().get("rules", {}).get("restricted_connections", [])
    resolved = []
    for rule in rules:
        resolved.append(
            {
                "dst_container": rule.get("dst_container"),
                "dst_port": rule.get("dst_port"),
                "dst_ips": _resolve_container_ips(rule.get("dst_container", "")),
                "allowed_sources": set(rule.get("allowed_sources", [])),
                "description": rule.get("description", ""),
            }
        )
    return resolved


def get_port_scan_threshold() -> int:
    return _load_policy().get("rules", {}).get("port_scan_threshold", 10)


def get_port_scan_window_seconds() -> int:
    return _load_policy().get("rules", {}).get("port_scan_window_seconds", 30)
