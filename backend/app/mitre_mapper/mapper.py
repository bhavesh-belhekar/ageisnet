"""MITRE ATT&CK mapping driven by config/mitre_mapping.yaml.

Provides central resolution of MITRE ATT&CK Tactic and Technique metadata
(Tactic ID, Tactic Name, Technique ID, Technique Name) for rule-based detections,
ML flow anomalies, and graph-based lateral movement detections.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("mitre_mapper")

_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "mitre_mapping.yaml"


@dataclass(frozen=True)
class MitreInfo:
    """Standardized MITRE ATT&CK annotation."""

    technique_id: str | None = None
    technique_name: str | None = None
    tactic_id: str | None = None
    tactic_name: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


@lru_cache(maxsize=1)
def _load_mapping() -> dict[str, Any]:
    """Load and cache the YAML MITRE mapping file."""
    if not _CONFIG_PATH.exists():
        logger.error("MITRE mapping configuration not found at %s", _CONFIG_PATH)
        return {}
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data
    except Exception:
        logger.exception("Failed to load MITRE mapping configuration from %s", _CONFIG_PATH)
        return {}


def clear_mapping_cache() -> None:
    """Clear cached YAML configuration (primarily for test isolation)."""
    _load_mapping.cache_clear()


def get_technique_details(technique_id: str | None) -> MitreInfo | None:
    """Look up canonical technique details by technique ID."""
    if not technique_id:
        return None

    mapping = _load_mapping()
    techniques = mapping.get("techniques", {})
    entry = techniques.get(technique_id)
    if not entry:
        logger.debug("Technique ID %s not found in canonical techniques table", technique_id)
        return MitreInfo(technique_id=technique_id)

    return MitreInfo(
        technique_id=entry.get("technique_id", technique_id),
        technique_name=entry.get("technique_name"),
        tactic_id=entry.get("tactic_id"),
        tactic_name=entry.get("tactic_name"),
    )


def get_mitre_info(detection_category: str, specific_type: str) -> MitreInfo | None:
    """Look up full MITRE ATT&CK metadata for a detection category and specific type.

    Args:
        detection_category: e.g. "rule", "ml", "fallback"
        specific_type: e.g. "known_bad_ip_connection", "graph_lateral_path", "flow_beaconing"

    Returns:
        MitreInfo with technique and tactic metadata, or None if unmapped.
    """
    mapping = _load_mapping()
    detection_types = mapping.get("detection_type_to_technique", {})
    category_map = detection_types.get(detection_category, {})

    technique_id = category_map.get(specific_type)
    if technique_id is None:
        # Check fallback section if not found in category
        fallback_map = detection_types.get("fallback", {})
        technique_id = fallback_map.get(specific_type)

    if technique_id is None:
        return None

    return get_technique_details(technique_id)


def get_mitre_info_by_technique(technique_id: str | None) -> MitreInfo | None:
    """Look up full MITRE ATT&CK metadata directly by technique ID."""
    return get_technique_details(technique_id)


def resolve_mitre(detection_category: str, specific_type: str) -> str | None:
    """Backward-compatible lookup that returns only the technique ID string."""
    info = get_mitre_info(detection_category, specific_type)
    return info.technique_id if info else None
