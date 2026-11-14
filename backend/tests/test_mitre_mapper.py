"""Tests for MITRE ATT&CK mapping and standardization (FR-12)."""

from __future__ import annotations

import pytest

from app.mitre_mapper.mapper import (
    MitreInfo,
    clear_mapping_cache,
    get_mitre_info,
    get_mitre_info_by_technique,
    resolve_mitre,
)


@pytest.fixture(autouse=True)
def _reset_cache():
    clear_mapping_cache()
    yield
    clear_mapping_cache()


def test_rule_mappings_complete():
    """All 4 backend detection rules must map to complete MITRE ATT&CK metadata."""
    # RULE-001: known_bad_ip_connection -> T1071
    r1 = get_mitre_info("rule", "known_bad_ip_connection")
    assert r1 is not None
    assert r1.technique_id == "T1071"
    assert r1.technique_name == "Application Layer Protocol"
    assert r1.tactic_id == "TA0011"
    assert r1.tactic_name == "Command and Control"

    # RULE-002: known_bad_port -> T1043
    r2 = get_mitre_info("rule", "known_bad_port")
    assert r2 is not None
    assert r2.technique_id == "T1043"
    assert r2.technique_name == "Commonly Used Port"
    assert r2.tactic_id == "TA0011"
    assert r2.tactic_name == "Command and Control"

    # RULE-003: port_scan -> T1046
    r3 = get_mitre_info("rule", "port_scan")
    assert r3 is not None
    assert r3.technique_id == "T1046"
    assert r3.technique_name == "Network Service Discovery"
    assert r3.tactic_id == "TA0007"
    assert r3.tactic_name == "Discovery"

    # RULE-004: restricted_protocol -> T1571
    r4 = get_mitre_info("rule", "restricted_protocol")
    assert r4 is not None
    assert r4.technique_id == "T1571"
    assert r4.technique_name == "Non-Standard Port"
    assert r4.tactic_id == "TA0011"
    assert r4.tactic_name == "Command and Control"


def test_ml_flow_mappings():
    """ML flow anomaly subtypes map to specific technique and tactic definitions."""
    # Beaconing -> T1071.001
    beaconing = get_mitre_info("ml", "flow_beaconing")
    assert beaconing is not None
    assert beaconing.technique_id == "T1071.001"
    assert beaconing.technique_name == "Web Protocols"
    assert beaconing.tactic_id == "TA0011"
    assert beaconing.tactic_name == "Command and Control"

    # Exfiltration Spike -> T1041
    exfil = get_mitre_info("ml", "flow_exfiltration_spike")
    assert exfil is not None
    assert exfil.technique_id == "T1041"
    assert exfil.technique_name == "Exfiltration Over C2 Channel"
    assert exfil.tactic_id == "TA0010"
    assert exfil.tactic_name == "Exfiltration"

    # Fallback -> T1071
    fallback = get_mitre_info("fallback", "ml_flow_anomaly")
    assert fallback is not None
    assert fallback.technique_id == "T1071"
    assert fallback.technique_name == "Application Layer Protocol"
    assert fallback.tactic_id == "TA0011"
    assert fallback.tactic_name == "Command and Control"


def test_graph_and_neo4j_mappings():
    """Graph lateral movement and reconnaissance alerts have standardized mappings."""
    # Multi-hop lateral path -> T1021
    lat_path = get_mitre_info("ml", "graph_lateral_path")
    assert lat_path is not None
    assert lat_path.technique_id == "T1021"
    assert lat_path.technique_name == "Remote Services"
    assert lat_path.tactic_id == "TA0008"
    assert lat_path.tactic_name == "Lateral Movement"

    # Internal recon -> T1046
    recon = get_mitre_info("ml", "graph_internal_recon")
    assert recon is not None
    assert recon.technique_id == "T1046"
    assert recon.technique_name == "Network Service Discovery"
    assert recon.tactic_id == "TA0007"
    assert recon.tactic_name == "Discovery"

    # Unseen edge / lateral movement -> T1021
    edge = get_mitre_info("ml", "graph_lateral_movement")
    assert edge is not None
    assert edge.technique_id == "T1021"
    assert edge.technique_name == "Remote Services"
    assert edge.tactic_id == "TA0008"
    assert edge.tactic_name == "Lateral Movement"

    # Sensitive port alone without credential abuse proof -> None
    sensitive = get_mitre_info("ml", "graph_sensitive_port")
    assert sensitive is None


def test_get_mitre_info_by_technique():
    """Direct technique ID resolution correctly returns all 4 fields."""
    info_t1021 = get_mitre_info_by_technique("T1021")
    assert info_t1021 is not None
    assert info_t1021.technique_id == "T1021"
    assert info_t1021.technique_name == "Remote Services"
    assert info_t1021.tactic_id == "TA0008"
    assert info_t1021.tactic_name == "Lateral Movement"

    assert get_mitre_info_by_technique(None) is None
    assert get_mitre_info_by_technique("") is None

    # Unknown technique returns MitreInfo with technique_id only
    unknown = get_mitre_info_by_technique("T9999")
    assert unknown is not None
    assert unknown.technique_id == "T9999"
    assert unknown.technique_name is None
    assert unknown.tactic_id is None
    assert unknown.tactic_name is None


def test_resolve_mitre_backward_compatibility():
    """resolve_mitre returns only the technique ID string."""
    assert resolve_mitre("rule", "known_bad_ip_connection") == "T1071"
    assert resolve_mitre("rule", "known_bad_port") == "T1043"
    assert resolve_mitre("rule", "port_scan") == "T1046"
    assert resolve_mitre("rule", "restricted_protocol") == "T1571"
    assert resolve_mitre("ml", "flow_beaconing") == "T1071.001"
    assert resolve_mitre("ml", "flow_exfiltration_spike") == "T1041"
    assert resolve_mitre("ml", "graph_lateral_path") == "T1021"
    assert resolve_mitre("ml", "graph_sensitive_port") is None
    assert resolve_mitre("unknown", "unknown") is None
