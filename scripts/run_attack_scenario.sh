#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 <scenario>"
    echo "Scenarios: port_scan, known_bad_ip, beaconing, lateral_movement, exfiltration"
    echo "Implemented in Phase 7."
}

if [ "$#" -ne 1 ]; then
    usage
    exit 1
fi

SCENARIO="$1"

case "$SCENARIO" in
    port_scan|known_bad_ip|beaconing|lateral_movement|exfiltration)
        echo "Scenario '$SCENARIO' is not implemented yet (Phase 7)."
        ;;
    *)
        usage
        exit 1
        ;;
esac