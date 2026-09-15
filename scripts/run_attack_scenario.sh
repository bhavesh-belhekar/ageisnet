#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <scenario>

Run an AegisNet attack scenario via the attacker-sim container.

Scenarios:
  port_scan        TCP port scan against demo services
  known_bad_ip     Connection to a known-bad IP (from threat intel)
  beaconing        Periodic beacon traffic to an external IP
  lateral_movement SSH-like connections between containers
  exfiltration     Large outbound data transfer

Options:
  --all            Run all scenarios sequentially
  --list           List available scenarios
  -h, --help       Show this help
EOF
}

if [ "$#" -lt 1 ]; then
    usage
    exit 1
fi

case "$1" in
    --help|-h)
        usage
        exit 0
        ;;
    --list|-l)
        docker compose run --rm attacker-sim --list
        ;;
    --all|-a)
        docker compose run --rm attacker-sim --all
        ;;
    *)
        docker compose run --rm attacker-sim "$1"
        ;;
esac
