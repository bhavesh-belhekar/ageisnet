#!/usr/bin/env bash
set -euo pipefail

SCRIPTS_DIR="/attacks/scripts"

usage() {
    cat <<EOF
ml-test-sim — ML detection validation traffic generator

This container has a non-blacklisted IP, so it can test ML-only
detections (flow_model, graph_model) without RULE-001 interference.

Usage:
  docker compose run --rm ml-test-sim <scenario>      Run a single scenario
  docker compose run --rm ml-test-sim --all            Run all scenarios
  docker compose run --rm ml-test-sim --list           List available scenarios
  docker compose run --rm ml-test-sim                  Interactive mode

Scenarios:
  exfiltration     Large outbound data transfer (flow_model / T1041)
EOF
}

list_scenarios() {
    echo "Available scenarios:"
    for f in "$SCRIPTS_DIR"/*.py; do
        [ -f "$f" ] || continue
        name=$(basename "$f" .py)
        [ "$name" = "__init__" ] && continue
        echo "  $name"
    done
}

run_scenario() {
    local scenario="$1"
    local script="$SCRIPTS_DIR/${scenario}.py"

    if [ ! -f "$script" ]; then
        echo "[ERROR] Scenario '$scenario' not found at $script"
        echo "Run with --list to see available scenarios."
        return 1
    fi

    echo "=========================================="
    echo "  Running: $scenario"
    echo "=========================================="
    (cd /attacks && python3 "$script")
    local rc=$?
    if [ $rc -eq 0 ]; then
        echo "[OK] $scenario completed successfully"
    else
        echo "[FAIL] $scenario exited with code $rc"
    fi
    return $rc
}

run_all() {
    local failed=0
    for f in "$SCRIPTS_DIR"/*.py; do
        [ -f "$f" ] || continue
        name=$(basename "$f" .py)
        [ "$name" = "__init__" ] && continue
        run_scenario "$name" || failed=$((failed + 1))
        echo ""
        sleep 2
    done
    echo "=========================================="
    if [ $failed -eq 0 ]; then
        echo "  All scenarios completed successfully"
    else
        echo "  $failed scenario(s) failed"
    fi
    echo "=========================================="
}

interactive_mode() {
    echo "ml-test-sim interactive mode"
    echo "Type a scenario name to run it, 'list' to see available, 'quit' to exit."
    echo ""
    while true; do
        printf "ml-test-sim> "
        read -r cmd || break
        cmd=$(echo "$cmd" | xargs)
        [ -z "$cmd" ] && continue
        case "$cmd" in
            quit|exit|q)
                echo "Exiting."
                break
                ;;
            list|ls)
                list_scenarios
                ;;
            all)
                run_all
                ;;
            *)
                run_scenario "$cmd"
                ;;
        esac
        echo ""
    done
}

# --- Main ---

if [ $# -eq 0 ]; then
    interactive_mode
    exit 0
fi

case "$1" in
    --all|-a)
        run_all
        ;;
    --list|-l)
        list_scenarios
        ;;
    --help|-h)
        usage
        ;;
    *)
        run_scenario "$1"
        ;;
esac
