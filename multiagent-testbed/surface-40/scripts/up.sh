#!/usr/bin/env bash
# Bring up one SURFACE-40 group (or all).
# Usage: ./scripts/up.sh [conventional|ai|chatbot|fake-ai|all|infra]
set -euo pipefail
cd "$(dirname "$0")/.."
PROFILE="${1:-infra}"

case "$PROFILE" in
  infra)
    docker compose up -d
    ;;
  conventional|ai|chatbot|fake-ai|all)
    docker compose --profile "$PROFILE" up -d
    ;;
  *)
    echo "Usage: $0 [infra|conventional|ai|chatbot|fake-ai|all]" >&2
    exit 1
    ;;
esac

echo
docker compose ps
echo
echo "Targets: $(pwd)/ground_truth/targets.json"
echo "Widget scan URL: http://store.testbed.local:3029  (run scripts/install-hosts.sh first)"
