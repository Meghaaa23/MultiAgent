#!/usr/bin/env bash
# snapshot.sh — save current Docker volume state for a clean-reset baseline
set -euo pipefail
SNAPSHOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/snapshots"
TAG="${1:-baseline}"
STAMP="$(date +%Y%m%d_%H%M%S)"
NAME="${TAG}_${STAMP}"
mkdir -p "$SNAPSHOT_DIR/$NAME"

echo "[snapshot] Stopping app containers (keeping DBs up)..."
docker compose stop wordpress joomla drupal opencart prestashop \
  webgoat juiceshop bwapp nodegoat mutillidae \
  dvwa phpbb rest-api strapi directus \
  keycloak grafana gitea nextcloud redmine 2>/dev/null || true

echo "[snapshot] Exporting volumes..."
for VOL in $(docker volume ls --filter "name=testbed" -q); do
  echo "  → $VOL"
  docker run --rm -v "${VOL}:/data" -v "$SNAPSHOT_DIR/$NAME:/backup" \
    alpine tar czf "/backup/${VOL}.tar.gz" -C /data . 2>/dev/null || true
done

docker compose start 2>/dev/null || true
echo "[snapshot] Snapshot saved: snapshots/$NAME"
