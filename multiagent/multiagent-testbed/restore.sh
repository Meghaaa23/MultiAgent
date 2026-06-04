#!/usr/bin/env bash
# restore.sh — restore a snapshot to bring testbed back to clean state
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAPSHOT_DIR="$SCRIPT_DIR/snapshots"

if [[ -z "${1:-}" ]]; then
  echo "Usage: $0 <snapshot_name>"
  echo "Available snapshots:"
  ls "$SNAPSHOT_DIR" 2>/dev/null || echo "  (none)"
  exit 1
fi

NAME="$1"
[[ -d "$SNAPSHOT_DIR/$NAME" ]] || { echo "Snapshot not found: $NAME"; exit 1; }

echo "[restore] Stopping all containers..."
cd "$SCRIPT_DIR" && docker compose down 2>/dev/null || true

echo "[restore] Restoring volumes from $NAME..."
for ARCHIVE in "$SNAPSHOT_DIR/$NAME"/*.tar.gz; do
  VOL="$(basename "$ARCHIVE" .tar.gz)"
  echo "  → $VOL"
  docker volume create "$VOL" 2>/dev/null || true
  docker run --rm -v "${VOL}:/data" -v "$SNAPSHOT_DIR/$NAME:/backup" \
    alpine sh -c "rm -rf /data/* /data/..?* /data/.[!.]* 2>/dev/null; tar xzf /backup/$(basename "$ARCHIVE") -C /data"
done

echo "[restore] Restarting testbed..."
docker compose up -d
echo "[restore] Done. Testbed restored to: $NAME"
