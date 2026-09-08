#!/usr/bin/env bash
# Optional one-shot pull of every image referenced by the stack.
# Does not start containers. Some images are amd64-only.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose --profile all config --images | sort -u | while read -r img; do
  echo "==> pulling $img"
  docker pull "$img" || echo "WARN: failed to pull $img" >&2
done
