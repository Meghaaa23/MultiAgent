#!/usr/bin/env bash
# Install hostname aliases so SURFACE sees distinct eTLD+1 for third-party widgets.
# Requires sudo. Idempotent.
set -euo pipefail
HOSTS=/etc/hosts
BLOCK_START="# surface-40 testbed"
BLOCK_END="# end surface-40 testbed"
ALIASES=(
  "127.0.0.1 store.testbed.local"
  "127.0.0.1 vendor.chat.local"
  "127.0.0.1 hubspot-embed.testbed.local"
)

if grep -q "$BLOCK_START" "$HOSTS"; then
  echo "surface-40 host aliases already present in $HOSTS"
  exit 0
fi

{
  echo ""
  echo "$BLOCK_START"
  printf '%s\n' "${ALIASES[@]}"
  echo "$BLOCK_END"
} | sudo tee -a "$HOSTS" >/dev/null

echo "Installed:"
printf '  %s\n' "${ALIASES[@]}"
echo "Scan widgets at http://store.testbed.local:3029 (not http://localhost:3029)."
