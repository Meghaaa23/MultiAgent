#!/usr/bin/env bash
# ============================================================================
# Cloud Agent install script — Multi-Agent RAG + AI Security Scanner
# Idempotent: safe to run repeatedly and against cached/partial state.
# ============================================================================
set -euo pipefail

# Resolve repo root (this script lives in <repo>/.cursor/)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# 1. System packages (Python venv + OCR/audio + Chromium runtime libraries)
#    Package names target Ubuntu 24.04 (noble); the *t64 variants replace the
#    pre-noble ABI packages the upstream Dockerfile listed.
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends \
  python3-venv python3-dev \
  tesseract-ocr ffmpeg \
  libnss3 libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 libdrm2 libdbus-1-3 \
  libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 \
  libpango-1.0-0 libcairo2 libasound2t64 libatspi2.0-0t64 libxshmfence1 \
  libglib2.0-0t64 libx11-xcb1 libxcb-dri3-0 \
  fonts-liberation fonts-noto-color-emoji

# ---------------------------------------------------------------------------
# 2. Python backend: virtual environment + pinned dependencies
# ---------------------------------------------------------------------------
if [ ! -x ".venv/bin/python" ]; then
  python3 -m venv .venv
fi
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r multiagent/requirements.txt
# pytest is not pinned in requirements.txt but drives the test suite in tests/.
./.venv/bin/pip install pytest

# Playwright browser used by the web-application scanner agent.
./.venv/bin/python -m playwright install chromium

# ---------------------------------------------------------------------------
# 3. Angular frontend dependencies
# ---------------------------------------------------------------------------
cd "$REPO_ROOT/multi-agent-llm"
npm ci

echo "✓ install complete"
