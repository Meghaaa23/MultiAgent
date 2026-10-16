# ============================================================================
# Multi-Agent RAG System - Dockerfile
# ============================================================================

FROM python:3.11-slim-bookworm

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DEBIAN_FRONTEND=noninteractive \
    TRANSFORMERS_CACHE=/tmp/hf_cache \
    HF_HOME=/tmp/hf_cache \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ---- System dependencies ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    wget \
    # Playwright / Chromium dependencies
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libatspi2.0-0 \
    libxshmfence1 \
    libglib2.0-0 \
    libx11-xcb1 \
    libxcb-dri3-0 \
    fonts-liberation \
    fonts-noto-color-emoji \
    # Audio processing
    ffmpeg \
    # OCR
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

# ---- Python dependencies ----
# Install from the fully-pinned lock for a deterministic, reproducible build.
# requirements.txt is the human-maintained intent; requirements.lock.txt is the
# resolved transitive set (regenerate with `pip freeze` after changing intent).
COPY requirements.txt requirements.lock.txt ./
RUN pip install --upgrade pip && \
    pip install --no-deps -r requirements.lock.txt

# ---- Install Playwright Chromium ----
RUN playwright install chromium && \
    # Clean up caches to reduce image size
    rm -rf /root/.cache /tmp/pip-* /tmp/hf_cache

# ---- Application code ----

COPY . .

# ---- Non-root hardening (F7) ----
# Run the backend as a dedicated unprivileged user. The application code in
# /app and the browsers in /ms-playwright stay root-owned and are only read /
# executed by this user (no write needed there). All runtime writes — the
# Chromium/Playwright profile + temp files, the HuggingFace cache, and the
# scanner's ~/.cache and ~/.multiagent state — are directed under /tmp, which
# the compose file mounts as a writable tmpfs so the root filesystem can be
# read-only. HOME/XDG are set only now so earlier build steps still use /root.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app \
         --no-create-home --home-dir /tmp --shell /usr/sbin/nologin app
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    XDG_CONFIG_HOME=/tmp/.config

USER app

# ---- Health check ----
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["python", "main.py"]