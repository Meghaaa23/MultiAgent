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
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# ---- Install Playwright Chromium ----
RUN playwright install chromium && \
    # Clean up caches to reduce image size
    rm -rf /root/.cache /tmp/pip-* /tmp/hf_cache

# ---- Application code ----

COPY . .

# ---- Create required directories ----
RUN mkdir -p uploads knowledge_base /tmp/hf_cache

# ---- Health check ----
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["python", "main.py"]