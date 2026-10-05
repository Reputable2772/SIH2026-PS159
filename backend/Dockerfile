FROM docker.io/library/python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install runtime dependencies: TShark (cli), OpenSSL, tcpdump, curl
# Disable setuid to avoid permission drops, and disable lua in init.lua to prevent superuser warnings/errors
RUN apt-get update && \
    echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections && \
    apt-get install -y --no-install-recommends \
        tshark \
        openssl \
        tcpdump \
        gcc \
        python3-dev \
        curl \
    && rm -rf /var/lib/apt/lists/* && \
    sed -i 's/disable_lua = false/disable_lua = true/' /usr/share/wireshark/init.lua

WORKDIR /app

# Copy dependency definition
COPY pyproject.toml .

# Install dependencies and project in editable mode
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -e . && \
    pip install --no-cache-dir "uvicorn[standard]"

# Copy source tree and test fixtures
COPY backend/ ./backend/
COPY scripts/ ./scripts/
COPY benchmark/ ./benchmark/
COPY demo_pcaps/ ./demo_pcaps/

# Pre-train the ML anomaly detection model into image and ensure files are globally readable
RUN python -c "from backend.anomaly.detector import TLSAnomalyDetector; det = TLSAnomalyDetector(); det.train(); det.save()" && \
    chmod -R a+rX /app /usr/share/wireshark

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
