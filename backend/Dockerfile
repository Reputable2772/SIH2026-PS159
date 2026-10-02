FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install runtime dependencies: TShark (cli), OpenSSL, tcpdump, curl
RUN apt-get update && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    apt-get install -y --no-install-recommends \
        tshark \
        openssl \
        tcpdump \
        gcc \
        python3-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

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

# Pre-train the ML anomaly detection model into image
RUN python -c "from backend.anomaly.detector import TLSAnomalyDetector; det = TLSAnomalyDetector(); det.train(); det.save()"

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
