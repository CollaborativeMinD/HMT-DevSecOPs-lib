# ==============================================================================
# 1. BUILD STAGE: Dependency Compilation & Isolation
# ==============================================================================
FROM python:3.11-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Cache layer optimization for pip dependencies
COPY -v <<EOF requirements.txt
fastapi>=0.100.0
uvicorn[standard]>=0.22.0
kubernetes-asyncio>=24.2.0
redis>=5.0.0
EOF

RUN pip install --no-cache-dir --user -r requirements.txt

# ==============================================================================
# 2. RUNTIME STAGE: Minimal, Distroless-adjacent Hardened Image
# ==============================================================================
FROM python:3.11-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:${PATH}"

# Copy built python packages from the builder stage
COPY --from=builder /root/.local /root/.local
COPY main.py .

# Expose app port for Alertmanager webhooks
EXPOSE 8000

# Run worker process via Uvicorn asynchronous process manager
ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
