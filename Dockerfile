# InfoShield — Root Dockerfile for Render / Cloud Hosting
FROM python:3.11-slim

# System dependencies: Tesseract OCR, ZBar (barcodes), OpenCV runtime libs, curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libzbar0 \
    libgl1 \
    libglib2.0-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application, including ML models and data dictionaries
COPY backend /app

# Ensure writable temporary directories for ephemeral processing
ENV UPLOAD_DIR=/tmp/infoshield/uploads
ENV OUTPUT_DIR=/tmp/infoshield/outputs
RUN mkdir -p /tmp/infoshield/uploads /tmp/infoshield/outputs

# Default production environment
ENV ENV=production
ENV HOST=0.0.0.0
ENV PORT=8000
EXPOSE 8000

# Health check to ensure service responds
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/api/health || exit 1

# Production startup using uvicorn listening on the dynamically assigned cloud PORT
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000}"]
