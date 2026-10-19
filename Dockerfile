# Production Dockerfile for AI Phishing Detector
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PORT=7860 \
    ENABLE_DESKTOP_NOTIFICATIONS=false

WORKDIR /app

# Install minimal build tools required for C-extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install lightweight CPU-only PyTorch first (~180MB vs 2.5GB CUDA)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch>=2.2.0 --index-url https://download.pytorch.org/whl/cpu

# Copy requirements and install remaining Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download and cache BERT model weights into the container image
# This ensures zero cold-start delay and prevents Gunicorn worker startup timeouts
RUN python -c "from transformers import AutoTokenizer, AutoModelForSequenceClassification; name='ealvaradob/bert-finetuned-phishing'; AutoTokenizer.from_pretrained(name); AutoModelForSequenceClassification.from_pretrained(name); print('Model pre-cached successfully!')"

# Copy application source code
COPY . .

# Ensure instance directory exists for SQLite database storage
RUN mkdir -p instance

# Expose port (7860 is default for Hugging Face Spaces; Render/Railway use $PORT)
EXPOSE 7860

# Run with Gunicorn using dynamic PORT binding
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-7860} --timeout 180 --workers 1 --threads 4 app:app"]
