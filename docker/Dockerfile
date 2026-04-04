# VulnScout Pro — Production Dockerfile
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PROJECT_ROOT=/app

WORKDIR /app

# Install system dependencies for PDF generation and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpangocairo-1.0-0 \
    libpango-1.0-0 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements/base.txt .
RUN pip install --no-cache-dir -r base.txt

# Copy application code
COPY . .

# Create data directories with appropriate permissions
RUN mkdir -p data/scans data/reports data/sessions data/logs data/exports data/uploads \
    && chmod -R 750 data

# Expose API port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
