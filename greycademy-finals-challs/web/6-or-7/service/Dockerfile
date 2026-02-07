# Use official slim Python image
FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . /app

RUN mv /app/flag.txt /flag-$(openssl rand -hex 5).txt && chmod 444 /flag-*.txt

# Create a non-root user and ensure only /app/data is writable by that user.
RUN groupadd -g 1000 appuser \
    && useradd -m -u 1000 -g appuser -s /usr/sbin/nologin appuser \
    && chown root:root /app \
    && chmod 755 /app \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app/data \
    && chmod 700 /app/data

EXPOSE 5000

USER appuser

CMD ["gunicorn", "-w", "8", "-b", "0.0.0.0:5000", "app:app"]
