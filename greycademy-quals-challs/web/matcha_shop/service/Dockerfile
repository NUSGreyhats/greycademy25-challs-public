FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

# Create a non-root user and ensure /data exists and is owned by the user
RUN adduser --disabled-password --gecos '' appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /app /data

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

USER appuser

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
