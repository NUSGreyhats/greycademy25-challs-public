FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y supervisor && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY public/ ./public/
COPY internal/ ./internal/
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN chmod 444 /app/internal/flag.txt

CMD ["sh", "-c", "cd /app/public && python init.py && /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf"]
