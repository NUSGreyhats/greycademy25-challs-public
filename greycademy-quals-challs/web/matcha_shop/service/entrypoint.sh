#!/bin/sh
set -e

# Ensure DATABASE is set (default to local file)
: "${DATABASE:=matcha_shop.db}"

if [ ! -f "$DATABASE" ]; then
  echo "Initializing database at $DATABASE"
  python - <<PY
import os
# The app reads DATABASE from environment variable, so make sure it's set
from app import init_db
init_db()
PY
fi

exec gunicorn --bind 0.0.0.0:8000 --workers=9 --threads=4 app:app
