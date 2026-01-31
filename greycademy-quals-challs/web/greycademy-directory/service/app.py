import os
import time
from typing import List, Dict

import psycopg2
import psycopg2.extras
from flask import Flask, render_template, request


app = Flask(__name__)

DB_SETTINGS = {
    "host": os.environ.get("DATABASE_HOST", "db"),
    "port": int(os.environ.get("DATABASE_PORT", 5432)),
    "dbname": os.environ.get("DATABASE_NAME", "directory"),
    "user": os.environ.get("DATABASE_USER", "devuser"),
    "password": os.environ.get("DATABASE_PASSWORD", "devpass"),
}

FLAG = open("flag.txt", "r", encoding="utf-8").read().strip()


def get_conn():
    return psycopg2.connect(**DB_SETTINGS)


def init_db():
    """(Re)seed the demo database with predictable data."""
    attempts = 0
    while attempts < 10:
        try:
            with get_conn() as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute("DROP TABLE IF EXISTS secrets")
                    cur.execute("DROP TABLE IF EXISTS accounts")
                    cur.execute(
                        """
                        CREATE TABLE accounts (
                            id SERIAL PRIMARY KEY,
                            username TEXT UNIQUE NOT NULL,
                            email TEXT NOT NULL
                        )
                        """
                    )
                    cur.execute(
                        """
                        CREATE TABLE secrets (
                            id SERIAL PRIMARY KEY,
                            secret TEXT NOT NULL
                        )
                        """
                    )
                    entries = [
                        ("jinkai", "jinkai@greycademy.local"),
                        ("vincent", "vincent@greycademy.local"),
                        ("elijah5399", "elijah5399@greycademy.local"),
                    ]
                    cur.executemany(
                        "INSERT INTO accounts (username, email) VALUES (%s, %s)",
                        entries,
                    )
                    cur.execute(
                        "INSERT INTO secrets (secret) VALUES (%s)",
                        (FLAG,),
                    )
            return
        except psycopg2.OperationalError:
            attempts += 1
            time.sleep(1)
    raise RuntimeError("Database never came online")


def render_rows(rows: List[Dict]) -> str:
    if not rows:
        return "(empty result set)"
    return "\n".join(repr(dict(row)) for row in rows)


@app.route("/", methods=["GET", "POST"])
def index():
    search_term = ""
    debug_enabled = False
    current_query = ""
    query_error = ""
    query_rows: List[Dict] = []
    raw_result = ""
    search_ran = False

    if request.method == "POST":
        search_ran = True
        search_term = request.form.get("username", "").strip()
        debug_value = request.form.get("debug_mode", "false").lower()
        debug_enabled = debug_value in ("true", "on", "1")

        current_query = (
            "SELECT username, email FROM accounts "
            f"WHERE username LIKE '%{search_term}%'"
        )

        try:
            with get_conn() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                    cur.execute(current_query)
                    records = cur.fetchall()
                    query_rows = [dict(row) for row in records]
                    raw_result = render_rows(query_rows)
        except Exception as exc:  # broad on purpose for the debug panel
            query_error = str(exc)
    else:
        debug_param = request.args.get("debug")
        if debug_param:
            debug_enabled = debug_param.lower() in ("true", "on", "1")

    return render_template(
        "index.html",
        search_term=search_term,
        search_ran=search_ran,
        results=query_rows,
        debug_enabled=debug_enabled,
        current_query=current_query,
        query_error=query_error,
        raw_result=raw_result,
    )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
else:
    # When running under a WSGI server, initialize once at import time.
    init_db()
