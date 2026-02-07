from flask import Flask
from db import init_db, create_tables, add_user
import secrets
if __name__ == '__main__':
    app = Flask(__name__)
    init_db(app)

    with app.app_context():
        create_tables(app)
        add_user('admin', secrets.token_hex(16), role='admin')
        print("Database initialized successfully!")
