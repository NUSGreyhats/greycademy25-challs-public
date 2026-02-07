from flask_sqlalchemy import SQLAlchemy
import os

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')


def init_db(app):
    user = os.environ.get('MYSQL_USER')
    password = os.environ.get('MYSQL_PASSWORD')
    host = os.environ.get('MYSQL_HOST')
    database = os.environ.get('MYSQL_DATABASE')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{user}:{password}@{host}/{database}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_POOL_RECYCLE'] = 299
    app.config['SQLALCHEMY_POOL_TIMEOUT'] = 20
    db.init_app(app)


def create_tables(app):
    with app.app_context():
        db.create_all()
        db.session.commit()


def add_user(username, password, role='user'):
    user = User(username=username, password=password, role=role)
    db.session.add(user)
    db.session.commit()
    return user


def get_user_by_username(username):
    return User.query.filter_by(username=username).first()


def verify_user(username, password):
    query = f"SELECT username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        result = db.session.execute(db.text(query))
        row = result.fetchone()
        if row:
            return get_user_by_username(username)
        return None
    except Exception:
        db.session.rollback()
        return None


