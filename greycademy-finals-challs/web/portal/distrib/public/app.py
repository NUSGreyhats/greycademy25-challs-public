from flask import render_template, Flask, request, redirect, url_for, jsonify, session
from db import init_db, verify_user, add_user
from utils import validate_host, fetch_url
from functools import wraps
import secrets


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
init_db(app)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = verify_user(username, password)
        if user:
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            add_user(username, password)
            return redirect(url_for('login'))
        except Exception:
            return render_template('register.html', error='Username already exists')
    return render_template('register.html')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    content = None

    if request.method == 'POST' and session.get('role') == 'admin':
        url = request.form.get('target_url', '')

        is_valid, result = validate_host(url)
        if not is_valid:
            content = result
        else:
            try:
                response = fetch_url(result)
                content = response.text
            except Exception:
                content = "Failed to fetch URL"

    return render_template('dashboard.html', username=session.get('username'), role=session.get('role'), content=content)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
