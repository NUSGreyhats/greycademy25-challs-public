import os
import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, g
from flask.json import jsonify
import requests

app = Flask(__name__)
DATABASE = os.environ.get('DATABASE', 'matcha_shop.db')

FLAG = open("./flag.txt", "r").read().strip()
assert FLAG != "", "Flag file is empty!"

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY,
                item_name TEXT NOT NULL,
                sweetness TEXT NOT NULL,
                milk_type TEXT NOT NULL,
                ice_level TEXT NOT NULL,
                toppings TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()

MENU_ITEMS = [
    {
        "id": "classic-matcha",
        "name": "Classic Matcha Latte",
        "description": "Premium ceremonial grade matcha with steamed milk.",
        "price": 5.50,
        "image": "img/matcha_latte.png"
    },
    {
        "id": "hojicha-latte",
        "name": "Hojicha Latte",
        "description": "Roasted green tea latte with a nutty, smoky flavor.",
        "price": 5.00,
        "image": "img/hojicha.png"
    },
    {
        "id": "matcha-strawberry",
        "name": "Matcha Strawberry",
        "description": "Creamy matcha blended with fresh strawberries and a touch of sweetness.",
        "price": 5.25,
        "image": "img/matcha_strawberry.png"
    },
    {
        "id": "matcha-float",
        "name": "Matcha Ice Cream Float",
        "description": "Iced matcha latte topped with a scoop of vanilla bean ice cream.",
        "price": 6.50,
        "image": "img/matcha_ice_cream.png"
    }
]

def localhost_only(f):
    def decorated_function(*args, **kwargs):
        if request.remote_addr != '127.0.0.1':
            print("Denied access from non-localhost address:", request.remote_addr)
            return "Access denied", 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html', menu=MENU_ITEMS)

@app.route('/order', methods=['POST'])
def order():
    item_id = request.form.get('item_id')
    item = next((item for item in MENU_ITEMS if item["id"] == item_id), None)
    if not item:
        return redirect(url_for('index'))
    return render_template('order.html', item=item)

@app.route('/submit_order', methods=['POST'])
def submit_order():
    item_name = request.form.get('item_name')
    sweetness = request.form.get('sweetness')
    milk_type = request.form.get('milk_type')
    ice_level = request.form.get('ice_level')
    toppings = ", ".join(request.form.getlist('toppings'))
    
    db = get_db()
    cursor = db.cursor()
    order_id = str(uuid.uuid4())
    cursor.execute('''
        INSERT INTO orders (id, item_name, sweetness, milk_type, ice_level, toppings)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (order_id, item_name, sweetness, milk_type, ice_level, toppings))
    db.commit()
    cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))
    order = cursor.fetchone()
    return render_template('confirmation.html', order=order, flag=FLAG)

@app.route('/confirmation', methods=['POST'])
def confirmation():
    order_id = request.form.get('order_id')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))
    order = cursor.fetchone()
    if not order:
        return redirect(url_for('index'))
    return render_template('confirmation.html', order=order, flag=FLAG)

@app.route('/edit', methods=['POST'])
def edit_order():
    order_id = request.form.get('order_id')
    if not order_id:
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()

    # Save changes
    if request.form.get('save'):
        sweetness = request.form.get('sweetness')
        milk_type = request.form.get('milk_type')
        ice_level = request.form.get('ice_level')

        response = requests.post(f"http://127.0.0.1:8000/backend/edit_order/{order_id}", json={
            "sweetness": sweetness,
            "milk_type": milk_type,
            "ice_level": ice_level,
            "toppings": request.form.getlist('toppings')
        })
        print(response.json())

        return render_template('confirmation.html', order=response.json(), flag=FLAG)

    # Load edit form
    cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))
    order = cursor.fetchone()
    if not order:
        return redirect(url_for('index'))

    toppings_selected = order['toppings'].split(', ') if order['toppings'] else []
    item = next((i for i in MENU_ITEMS if i['name'] == order['item_name']), None)
    return render_template('edit_order.html', order=order, item=item, toppings_selected=toppings_selected)

@localhost_only
@app.route('/backend/edit_order/<order_id>', methods=['POST'])
def backend_edit_order(order_id):
    db = get_db()
    cursor = db.cursor()

    data = request.get_json()

    sweetness = data.get('sweetness')
    milk_type = data.get('milk_type')
    ice_level = data.get('ice_level')
    toppings = ", ".join(data.get('toppings', []))

    cursor.execute('''
        UPDATE orders SET sweetness=?, milk_type=?, ice_level=?, toppings=?
        WHERE id = ?
    ''', (sweetness, milk_type, ice_level, toppings, order_id))
    db.commit()

    updated_order = dict(cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,)).fetchone())
    return jsonify(updated_order), 200

@localhost_only
@app.route('/backend/confirm_payment/<order_id>', methods=['POST'])
def backend_confirm_payment(order_id):
    db = get_db()
    cursor = db.cursor()

    cursor.execute('''
        UPDATE orders SET status='paid'
        WHERE id = ?
    ''', (order_id,))
    db.commit()

    updated_order = dict(cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,)).fetchone())
    return jsonify(updated_order), 200


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
