from flask import Flask, render_template, request, redirect, url_for, abort
import uuid
import threading
import os
from urllib.parse import urlparse
import socket

app = Flask(__name__)

_results = {}

def _admin_visit(url):
    try:
        admin_host = os.getenv('ADMIN_HOST', 'localhost')
        admin_port = int(os.getenv('ADMIN_PORT', '3001'))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((admin_host, admin_port))
            s.send(url.encode())
    except Exception as e:
        print(f"Failed to notify admin: {e}")

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/battle', methods=['POST'])
def battle():
    name1 = request.form.get('name1', 'Monster 1')
    name2 = request.form.get('name2', 'Monster 2')

    def parse_num(val):
        try:
            n = float(val)
            if n < 0:
                return None
            return n
        except Exception:
            return None

    hp1 = parse_num(request.form.get('hp1'))
    attack1 = parse_num(request.form.get('attack1'))
    hp2 = parse_num(request.form.get('hp2'))
    attack2 = parse_num(request.form.get('attack2'))

    if hp1 is None or attack1 is None or hp2 is None or attack2 is None:
        rid = uuid.uuid4().hex
        _results[rid] = {
            'error': 'Please enter non-negative numbers for HP and Attack for both monsters.',
            'm1': None,
            'm2': None,
            'winner': None,
            'reason': None
        }
        result_url = url_for('battle_result', rid=rid, _external=True)
        return redirect(url_for('battle_result', rid=rid))

    strength1 = hp1 * attack1
    strength2 = hp2 * attack2

    m1 = {'name': name1, 'hp': hp1, 'attack': attack1, 'strength': strength1}
    m2 = {'name': name2, 'hp': hp2, 'attack': attack2, 'strength': strength2}

    if strength1 > strength2:
        winner = name1
        reason = f"{name1} is stronger (hp*attack = {strength1} > {strength2})."
    elif strength2 > strength1:
        winner = name2
        reason = f"{name2} is stronger (hp*attack = {strength2} > {strength1})."
    else:
        if attack1 > attack2:
            winner = name1
            reason = f"{name1} wins tie by higher attack ({attack1} > {attack2})."
        elif attack2 > attack1:
            winner = name2
            reason = f"{name2} wins tie by higher attack ({attack2} > {attack1})."
        elif hp1 > hp2:
            winner = name1
            reason = f"{name1} wins tie by higher HP ({hp1} > {hp2})."
        elif hp2 > hp1:
            winner = name2
            reason = f"{name2} wins tie by higher HP ({hp2} > {hp1})."
        else:
            winner = "It's a tie!"
            reason = 'Both monsters are evenly matched.'

    rid = uuid.uuid4().hex
    _results[rid] = {
        'error': None,
        'm1': m1,
        'm2': m2,
        'winner': winner,
        'reason': reason
    }
    result_url = url_for('battle_result', rid=rid)
    print(f"result url: {result_url}")
    _admin_visit(result_url)
    return redirect(url_for('battle_result', rid=rid))

@app.route('/result/<rid>')
def battle_result(rid):
    data = _results.get(rid)
    if not data:
        abort(404)
    return render_template('result.html', **data)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=31001, use_reloader=False)