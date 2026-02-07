from flask import Flask, jsonify
import os
app = Flask(__name__)


@app.route('/', methods=['GET'])
def home():
    return "Welcome to the Future! (Under Construction)"


@app.route('/flag', methods=["GET"])
def flag():
    flag_path = os.path.join(os.path.dirname(__file__), 'flag.txt')
    try:
        with open(flag_path, 'r') as f:
            flag_content = f.read().strip()
        return jsonify({"flag": flag_content})
    except Exception as e:
        return jsonify({"error": "Flag not found"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)