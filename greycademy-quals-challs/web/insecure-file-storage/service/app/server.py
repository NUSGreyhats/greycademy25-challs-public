from flask import *
import urllib.parse

app = Flask(__name__)

# how this works:
# if a user goes to /download/?file=bucket_list.txt they download files/bucket_list.txt!
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    if '/' in filename or '..' in filename:
        return render_template('deny.html')
    filename = urllib.parse.unquote(filename)
    return send_file(f'./files/{filename}')

@app.route('/')
def index():
    return render_template('welcome.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)