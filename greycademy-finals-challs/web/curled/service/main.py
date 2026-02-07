from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
from urllib.parse import parse_qs

import os

FLAG = os.getenv('FLAG', '[FLAG]')

# Read HTML files at startup
with open('./index.html', 'r') as f:
    INDEX_HTML = f.read()

with open('./error.html', 'r') as f:
    ERROR_HTML = f.read()


class RequestHandler(BaseHTTPRequestHandler):
    def version_string(self):
        return 'greycademy'

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(INDEX_HTML.encode())
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(ERROR_HTML.encode())

    def do_POST(self):
        if self.path == '/flag':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 1000:
                self.send_error(413, "Cool, but I ain't reading allat")
                self.end_headers()
                return

            body = self.rfile.read(content_length).decode('utf-8')

            try:
                params = parse_qs(body)
                if 'poast' in params and 'flag' in params['poast']:
                    self.send_response(405)
                    self.end_headers()
                    self.wfile.write(b"Did you really think it would be that simple? I'm sorry to have let you down if you actually did.\n\nNow, try again, but maybe send a POAST instead.\n")
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Interesting! Thanks for sharing.\n")
            except:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Where's the poast?\n")
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Are you sure you're at the right place?\n")

    def do_POAST(self):
        if self.path == '/flag':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 1000:
                self.send_error(413, "Cool, but I ain't reading allat")
                self.end_headers()
                return

            body = self.rfile.read(content_length).decode('utf-8')

            try:
                params = parse_qs(body)
                if 'poast' in params and 'flag' in params['poast']:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Thanks for the good poast... Ah, I see you're in search for the flag!\n\nFrom here, HEAD over to /flag with the following token: sesquipedalian\n")
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Did you forget to bring the poast?\n")
            except:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Did you forget to bring the poast?\n")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Oops. It seems like you've ended up in the wrong place.\n")

    def do_HEAD(self):
        if self.path == '/flag':
            auth_header = self.headers.get('Authorization', '')

            if 'sesquipedalian' in auth_header:
                self.send_response(200)
                self.send_header('Flag', FLAG)
                self.end_headers()
                self.wfile.write(b"I hope you got what you were looking for.\n")
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"I will need a correct token for this...\n")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"")

    # Handle any other HTTP methods
    def handle_one_request(self):
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except:
            pass

    # Override to handle custom methods
    def parse_request(self):
        result = BaseHTTPRequestHandler.parse_request(self)
        if result and self.command not in ['GET', 'POST', 'POAST', 'HEAD']:
            self.log_request_custom()
            self.send_response(405)
            self.end_headers()
            self.wfile.write(b"That didn't work. Maybe you want to double check what you're doing?\n")
            return False
        return result


if __name__ == '__main__':
    server = HTTPServer(('', 3000), RequestHandler)
    print('Server running on port 3000...')
    server.serve_forever()
