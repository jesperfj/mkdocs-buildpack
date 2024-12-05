import os
import base64
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Set your username and password here
USERNAME = "user"
PASSWORD = "password"

# Directory to serve files from
SERVE_DIRECTORY = "site"

class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_HEAD(self):
        self._authenticate()

    def do_GET(self):
        if not self._authenticate():
            return
        super().do_GET()

    def _authenticate(self):
        """Check for proper authentication."""
        auth_header = self.headers.get("Authorization")
        if auth_header is None or not self._is_authorized(auth_header):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Protected"')
            self.end_headers()
            self.wfile.write(b"Authentication required.")
            return False
        return True

    def _is_authorized(self, auth_header):
        """Verify the provided Authorization header."""
        try:
            auth_type, encoded_credentials = auth_header.split(" ", 1)
            if auth_type != "Basic":
                return False
            credentials = base64.b64decode(encoded_credentials).decode("utf-8")
            provided_username, provided_password = credentials.split(":", 1)
            return provided_username == USERNAME and provided_password == PASSWORD
        except Exception:
            return False

def run(server_class=HTTPServer, handler_class=AuthHTTPRequestHandler):
    # Change to the directory to serve files from
    os.chdir(SERVE_DIRECTORY)
    server_address = ("", 8001)  # Serve on all interfaces, port 8000
    httpd = server_class(server_address, handler_class)
    print(f"Serving files from {SERVE_DIRECTORY} on port 8000 with basic authentication...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
