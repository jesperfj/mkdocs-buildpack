import os
import base64
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Set your username and password here
USERNAME = os.getenv("HTTP_BASIC_AUTH_USER")
PASSWORD = os.getenv("HTTP_BASIC_AUTH_PASSWORD")

# Directory to serve files from
SERVE_DIRECTORY = os.getenv("SERVER_DIRECTORY", "site")

# Default port
DEFAULT_PORT = 8001

class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_HEAD(self):
        self._handle_redirect()
        self._authenticate()

    def do_GET(self):
        if self._handle_redirect():
            return
        if not self._authenticate():
            return
        super().do_GET()

    def _handle_redirect(self):
        """Redirect HTTP requests to HTTPS."""
        if self.headers.get("X-Forwarded-Proto") != "https":
            host = self.headers.get("Host")
            if host:
                https_url = f"https://{host}{self.path}"
                self.send_response(301)
                self.send_header("Location", https_url)
                self.end_headers()
                self.wfile.write(b"Redirecting to HTTPS...")
            return True
        return False
        
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
    
    # Get the port from the environment variable or use the default
    port = int(os.getenv("PORT", DEFAULT_PORT))
    server_address = ("", port)
    
    httpd = server_class(server_address, handler_class)
    print(f"Serving files from {SERVE_DIRECTORY} on port {port} with basic authentication...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
