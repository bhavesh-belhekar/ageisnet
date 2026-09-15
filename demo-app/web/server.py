"""Demo web frontend — simulates a realistic e-commerce web application.

Served by nginx; the API proxy routes /api/* and /health to demo-api.
This module generates client-side traffic by periodically fetching
products, creating orders, and displaying them.
"""

import json
import random
import time
import urllib.request
from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread

API_HOST = "demo-api"
API_PORT = 5000


class WebHandler(SimpleHTTPRequestHandler):
    """Serve static files and proxy /api/* to demo-api."""

    def do_GET(self):
        path = self.path.split("?")[0]

        # Proxy API requests
        if path.startswith("/api/") or path == "/health":
            return self._proxy_request("GET")

        # Serve static content
        if path == "/" or path == "/index.html":
            self.path = "/index.html"
            return super().do_GET()

        return super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            return self._proxy_request("POST")
        self.send_error(404)

    def _proxy_request(self, method: str):
        url = f"http://{API_HOST}:{API_PORT}{self.path}"
        body = None
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else None

        try:
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except Exception as e:
            error_body = json.dumps({"error": "proxy_failed", "detail": str(e)}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(error_body)))
            self.end_headers()
            self.wfile.write(error_body)

    def log_message(self, fmt, *args):
        pass  # suppress default logging


def _background_browsing():
    """Simulate a user browsing the storefront — generates continuous traffic."""
    time.sleep(8)
    while True:
        try:
            # Browse products
            urllib.request.urlopen(f"http://localhost:80/api/products", timeout=3)
            time.sleep(random.uniform(2, 6))

            # View stats
            urllib.request.urlopen(f"http://localhost:80/api/stats", timeout=3)
            time.sleep(random.uniform(3, 8))

            # Occasionally place an order
            if random.random() < 0.3:
                uid = random.randint(1, 5)
                pid = random.randint(1, 5)
                qty = random.randint(1, 2)
                req = urllib.request.Request(
                    f"http://localhost:80/api/orders",
                    data=json.dumps({"user_id": uid, "product_id": pid, "quantity": qty}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=3)
                time.sleep(random.uniform(1, 3))
        except Exception:
            time.sleep(5)


def main():
    server = HTTPServer(("0.0.0.0", 80), WebHandler)
    t = Thread(target=_background_browsing, daemon=True)
    t.start()
    server.serve_forever()


if __name__ == "__main__":
    main()
