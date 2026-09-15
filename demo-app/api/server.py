"""Demo API server — realistic multi-service application for traffic generation.

Generates observable network traffic between demo-web, demo-api, and demo-db
that the eBPF agent can capture.  Endpoints simulate a small e-commerce API:
users, products, orders, and a health-check that pings the database.

No external dependencies — stdlib only (asyncio + http.server + psycopg2
would be ideal, but we keep it minimal with sqlite for the in-memory store
and direct TCP to postgres for the DB health check).
"""

from __future__ import annotations

import json
import logging
import os
import random
import socket
import sqlite3
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("demo-api")

DB_HOST = os.environ.get("DEMO_DB_HOST", "demo-db")
DB_PORT = int(os.environ.get("DEMO_DB_PORT", "5432"))
LISTEN_PORT = int(os.environ.get("DEMO_API_PORT", "5000"))

# ---------------------------------------------------------------------------
# In-memory SQLite store (realistic-looking data for the demo)
# ---------------------------------------------------------------------------

_db: sqlite3.Connection | None = None


def _init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL DEFAULT 100
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            total REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL
        );
    """)

    # Seed realistic data
    users = [
        ("alice", "alice@example.com", "admin"),
        ("bob", "bob@example.com", "user"),
        ("charlie", "charlie@example.com", "user"),
        ("diana", "diana@example.com", "user"),
        ("eve", "eve@example.com", "user"),
    ]
    now = datetime.now(timezone.utc).isoformat()
    for uname, email, role in users:
        cur.execute(
            "INSERT INTO users (username, email, role, created_at) VALUES (?, ?, ?, ?)",
            (uname, email, role, now),
        )

    products = [
        ("Widget A", 29.99, 150),
        ("Widget B", 49.99, 80),
        ("Gadget X", 99.99, 45),
        ("Gadget Y", 149.99, 30),
        ("Thingamajig", 19.99, 200),
    ]
    for name, price, stock in products:
        cur.execute(
            "INSERT INTO products (name, price, stock) VALUES (?, ?, ?)",
            (name, price, stock),
        )

    # Seed some historical orders
    for _ in range(25):
        uid = random.randint(1, 5)
        pid = random.randint(1, 5)
        qty = random.randint(1, 5)
        price = conn.execute("SELECT price FROM products WHERE id = ?", (pid,)).fetchone()[0]
        cur.execute(
            "INSERT INTO orders (user_id, product_id, quantity, total, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (uid, pid, qty, qty * price, random.choice(["pending", "shipped", "delivered"]), now),
        )

    conn.commit()
    logger.info("initialized in-memory store: 5 users, 5 products, 25 orders")
    return conn


def _get_db() -> sqlite3.Connection:
    global _db
    if _db is None:
        _db = _init_db()
    return _db


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class DemoAPIHandler(BaseHTTPRequestHandler):
    """Routes requests to realistic e-commerce endpoints."""

    def log_message(self, fmt, *args):  # noqa: ARG002
        # Suppress default access log — we log ourselves
        pass

    def _json(self, code: int, data: object) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    # ---- Routes ----

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path == "/health":
            return self._handle_health()
        if path == "/api/users":
            return self._handle_list_users()
        if path == "/api/products":
            return self._handle_list_products()
        if path.startswith("/api/orders"):
            return self._handle_list_orders()
        if path == "/api/stats":
            return self._handle_stats()

        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]

        if path == "/api/orders":
            return self._handle_create_order()

        self._json(404, {"error": "not_found"})

    # ---- Endpoint implementations ----

    def _handle_health(self) -> None:
        """Health check — pings postgres to generate DB traffic."""
        db_ok = False
        try:
            sock = socket.create_connection((DB_HOST, DB_PORT), timeout=2)
            sock.close()
            db_ok = True
        except OSError:
            pass
        self._json(200, {
            "status": "healthy" if db_ok else "degraded",
            "db_connected": db_ok,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def _handle_list_users(self) -> None:
        db = _get_db()
        rows = db.execute("SELECT id, username, email, role FROM users").fetchall()
        self._json(200, [dict(r) for r in rows])

    def _handle_list_products(self) -> None:
        db = _get_db()
        rows = db.execute("SELECT id, name, price, stock FROM products").fetchall()
        self._json(200, [dict(r) for r in rows])

    def _handle_list_orders(self) -> None:
        db = _get_db()
        rows = db.execute(
            "SELECT o.id, u.username, p.name as product, o.quantity, o.total, o.status "
            "FROM orders o JOIN users u ON o.user_id = u.id JOIN products p ON o.product_id = p.id "
            "ORDER BY o.id DESC LIMIT 50"
        ).fetchall()
        self._json(200, [dict(r) for r in rows])

    def _handle_create_order(self) -> None:
        body = self._read_body()
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return self._json(400, {"error": "invalid_json"})

        user_id = data.get("user_id")
        product_id = data.get("product_id")
        quantity = data.get("quantity", 1)

        if not user_id or not product_id:
            return self._json(400, {"error": "missing_fields"})

        db = _get_db()
        product = db.execute("SELECT price FROM products WHERE id = ?", (product_id,)).fetchone()
        if not product:
            return self._json(404, {"error": "product_not_found"})

        total = product[0] * quantity
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO orders (user_id, product_id, quantity, total, status, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?)",
            (user_id, product_id, quantity, total, now),
        )
        db.commit()
        self._json(201, {"order_id": cur.lastrowid, "total": total})

    def _handle_stats(self) -> None:
        """Aggregate stats — generates a heavier DB query for observable traffic."""
        db = _get_db()
        stats = {
            "total_orders": db.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
            "total_users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "total_products": db.execute("SELECT COUNT(*) FROM products").fetchone()[0],
            "revenue": db.execute("SELECT COALESCE(SUM(total), 0) FROM orders WHERE status != 'cancelled'").fetchone()[0],
        }
        self._json(200, stats)


# ---------------------------------------------------------------------------
# Background traffic generator — simulates ongoing user activity
# ---------------------------------------------------------------------------

def _background_traffic():
    """Periodically hit endpoints to simulate ongoing user activity."""
    import urllib.request

    time.sleep(5)  # let services start up
    while True:
        try:
            # Random user browsing
            urllib.request.urlopen("http://localhost:5000/api/products", timeout=3)
            time.sleep(random.uniform(1, 3))

            # Occasional order creation
            uid = random.randint(1, 5)
            pid = random.randint(1, 5)
            qty = random.randint(1, 3)
            req = urllib.request.Request(
                "http://localhost:5000/api/orders",
                data=json.dumps({"user_id": uid, "product_id": pid, "quantity": qty}).encode(),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=3)
            time.sleep(random.uniform(2, 5))

            # Health check
            urllib.request.urlopen("http://localhost:5000/health", timeout=3)
            time.sleep(random.uniform(3, 8))
        except Exception:
            time.sleep(5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    server = HTTPServer(("0.0.0.0", LISTEN_PORT), DemoAPIHandler)
    logger.info("demo-api listening on port %d", LISTEN_PORT)

    # Start background traffic generator in a daemon thread
    traffic_thread = Thread(target=_background_traffic, daemon=True)
    traffic_thread.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("demo-api shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
