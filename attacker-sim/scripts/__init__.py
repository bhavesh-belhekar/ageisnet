"""Shared utilities for attack scripts.

Provides common functions for generating network traffic that the eBPF
agent will capture and feed through the AegisNet detection pipeline.
"""

from __future__ import annotations

import socket
import time
import sys


def get_target_host(service: str) -> str:
    """Resolve a service name to its Docker network hostname."""
    return service


def tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    """Attempt a TCP connection; returns True if connected."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def send_data(host: str, port: int, data: bytes, timeout: float = 5.0) -> int:
    """Send raw data over TCP; returns bytes sent."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        # Read response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        return len(response)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"  [!] send_data to {host}:{port} failed: {e}", file=sys.stderr)
        return 0


def http_get(host: str, port: int, path: str = "/", timeout: float = 3.0) -> tuple[int, bytes]:
    """Send an HTTP GET request; returns (status_code, body)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        # Parse status line
        status_line = response.split(b"\r\n")[0]
        status_code = int(status_line.split(b" ")[1])
        body = response.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in response else b""
        return status_code, body
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"  [!] HTTP GET {host}:{port}{path} failed: {e}", file=sys.stderr)
        return 0, b""


def http_post(host: str, port: int, path: str, body: bytes, content_type: str = "application/json", timeout: float = 3.0) -> tuple[int, bytes]:
    """Send an HTTP POST request; returns (status_code, response_body)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body
        sock.sendall(request)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        status_line = response.split(b"\r\n")[0]
        status_code = int(status_line.split(b" ")[1])
        resp_body = response.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in response else b""
        return status_code, resp_body
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"  [!] HTTP POST {host}:{port}{path} failed: {e}", file=sys.stderr)
        return 0, b""


def banner(msg: str) -> None:
    """Print a scenario banner."""
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}\n")


def log(msg: str) -> None:
    """Print a timestamped log line."""
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")
