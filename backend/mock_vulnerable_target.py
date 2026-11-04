"""
Orion Security Platform — Benchmark Local Test Target Server.

PURPOSE: An intentionally vulnerable, isolated HTTP server for developer testing
and end-to-end scanner validation. Simulates real-world OWASP Top 10 vulnerabilities:
- Missing security headers (HSTS, CSP, X-Frame-Options)
- Exposed server banners & WordPress CMS signatures
- Multiple pages, forms, and JavaScript bundles
- Leaked credentials in frontend code
- Insecure CORS configuration with credentials
- Exposed administrative and environment files
- IDOR / BOLA endpoint logic
"""
from __future__ import annotations

import http.server
import socketserver
import threading
from typing import Optional

PORT = 8888


class VulnerableHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Deliberately expose server banner and omit HSTS/CSP
        self.send_header("Server", "nginx/1.18.0 (Ubuntu)")
        # Insecure CORS reflecting any Origin
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        # 1. Exposed .env file
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASSWORD=supersecret_db_pass_123\nAWS_SECRET=AKIAIOSFODNN7EXAMPLE\n")
            return

        # 2. Exposed JS bundle with leaked credentials and hidden endpoints
        if self.path.startswith("/static/bundle.js"):
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            fake_fb = "AIza" + "SyD-fakeGoogleKey1234567890abcdefX1"
            fake_stripe = "sk_" + "live_51Abcdefghijklmnopqrstuv"
            js_content = f"""
            // Frontend Core Application Bundle
            const CONFIG = {{
                apiBase: "/api/v1",
                firebaseKey: "{fake_fb}",
                stripePublic: "{fake_stripe}",
            }};
            function fetchUsers() {{
                return fetch("/api/v1/users");
            }}
            function getAdminDashboard() {{
                return fetch("/internal/admin/settings");
            }}
            """
            self.wfile.write(js_content.encode("utf-8"))
            return

        # 3. IDOR Endpoints: /api/v1/users/1 vs /api/v1/users/2
        if self.path.startswith("/api/v1/users/"):
            user_id = self.path.split("/")[-1]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if user_id == "1":
                self.wfile.write(b'{"id": 1, "username": "admin", "email": "admin@orion-sec.local", "role": "superadmin"}')
            else:
                self.wfile.write(f'{{"id": {user_id}, "username": "victim_{user_id}", "email": "user{user_id}@orion-sec.local", "role": "user"}}'.encode("utf-8"))
            return

        # 4. Search endpoint (Reflection / XSS test)
        if self.path.startswith("/search"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            query = self.path.split("q=")[-1] if "q=" in self.path else ""
            html = f"""<!DOCTYPE html>
            <html>
            <head><title>Search Results</title></head>
            <body>
                <h1>Search Results for: {query}</h1>
                <p>No products matched your query.</p>
                <a href="/">Back to Home</a>
            </body>
            </html>"""
            self.wfile.write(html.encode("utf-8"))
            return

        # 5. Login form
        if self.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html = """<!DOCTYPE html>
            <html>
            <head><title>Sign In</title></head>
            <body>
                <form action="/login" method="POST">
                    <label>Username: <input type="text" name="username" /></label>
                    <label>Password: <input type="password" name="password" /></label>
                    <button type="submit">Login</button>
                </form>
            </body>
            </html>"""
            self.wfile.write(html.encode("utf-8"))
            return

        # 6. Default Homepage with WordPress signature, navigation, forms, and bundle script
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        html = """<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="generator" content="WordPress 6.4.2" />
            <title>Orion Security Benchmark Application</title>
            <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
        </head>
        <body>
            <header>
                <h1>Orion Benchmark Target v1.0</h1>
                <nav>
                    <a href="/login">User Login</a> |
                    <a href="/search?q=test">Search Catalog</a> |
                    <a href="/api/v1/users/1">My Profile</a> |
                    <a href="/wp-admin/">Admin Portal</a>
                </nav>
            </header>
            <main>
                <p>Welcome to the Orion Security benchmark testbed application.</p>
                <form action="/search" method="GET">
                    <input type="text" name="q" placeholder="Search articles..." />
                    <button type="submit">Search</button>
                </form>
            </main>
            <script src="/static/bundle.js"></script>
        </body>
        </html>"""
        self.wfile.write(html.encode("utf-8"))


class TargetServer:
    def __init__(self, port: int = PORT):
        self.port = port
        self.httpd: Optional[socketserver.TCPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        socketserver.TCPServer.allow_reuse_address = True
        self.httpd = socketserver.TCPServer(("127.0.0.1", self.port), VulnerableHTTPHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        print(f"[TESTBED] Benchmark Vulnerable Target started at http://127.0.0.1:{self.port}/")

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            print("[TESTBED] Target server stopped.")


if __name__ == "__main__":
    server = TargetServer()
    server.start()
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()

