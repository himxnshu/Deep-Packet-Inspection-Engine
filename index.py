"""
Vercel Python Entrypoint for Kraken DPI Engine.
File: index.py

Provides WSGI/ASGI and BaseHTTPRequestHandler endpoints for Vercel deployment.
Serves the Interactive DPI Studio Showcase and REST API endpoints.
"""

from http.server import BaseHTTPRequestHandler
import json
import os
import urllib.parse

# Path to public assets and index.html
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_PATH = os.path.join(BASE_DIR, "public", "index.html")

def get_html_content() -> bytes:
    if os.path.exists(HTML_PATH):
        with open(HTML_PATH, "rb") as f:
            return f.read()
    return b"""<!DOCTYPE html>
<html>
<head><title>Kraken DPI Engine</title></head>
<body style="background:#070a13;color:#fff;font-family:sans-serif;padding:40px;text-align:center;">
    <h1>Kraken DPI Engine</h1>
    <p>Please visit GitHub: <a href="https://github.com/himxnshu/Deep-Packet-Inspection-Engine" style="color:#00f5ff;">himxnshu/Deep-Packet-Inspection-Engine</a></p>
</body>
</html>"""


# -----------------------------------------------------------------------------
# 1. WSGI Callable (Standard for Vercel Python Runtime "index:app")
# -----------------------------------------------------------------------------
def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    # API Routes
    if path == "/api/status":
        body = json.dumps({
            "status": "online",
            "engine": "Kraken DPI v2.0",
            "runtime": "Vercel Python Serverless",
            "total_packets": 77,
            "classified_flows": "16 / 27",
            "drop_rate": "7.79%",
            "recommended_host": "Streamlit Community Cloud (share.streamlit.io)"
        }).encode("utf-8")
        status = "200 OK"
        headers = [
            ("Content-Type", "application/json"),
            ("Access-Control-Allow-Origin", "*"),
            ("Content-Length", str(len(body)))
        ]
        start_response(status, headers)
        return [body]

    # Serve static assets or interactive HTML dashboard
    content = get_html_content()
    status = "200 OK"
    headers = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Content-Length", str(len(content))),
        ("Cache-Control", "public, max-age=3600")
    ]
    start_response(status, headers)
    return [content]

# Aliases for WSGI / ASGI runners
application = app


# -----------------------------------------------------------------------------
# 2. BaseHTTPRequestHandler Class (Vercel Serverless Function fallback)
# -----------------------------------------------------------------------------
class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/status":
            data = json.dumps({
                "status": "online",
                "engine": "Kraken DPI v2.0",
                "runtime": "Vercel Python Serverless",
                "total_packets": 77,
                "drop_rate": "7.79%"
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        content = get_html_content()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()


if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    port = 8000
    print(f"Starting test server at http://localhost:{port}")
    httpd = make_server("", port, app)
    httpd.serve_forever()
