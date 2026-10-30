"""Web dashboard server (Python standard library only).
Run:  python server.py [port]      then open http://localhost:8080
The browser sends log text to this server; the Python regexes in
access_log_analyzer.py do all the matching and the result is shown as a dashboard.
"""
import json, sys, os
from http.server import BaseHTTPRequestHandler, HTTPServer
import access_log_analyzer as core

HERE = os.path.dirname(os.path.abspath(__file__))
def read(name): return open(os.path.join(HERE, name), encoding="utf-8").read()

class H(BaseHTTPRequestHandler):
    def send(self, body, ctype="application/json", code=200):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"): self.send(read("dashboard.html"), "text/html")
        elif self.path == "/api/sample": self.send(json.dumps({"text": read("access.log")}))
        elif self.path == "/api/regexes": self.send(json.dumps(core.REGEXES))
        else: self.send(json.dumps({"error": "not found"}), code=404)

    def do_POST(self):
        try:
            data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if self.path == "/api/analyze": out = core.analyze_text(data.get("text", ""))
            elif self.path == "/api/check": out = core.check_data(data.get("line", ""))
            else: return self.send(json.dumps({"error": "not found"}), code=404)
            self.send(json.dumps(out))
        except Exception as e:
            self.send(json.dumps({"error": str(e)}), code=400)

    def log_message(self, fmt, *a): print("[server]", fmt % a)

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"Dashboard running at http://localhost:{port}  (Ctrl+C to stop)")
    HTTPServer(("", port), H).serve_forever()
