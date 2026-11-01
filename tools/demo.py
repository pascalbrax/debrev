#!/usr/bin/python3
"""Build a throw-away demo instance (example.com data only) and serve its web interface over plain HTTP.

    tools/demo.py [DIR] [PORT]        # default: /tmp/debrev-demo on 127.0.0.1:8099, login demo / demo-password-1

Used to take the screenshots in docs/screenshots. It never touches /etc, /var or any real state: everything lives
below DIR (the same DEBREV_ROOT switch the tests use).
"""
import json
import os
import random
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/debrev-demo")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8099
APP = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP))
os.environ["DEBREV_ROOT"] = str(ROOT)
os.environ.setdefault("DEBREV_AUTHOR", "demo")

HOSTS = [  # domain, upstream, extra args, days of certificate left
    ("app.example.com", "http://127.0.0.1:9001", ["--websockets"], 71),
    ("blog.example.com", "http://127.0.0.1:9002", ["--cache"], 58),
    ("files.example.com", "http://127.0.0.1:9003", [], 80),
    ("grafana.example.com", "http://127.0.0.1:9004", [], 9),
    ("wiki.example.com", "http://127.0.0.1:9006", [], 64),
    ("legacy.example.com", "http://127.0.0.1:9005", [], 33),
]
LIVE_PORTS = (9001, 9002, 9003, 9004, 9006)


def cli(*args):
    subprocess.run([sys.executable, "-m", "debrev", *args], check=True, cwd=APP, capture_output=True,
                   env={**os.environ, "PATH": os.environ["PATH"] + ":/usr/sbin:/sbin", "GIT_AUTHOR_NAME": "demo", "GIT_AUTHOR_EMAIL": "demo@example.com",
                        "GIT_COMMITTER_NAME": "demo", "GIT_COMMITTER_EMAIL": "demo@example.com"})


def build():
    from debrev import auth, traffic
    from debrev.paths import Paths
    p = Paths.from_env()
    if ROOT.exists():
        subprocess.run(["rm", "-rf", str(ROOT)], check=True)
    for d in (p.etc, p.lib, p.letsencrypt, p.access_log.parent):
        d.mkdir(parents=True, exist_ok=True)
    cli("init")
    for dom, up, extra, days in HOSTS:
        cli("host", "add", dom, up, *extra)
        d = p.certs_dir / dom
        d.mkdir(parents=True, exist_ok=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", str(days), "-subj", f"/CN={dom}",
                        "-addext", f"subjectAltName=DNS:{dom}", "-keyout", str(d / "privkey.pem"),
                        "-out", str(d / "fullchain.pem")], check=True, capture_output=True)
    auth.add_user(p, "demo", "demo-password-1")
    from debrev import node
    node.save(p, node.Node(name="proxy-a"))
    cli("cluster", "set", "--vip", "192.168.1.100")
    try:
        cli("apply")                                       # makes the "live version" match; needs nginx, optional
    except subprocess.CalledProcessError:
        pass

    # a day of synthetic traffic, written as nginx's JSON access log and counted the normal way
    rnd = random.Random(7)
    now = time.time()
    doms = [h[0] for h in HOSTS]
    weight = [30, 22, 18, 5, 6, 2]
    ua = ["Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Safari/605.1",
          "curl/8.5.0", "Mozilla/5.0 (compatible; Googlebot/2.1)"]
    paths = ["/", "/index.html", "/api/items", "/static/app.js", "/login", "/feed.xml", "/dashboard", "/api/status"]
    lines = []
    for i in range(14000):
        t = now - rnd.random() ** 0.8 * 86400
        host = rnd.choices(doms, weight)[0]
        ip = rnd.choice(["198.51.100.%d" % rnd.randint(2, 40), "203.0.113.%d" % rnd.randint(2, 20), "192.0.2.%d" % rnd.randint(2, 9)])
        s = rnd.choices([200, 304, 301, 404, 502, 500], [80, 10, 3, 4, 2, .3])[0]
        if host == "legacy.example.com":
            s = 502
        lines.append(json.dumps({"t": round(t, 3), "ip": ip, "host": host, "m": "GET", "u": rnd.choice(paths), "s": s,
                                 "b": rnd.randint(300, 90000), "rt": round(rnd.random() ** 3, 3), "us": str(s),
                                 "ua": rnd.choice(ua)}))
    scan = "203.0.113.99"                                  # one noisy scanner, partly rate limited
    for i in range(900):
        t = now - rnd.random() * 7200
        lines.append(json.dumps({"t": round(t, 3), "ip": scan, "host": "app.example.com", "m": "GET",
                                 "u": rnd.choice(["/wp-login.php", "/.env", "/admin", "/xmlrpc.php"]),
                                 "s": rnd.choice([429, 429, 429, 404]), "b": 150, "rt": 0.0, "us": "-", "ua": "python-requests/2.31"}))
    lines.sort(key=lambda l: json.loads(l)["t"])
    p.access_log.write_text("\n".join(lines) + "\n")
    traffic.collect(p)
    return p


def backends():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a):
            pass
    for port in LIVE_PORTS:
        srv = HTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()


def fake_address():
    """The dashboard shows the machine's outgoing address; show a documentation-style one instead."""
    orig = socket.socket.getsockname
    socket.socket.getsockname = lambda self: ("192.168.1.10", 0) if self.type == socket.SOCK_DGRAM else orig(self)


if __name__ == "__main__":
    p = build()
    fake_address()
    backends()
    import uvicorn
    from debrev import web
    print(f"demo on http://127.0.0.1:{PORT}  login: demo / demo-password-1", flush=True)
    uvicorn.run(web.create_app(p, secure_cookie=False), host="127.0.0.1", port=PORT, log_level="warning")
