#!/usr/bin/python3
"""Take the README screenshots of the demo instance (tools/demo.py) with headless Chromium over the DevTools protocol.

    tools/screenshots.py OUTDIR [PORT]      needs: chromium, python3-websocket

Run tools/demo.py first (same DEBREV_ROOT). Pages are captured at 1280 px wide plus one phone-sized view.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import websocket

OUT = Path(sys.argv[1])
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8099
ROOT = os.environ.get("DEBREV_ROOT", "/tmp/debrev-demo")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["DEBREV_ROOT"] = ROOT

PAGES = [("dashboard", "/"), ("hosts", "/hosts"), ("host-edit", "/hosts/app.example.com"),
         ("certificates", "/certs"), ("health", "/health"), ("security", "/security"), ("history", "/history")]


def main():
    from debrev import auth
    from debrev.paths import Paths
    p = Paths.from_env()
    cookie = auth.make_session(p, {"name": "demo", **auth.load_users(p)["demo"]})
    OUT.mkdir(parents=True, exist_ok=True)
    prof = tempfile.mkdtemp()
    ch = subprocess.Popen(["chromium", "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
                           f"--user-data-dir={prof}", "--remote-debugging-port=9333", "about:blank"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9333/json"))
                break
            except OSError:
                time.sleep(0.2)
        ws = websocket.create_connection([t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"], timeout=30)
        n = [0]

        def call(method, **params):
            n[0] += 1
            ws.send(json.dumps({"id": n[0], "method": method, "params": params}))
            while True:
                m = json.loads(ws.recv())
                if m.get("id") == n[0]:
                    return m.get("result", {})

        call("Network.enable")
        call("Network.setCookie", name=auth_cookie(), value=cookie, domain="127.0.0.1", path="/")
        call("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "light"}])

        def shot(name, path, w, h, mobile=False):
            call("Emulation.setDeviceMetricsOverride", width=w, height=h, deviceScaleFactor=1, mobile=mobile)
            call("Page.navigate", url=f"http://127.0.0.1:{PORT}{path}")
            time.sleep(2.5)
            size = call("Page.getLayoutMetrics")["cssContentSize"]
            data = call("Page.captureScreenshot", format="png", captureBeyondViewport=True,
                        clip={"x": 0, "y": 0, "width": w, "height": min(size["height"], 1500 if name == "health" else 2600), "scale": 1})["data"]
            (OUT / f"{name}.png").write_bytes(base64.b64decode(data))
            print("wrote", OUT / f"{name}.png")

        for name, path in PAGES:
            shot(name, path, 1280, 800)
        shot("dashboard-mobile", "/", 390, 800, mobile=True)
    finally:
        ch.terminate()


def auth_cookie():
    from debrev import web
    return web.COOKIE


main()
