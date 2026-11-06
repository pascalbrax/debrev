"""Traffic statistics from nginx's JSON access log (written by the global config).

`collect()` reads new log lines (incrementally, run every minute by a timer and before a
page view) into a small SQLite database of per-minute counters; the web page reads those
counters, tails the log for the latest requests, probes the upstreams and derives suggestions.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from html import escape
from urllib.parse import urlsplit

from . import dns
from .paths import Paths

# One JSON object per line; $uri has no query string (tokens in URLs stay out of the statistics).
LOG_FORMAT = ('{"t":$msec,"ip":"$remote_addr","host":"$host","m":"$request_method","u":"$uri",'
              '"s":$status,"b":$body_bytes_sent,"rt":$request_time,"us":"$upstream_status","ua":"$http_user_agent"}')

KEEP_DAYS = 8
CLASSES = ("c2", "c3", "c4", "c429", "c444", "c5")
LABELS = {"c2": "2xx ok", "c3": "3xx redirect", "c4": "4xx client error", "c429": "429 rate limited",
          "c444": "444 dropped", "c5": "5xx server error"}
CHUNK = 32 * 1024 * 1024


def cls(status: int) -> str | None:
    if status == 429:
        return "c429"
    if status == 444:
        return "c444"
    return {2: "c2", 3: "c3", 4: "c4", 5: "c5"}.get(status // 100)


def parse_line(line: str) -> dict | None:
    try:
        d = json.loads(line)
        d["t"], d["s"], d["b"], d["rt"] = float(d["t"]), int(d["s"]), int(d["b"]), float(d["rt"])
        d["ip"], d["host"] = str(d["ip"]), str(d["host"]).lower()
        return d
    except (ValueError, KeyError, TypeError):
        return None


def _db(p: Paths) -> sqlite3.Connection:
    try:
        return _open(p)
    except sqlite3.DatabaseError:          # damaged file: keep it for inspection and start counting afresh
        p.traffic_db.replace(p.traffic_db.with_name(f"traffic.db.corrupt-{int(time.time())}"))
        return _open(p)


def _open(p: Paths) -> sqlite3.Connection:
    db = sqlite3.connect(p.traffic_db, timeout=20)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS minute(ts INTEGER, host TEXT, cls TEXT, n INTEGER, bytes INTEGER, rt REAL, PRIMARY KEY(ts, host, cls));
        CREATE TABLE IF NOT EXISTS ip(hour INTEGER, ip TEXT, n INTEGER, ok INTEGER, bad INTEGER, lim INTEGER, bytes INTEGER, PRIMARY KEY(hour, ip));
        CREATE TABLE IF NOT EXISTS lim(hour INTEGER, host TEXT, ip TEXT, n INTEGER, PRIMARY KEY(hour, host, ip));
    """)
    return db


def collect(p: Paths) -> int:
    """Read new access-log lines into the counters. Returns the number of lines counted."""
    try:
        f = open(p.access_log, "rb")
    except OSError:
        return 0
    with f, _db(p) as db:
        meta = dict(db.execute("SELECT k, v FROM meta"))
        st = os.fstat(f.fileno())
        off = int(meta.get("offset", 0)) if meta.get("inode") == str(st.st_ino) else 0
        if off > st.st_size:
            off = 0
        if st.st_size - off > CHUNK and "offset" not in meta:
            off = st.st_size - CHUNK                      # first run on a huge log: the recent part is enough
        f.seek(off)
        data = f.read(CHUNK)
        end = data.rfind(b"\n")
        if end < 0:
            return 0
        data = data[:end + 1]
        minute, ipt, limt = {}, {}, {}
        n = 0
        for raw in data.splitlines():
            d = parse_line(raw.decode("utf-8", "replace"))
            if not d:
                continue
            c = cls(d["s"])
            if c is None:
                continue
            n += 1
            ts, hour = int(d["t"]) // 60 * 60, int(d["t"]) // 3600 * 3600
            m = minute.setdefault((ts, d["host"], c), [0, 0, 0.0])
            m[0] += 1; m[1] += d["b"]; m[2] += d["rt"]
            i = ipt.setdefault((hour, d["ip"]), [0, 0, 0, 0, 0])
            i[0] += 1; i[4] += d["b"]
            if c in ("c2", "c3"):
                i[1] += 1
            elif c in ("c4", "c444", "c429") and d["s"] != 401:
                i[2] += 1
            if c == "c429":
                i[3] += 1
                limt[(hour, d["host"], d["ip"])] = limt.get((hour, d["host"], d["ip"]), 0) + 1
        db.executemany("INSERT INTO minute VALUES(?,?,?,?,?,?) ON CONFLICT(ts,host,cls) DO UPDATE SET n=n+excluded.n, bytes=bytes+excluded.bytes, rt=rt+excluded.rt",
                       [(*k, *v) for k, v in minute.items()])
        db.executemany("INSERT INTO ip VALUES(?,?,?,?,?,?,?) ON CONFLICT(hour,ip) DO UPDATE SET n=n+excluded.n, ok=ok+excluded.ok, bad=bad+excluded.bad, lim=lim+excluded.lim, bytes=bytes+excluded.bytes",
                       [(k[0], k[1], v[0], v[1], v[2], v[3], v[4]) for k, v in ipt.items()])
        db.executemany("INSERT INTO lim VALUES(?,?,?,?) ON CONFLICT(hour,host,ip) DO UPDATE SET n=n+excluded.n",
                       [(*k, v) for k, v in limt.items()])
        cut = int(time.time()) - KEEP_DAYS * 86400
        for t, col in (("minute", "ts"), ("ip", "hour"), ("lim", "hour")):
            db.execute(f"DELETE FROM {t} WHERE {col} < ?", (cut,))
        db.execute("INSERT OR REPLACE INTO meta VALUES('inode', ?)", (str(st.st_ino),))
        db.execute("INSERT OR REPLACE INTO meta VALUES('offset', ?)", (str(off + len(data)),))
        db.execute("INSERT OR REPLACE INTO meta VALUES('last', ?)", (str(int(time.time())),))
    return n


# ---------------------------------------------------------------- queries
RANGES = {"1h": (3600, 60), "24h": (86400, 1800), "7d": (7 * 86400, 10800)}   # window, bucket seconds


def _since(rng: str, now: float | None = None) -> tuple[int, int, int]:
    window, step = RANGES.get(rng, RANGES["24h"])
    end = int(now or time.time()) // step * step + step
    return end - window - step, end, step


def series(p: Paths, rng: str = "24h", now: float | None = None) -> list[dict]:
    start, end, step = _since(rng, now)
    buckets = {t: {"t": t, "n": 0, "bytes": 0, **{c: 0 for c in CLASSES}} for t in range(start + step, end, step)}
    with _db(p) as db:
        for ts, c, n, b in db.execute("SELECT ts, cls, SUM(n), SUM(bytes) FROM minute WHERE ts >= ? GROUP BY ts, cls", (start,)):
            bk = buckets.get(ts // step * step)
            if bk:
                bk[c] += n; bk["n"] += n; bk["bytes"] += b
    return [buckets[t] for t in sorted(buckets)]


def totals(p: Paths, rng: str = "24h", now: float | None = None) -> dict:
    start, _, _ = _since(rng, now)
    t = {"n": 0, "bytes": 0, "rt": 0.0, **{c: 0 for c in CLASSES}}
    with _db(p) as db:
        for c, n, b, rt in db.execute("SELECT cls, SUM(n), SUM(bytes), SUM(rt) FROM minute WHERE ts >= ? GROUP BY cls", (start,)):
            t[c] += n; t["n"] += n; t["bytes"] += b; t["rt"] += rt
    t["avg_ms"] = round(t["rt"] / t["n"] * 1000) if t["n"] else 0
    return t


def hosts_table(p: Paths, rng: str = "24h", now: float | None = None) -> list[dict]:
    start, _, _ = _since(rng, now)
    rows: dict = {}
    with _db(p) as db:
        for host, c, n, b, rt in db.execute("SELECT host, cls, SUM(n), SUM(bytes), SUM(rt) FROM minute WHERE ts >= ? GROUP BY host, cls", (start,)):
            r = rows.setdefault(host, {"host": host, "n": 0, "bytes": 0, "rt": 0.0, **{x: 0 for x in CLASSES}})
            r[c] += n; r["n"] += n; r["bytes"] += b; r["rt"] += rt
    for r in rows.values():
        r["avg_ms"] = round(r["rt"] / r["n"] * 1000) if r["n"] else 0
    return sorted(rows.values(), key=lambda r: -r["n"])


def ips_table(p: Paths, rng: str = "24h", limit: int = 15, now: float | None = None) -> list[dict]:
    start, _, _ = _since(rng, now)
    with _db(p) as db:
        return [dict(ip=ip, n=n, ok=ok, bad=bad, lim=lim, bytes=b) for ip, n, ok, bad, lim, b in db.execute(
            "SELECT ip, SUM(n), SUM(ok), SUM(bad), SUM(lim), SUM(bytes) FROM ip WHERE hour >= ? GROUP BY ip ORDER BY SUM(n) DESC LIMIT ?",
            (start // 3600 * 3600, limit))]


def limited(p: Paths, rng: str = "24h", now: float | None = None) -> list[dict]:
    """Who hit the rate limit, where, and how much real traffic they also had (hints at legitimate users)."""
    start, _, _ = _since(rng, now)
    with _db(p) as db:
        rows = db.execute("SELECT l.host, l.ip, SUM(l.n) FROM lim l WHERE l.hour >= ? GROUP BY l.host, l.ip", (start // 3600 * 3600,)).fetchall()
        ok = {ip: (o, n) for ip, o, n in db.execute("SELECT ip, SUM(ok), SUM(n) FROM ip WHERE hour >= ? GROUP BY ip", (start // 3600 * 3600,))}
    return [dict(host=h, ip=ip, hits=n, ok=ok.get(ip, (0, 0))[0], total=ok.get(ip, (0, 0))[1]) for h, ip, n in rows]


def hosts_hit_by(p: Paths, ips: list[str], rng: str = "7d", now: float | None = None) -> dict[str, list[dict]]:
    """For each address: the hosts it was rate limited on ({host, hits}), busiest first."""
    if not ips:
        return {}
    start, _, _ = _since(rng, now)
    out: dict[str, list[dict]] = {ip: [] for ip in ips}
    with _db(p) as db:
        q = ",".join("?" * len(ips))
        for host, ip, n in db.execute(f"SELECT host, ip, SUM(n) FROM lim WHERE hour >= ? AND ip IN ({q}) GROUP BY host, ip ORDER BY 3 DESC",
                                      (start // 3600 * 3600, *ips)):
            out[ip].append({"host": host, "hits": n})
    return out


def recent(p: Paths, count: int = 100, only_errors: bool = False) -> list[dict]:
    """The newest requests, read from the end of the access log."""
    try:
        with open(p.access_log, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            got: list[dict] = []
            back = 256 * 1024
            while True:
                f.seek(max(0, size - back))
                lines = f.read().splitlines()
                if size > back:
                    lines = lines[1:]                          # first line is probably cut
                got = [d for d in map(lambda x: parse_line(x.decode("utf-8", "replace")), lines) if d and (not only_errors or d["s"] >= 400)]
                if len(got) >= count or back >= size or back >= 16 * 1024 * 1024:
                    break
                back *= 4
    except OSError:
        return []
    return got[-count:][::-1]


def status(p: Paths) -> dict:
    try:
        with _db(p) as db:
            last = dict(db.execute("SELECT k, v FROM meta")).get("last")
    except sqlite3.Error:
        last = None
    try:
        size = p.access_log.stat().st_size
    except OSError:
        size = None
    return {"log_exists": size is not None, "log_size": size, "last": int(last) if last else None}


# ---------------------------------------------------------------- upstreams
def probe_upstreams(p: Paths, hosts: list[dict], timeout: float = 1.5) -> list[dict]:
    """One TCP connect per distinct backend address; hosts sharing a backend share the result."""
    cache = dns._load(p)

    def target(h):
        u = urlsplit(h["upstream"])
        name = (u.hostname or "").lower()
        port = u.port or (443 if u.scheme == "https" else 80)
        ip = name if dns.is_ip(name) else (cache.get(name) or {}).get("ip")
        return name, port, ip

    def probe(key):
        ip, port = key
        t0 = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return {"up": True, "ms": round((time.monotonic() - t0) * 1000), "error": ""}
        except OSError as e:
            return {"up": False, "ms": None, "error": (e.strerror or str(e))[:60]}

    live = [h for h in hosts if h["enabled"]]
    targets = {h["domain"]: target(h) for h in live}
    keys = sorted({(ip, port) for _n, port, ip in targets.values() if ip})
    with ThreadPoolExecutor(max_workers=16) as ex:
        found = dict(zip(keys, ex.map(probe, keys)))
    rows = []
    for h in live:
        name, port, ip = targets[h["domain"]]
        r = {"domain": h["domain"], "target": f"{name}:{port}", "up": False, "ms": None, "error": ""}
        r.update(found[(ip, port)] if ip else {"error": "name not resolved"})
        rows.append(r)
    return sorted(rows, key=lambda r: (r["up"], r["domain"]))


# ---------------------------------------------------------------- suggestions
def suggestions(hosts: list[dict], rows: list[dict], ips: list[dict], lim: list[dict], ups: list[dict], tot: dict,
                have_fail2ban: bool, days_of_data: float) -> list[dict]:
    out: list[dict] = []

    def add(level, title, detail, link=None):
        out.append({"level": level, "title": title, "detail": detail, "link": link})

    by_host = {h["domain"]: h for h in hosts}
    for u in ups:
        if not u["up"]:
            add("bad", f"{u['domain']}: backend {u['target']} is not answering ({u['error'] or 'no connection'})",
                "Visitors get 502 errors. Start the service, fix the upstream address on the host page, or disable the host if it is meant to be off (an on-demand host will answer once started).",
                f"/hosts/{u['domain']}")
    down = {u["domain"] for u in ups if not u["up"]}
    for r in rows:
        if r["c5"] >= 10 and r["c5"] / r["n"] > 0.1 and r["host"] not in down:
            add("warn", f"{r['host']}: {r['c5']} server errors ({r['c5'] * 100 // r['n']}% of its requests)",
                "The backend answers but fails, or is intermittently unreachable. Check its logs; a longer read timeout on the host page helps if requests simply take too long.",
                f"/hosts/{r['host']}" if r["host"] in by_host else None)
        if r["n"] >= 20 and r["avg_ms"] > 2000 and r["host"] in by_host:
            add("info", f"{r['host']}: slow, {r['avg_ms']} ms per request on average",
                "Slow backend or large transfers. If it serves static files, turn on caching for the host." if not by_host[r["host"]]["cache"]["enabled"]
                else "Caching is already on; the backend itself is slow.", f"/hosts/{r['host']}")
    for i in ips:
        if i["n"] >= 50 and i["bad"] / i["n"] >= 0.8 and i["ok"] / i["n"] < 0.1:
            add("warn", f"{i['ip']}: scanner, {i['n']} requests, {i['bad'] * 100 // i['n']}% refused or not found",
                ("fail2ban will ban such addresses automatically." if have_fail2ban else
                 "Install fail2ban (sudo ./install.sh --fail2ban on each server) to ban addresses like this automatically, or block it at your router."))
    seen = set()
    for l in lim:
        if l["total"] and l["ok"] / l["total"] >= 0.5 and l["hits"] >= 20 and (l["host"], l["ip"]) not in seen:
            seen.add((l["host"], l["ip"]))
            add("warn", f"{l['ip']} was rate limited {l['hits']} times on {l['host']} but mostly sends normal requests",
                "Probably a real user or app (sync client, S3 client, many users behind one address). Raise the limits in Settings, or switch rate limiting off for this host.",
                f"/hosts/{l['host']}" if l["host"] in by_host else "/settings")
    n444 = tot["c444"]
    if n444 >= 100:
        add("info", f"{n444} requests for unknown names or by bare IP were dropped",
            "Normal background noise on a public address: internet scanners. Nothing to do.")
    if tot["n"] >= 500 and tot["c429"] / tot["n"] > 0.05:
        add("warn", f"{tot['c429']} requests ({tot['c429'] * 100 // tot['n']}%) were rate limited",
            "That is a lot. Check the rate limited addresses below; if they look legitimate raise the limits in Settings.", "/settings")
    if tot["n"] >= 200:
        top = ips[0] if ips else None
        if top and top["n"] / tot["n"] > 0.5 and top["ok"] / top["n"] > 0.5:
            add("info", f"{top['ip']} produces {top['n'] * 100 // tot['n']}% of all requests",
                "One client dominates the traffic. Fine for a backup or sync job; unexpected otherwise.")
    quiet = [d for d, h in by_host.items() if h["enabled"] and d not in {r["host"] for r in rows}]
    if days_of_data >= 1 and quiet:
        add("info", f"{len(quiet)} enabled host(s) had no requests in this period", ", ".join(sorted(quiet)))
    if not out:
        add("ok", "Nothing needs attention", "No failing backends, scanners, or legitimate users being limited in this period.")
    order = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
    return sorted(out, key=lambda s: order[s["level"]])


# ---------------------------------------------------------------- charts (inline SVG; colours come from CSS classes)
def human_bytes(n: float) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return ""


def label_time(t: int, step: int) -> str:
    return time.strftime("%H:%M" if step < 86400 else "%d.%m", time.localtime(t))


def chart(buckets: list[dict], step: int, kind: str = "requests", w: int = 720, h: int = 150) -> dict:
    """Stacked bars. Returns {svg, max, first, last}; one <title> per bucket gives the hover text."""
    keys = CLASSES if kind == "requests" else ("bytes",)
    peak = max((sum(b[k] for k in keys) for b in buckets), default=0) or 1
    n = max(len(buckets), 1)
    slot = w / n
    bw = max(slot - 2, 1)
    parts = [f'<svg class="chart" viewBox="0 0 {w} {h}" preserveAspectRatio="none" role="img" aria-label="{"Requests" if kind == "requests" else "Traffic"} over time">']
    for frac in (0.5, 1):
        y = h - h * frac
        parts.append(f'<line class="grid" x1="0" x2="{w}" y1="{y:.1f}" y2="{y:.1f}"/>')
    for i, b in enumerate(buckets):
        x = i * slot + 1
        y = float(h)
        tip = label_time(b["t"], step) + " – "
        if kind == "requests":
            tip += f"{b['n']} requests" + "".join(f", {b[k]} {LABELS[k].split()[0]}" for k in CLASSES if b[k])
        else:
            tip += human_bytes(b["bytes"])
        rects = []
        for k in keys:
            v = b[k]
            if not v:
                continue
            bh = max(v / peak * (h - 4), 1.5)
            y -= bh
            rects.append(f'<rect class="{"bytes" if kind != "requests" else k}" x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{bh:.1f}"/>')
        parts.append(f'<g><title>{escape(tip)}</title><rect class="hit" x="{x - 1:.1f}" y="0" width="{slot:.1f}" height="{h}"/>{"".join(rects)}</g>')
    parts.append("</svg>")
    return {"svg": "".join(parts), "max": (str(peak) if kind == "requests" else human_bytes(peak)),
            "first": label_time(buckets[0]["t"], step) if buckets else "", "last": label_time(buckets[-1]["t"], step) if buckets else ""}
