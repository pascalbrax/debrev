import json
import time

from conftest import write_host
from debrev import state as st, traffic as tf


def line(t, ip="1.2.3.4", host="a.example.com", s=200, b=1000, rt=0.05, u="/", **kw):
    return json.dumps({"t": t, "ip": ip, "host": host, "m": "GET", "u": u, "s": s, "b": b, "rt": rt, "us": "", "ua": "x", **kw})


def feed(paths, lines, mode="w"):
    with open(paths.access_log, mode) as f:
        f.write("\n".join(lines) + "\n")


def test_collect_counts_and_is_incremental(paths):
    now = time.time()
    feed(paths, [line(now), line(now, s=404), line(now, s=502, b=0), line(now, s=429), line(now, s=444), "garbage"])
    assert tf.collect(paths) == 5
    assert tf.collect(paths) == 0                        # nothing new
    feed(paths, [line(now)], "a")
    assert tf.collect(paths) == 1
    t = tf.totals(paths, "1h")
    assert t["n"] == 6 and t["c2"] == 2 and t["c4"] == 1 and t["c5"] == 1 and t["c429"] == 1 and t["c444"] == 1 and t["bytes"] == 5000
    assert tf.collect(paths) == 0


def test_partial_last_line_waits_and_rotation_restarts(paths):
    now = time.time()
    with open(paths.access_log, "w") as f:
        f.write(line(now) + "\n" + line(now)[:20])
    assert tf.collect(paths) == 1
    paths.access_log.rename(paths.access_log.with_suffix(".1"))
    feed(paths, [line(now), line(now)])
    assert tf.collect(paths) == 2


def test_tables_and_series(paths):
    now = time.time()
    feed(paths, [line(now, host="a.example.com")] * 3 + [line(now, host="b.example.com", s=502)] * 2
         + [line(now, ip="9.9.9.9", s=404)] * 60 + [line(now, ip="9.9.9.9", s=429)] * 5)
    tf.collect(paths)
    rows = {r["host"]: r for r in tf.hosts_table(paths, "1h")}
    assert rows["a.example.com"]["n"] == 68 and rows["b.example.com"]["c5"] == 2
    ips = {i["ip"]: i for i in tf.ips_table(paths, "1h")}
    assert ips["9.9.9.9"]["bad"] == 65 and ips["9.9.9.9"]["lim"] == 5 and ips["1.2.3.4"]["ok"] == 3
    s = tf.series(paths, "1h")
    assert sum(b["n"] for b in s) == 70 and len(s) >= 59
    c = tf.chart(s, 60)
    assert c["svg"].startswith("<svg") and "<title>" in c["svg"] and 'class="c2"' in c["svg"]
    assert tf.chart([], 60)["svg"].startswith("<svg")


def test_recent_newest_first_and_errors_only(paths):
    now = time.time()
    feed(paths, [line(now + i, u=f"/{i}", s=500 if i % 10 == 0 else 200) for i in range(300)])
    r = tf.recent(paths, 5)
    assert [x["u"] for x in r] == ["/299", "/298", "/297", "/296", "/295"]
    e = tf.recent(paths, 3, only_errors=True)
    assert [x["u"] for x in e] == ["/290", "/280", "/270"]
    assert tf.recent(paths.__class__(access_log=paths.access_log.with_name("nope"))) == []


def test_upstream_probe(paths):
    import socket
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    write_host(paths, "up.example.com", f"domain: up.example.com\nupstream: http://127.0.0.1:{port}\n")
    write_host(paths, "down.example.com", "domain: down.example.com\nupstream: http://127.0.0.1:1\n")
    write_host(paths, "name.example.com", "domain: name.example.com\nupstream: http://nowhere:80\n")
    write_host(paths, "cached.example.com", f"domain: cached.example.com\nupstream: http://known:{port}\n")
    (paths.lib / "dns-cache.json").write_text(json.dumps({"known": {"ip": "127.0.0.1", "time": "x"}}))
    st.commit(paths, "t")
    res = {r["domain"]: r for r in tf.probe_upstreams(paths, st.load(paths)[0])}
    srv.close()
    assert res["up.example.com"]["up"] and not res["down.example.com"]["up"]
    assert res["cached.example.com"]["up"]
    assert res["name.example.com"]["error"] == "name not resolved"


def test_suggestions(paths):
    now = time.time()
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:80\n")
    write_host(paths, "idle.example.com", "domain: idle.example.com\nupstream: http://10.0.0.1:80\n")
    st.commit(paths, "t")
    hosts = st.load(paths)[0]
    feed(paths, [line(now, host="a.example.com", s=502)] * 30 + [line(now, host="a.example.com")] * 30
         + [line(now, ip="6.6.6.6", s=404)] * 90 + [line(now, ip="7.7.7.7", s=429, host="a.example.com")] * 40 + [line(now, ip="7.7.7.7")] * 100
         + [line(now, host="x", s=444)] * 150)
    tf.collect(paths)
    ups = [{"domain": "a.example.com", "target": "10.0.0.1:80", "up": False, "ms": None, "error": "refused"}]
    sug = tf.suggestions(hosts, tf.hosts_table(paths, "24h"), tf.ips_table(paths, "24h"), tf.limited(paths, "24h"), ups, tf.totals(paths, "24h"), False, 2)
    text = " | ".join(x["title"] for x in sug)
    assert "backend 10.0.0.1:80 is not answering" in text
    assert "6.6.6.6: scanner" in text and "7.7.7.7 was rate limited 40 times" in text
    assert "150 requests for unknown names" in text and "1 enabled host(s) had no requests" in text
    assert sug[0]["level"] == "bad"
    assert tf.suggestions([], [], [], [], [], {"n": 0, "c444": 0, "c429": 0}, False, 0)[0]["level"] == "ok"


def test_hosts_sharing_a_backend_are_probed_once(paths, monkeypatch):
    import socket
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
    port = srv.getsockname()[1]
    for d in ("a", "b", "c"):
        write_host(paths, f"{d}.example.com", f"domain: {d}.example.com\nupstream: http://127.0.0.1:{port}\n")
    write_host(paths, "d.example.com", "domain: d.example.com\nupstream: http://127.0.0.1:1\n")
    write_host(paths, "e.example.com", "domain: e.example.com\nupstream: http://127.0.0.1:1\nenabled: false\n")
    st.commit(paths, "t")
    calls = []
    real = socket.create_connection
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: calls.append(addr) or real(addr, timeout=timeout))
    res = tf.probe_upstreams(paths, st.load(paths)[0])
    srv.close()
    assert sorted(calls) == [("127.0.0.1", 1), ("127.0.0.1", port)]        # 2 connects for 4 enabled hosts
    assert {r["domain"]: r["up"] for r in res} == {"a.example.com": True, "b.example.com": True, "c.example.com": True, "d.example.com": False}
