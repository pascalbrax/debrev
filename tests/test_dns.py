import json

from conftest import write_host
from debrev import dns, state as st
from debrev.apply import apply


def hosts_for(paths, *urls):
    for i, u in enumerate(urls):
        write_host(paths, f"h{i}.example.com", f"domain: h{i}.example.com\nupstream: {u}\ntls: false\n")
    st.commit(paths, "hosts")
    return st.load(paths)[0]


def test_resolve_and_cache_fallback(paths, monkeypatch):
    hosts = hosts_for(paths, "http://nas:3000", "http://10.0.0.1:80")
    monkeypatch.setattr(dns, "lookup", lambda n: "192.168.1.107")
    r, w = dns.resolve_all(paths, hosts)
    assert r == {"nas": "192.168.1.107"} and not w

    def fail(n):
        raise OSError("down")
    monkeypatch.setattr(dns, "lookup", fail)
    r, w = dns.resolve_all(paths, hosts)
    assert r == {"nas": "192.168.1.107"} and "using cached" in w[0]


def test_no_cache_no_answer(paths, monkeypatch):
    hosts = hosts_for(paths, "http://nas:3000")
    monkeypatch.setattr(dns, "lookup", lambda n: (_ for _ in ()).throw(OSError("nx")))
    r, w = dns.resolve_all(paths, hosts)
    assert r == {} and "no cached address" in w[0]


def test_pin_ipv6_and_literals():
    assert dns.pin("http://[::1]:80", {})["url"] == "http://[::1]:80"
    assert dns.pin("http://x:80/p", {"x": "fe80::1"})["url"] == "http://[fe80::1]:80/p"
    assert dns.pin("http://x:80", {}) is None


def test_refresh_only_reapplies_on_change(paths, tmp_path, monkeypatch):
    from test_apply import fake_nginx
    paths.nginx_cmd = fake_nginx(tmp_path, "exit 0")
    hosts_for(paths, "http://nas:3000")
    ip = {"v": "10.0.0.5"}
    monkeypatch.setattr(dns, "lookup", lambda n: ip["v"])
    assert apply(paths).ok
    res = apply(paths, dns_only=True)
    assert res.ok and "unchanged" in res.message
    ip["v"] = "10.0.0.6"
    res = apply(paths, dns_only=True)
    assert res.ok and res.release
    assert "10.0.0.6" in (paths.live / "host-h0_example_com.conf").read_text()
    assert json.loads(paths.applied.read_text())["resolved"] == {"nas": "10.0.0.6"}
