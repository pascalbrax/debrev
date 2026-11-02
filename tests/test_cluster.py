import json
import shutil
import stat
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from conftest import write_host
from debrev import certs, cluster, node as nodemod, state as st
from debrev.paths import APP_DIR, Paths
from test_certs import fake_certbot, host, settings
from test_peer import mk_server, script


def node(**kw):
    return nodemod.Node(name="debrev-a", peer_address="192.168.1.120", **kw)


INFO = {"dev": "ens18", "src": "192.168.1.145", "prefix": 24}
CL = {"vip": "192.168.1.230", "vrid": 51}


def test_keepalived_config():
    txt = cluster.render_keepalived(node(priority=150), CL, INFO)
    for needle in ("priority 150", "virtual_router_id 51", "unicast_src_ip 192.168.1.145",
                   "192.168.1.120", "192.168.1.230/24 dev ens18", "weight -60",
                   "debrev-health", "debrev-vrrp-notify", "init_file 0", "state BACKUP",
                   "router_id debrev_debrev_a"):
        assert needle in txt, needle
    assert "nopreempt" not in txt          # the preferred node takes the IP back when healthy


def test_priorities_leave_room_for_failover():
    # healthy primary 150 / secondary 100; any failure or drain must put a node below its twin
    assert 150 + cluster.FAIL_WEIGHT < 100 and 150 + cluster.DRAIN_VALUE < 100
    assert 100 + cluster.FAIL_WEIGHT < 150 and 100 + cluster.DRAIN_VALUE < 150


def test_node_and_cluster_validation(paths):
    for bad in (0, 255, True, "x"):
        with pytest.raises(nodemod.NodeError):
            nodemod.validate("n", True, None, bad)
    with pytest.raises(nodemod.NodeError):
        nodemod.validate("n", True, None, 100, "eth0; rm")
    import yaml
    f = paths.state / "settings.yaml"
    for bad in ({"vip": "999.1.1.1"}, {"vip": "::1"}, {"vip": "10.0.0.1", "vrid": 0}, {"bogus": 1}):
        d = yaml.safe_load(f.read_text()); d["cluster"] = bad; f.write_text(yaml.safe_dump(d))
        assert st.load_settings(paths)[1], bad
    d["cluster"] = {"vip": "10.0.0.9"}; f.write_text(yaml.safe_dump(d))
    assert st.load_settings(paths)[0]["cluster"] == {"vip": "10.0.0.9", "vrid": 51}


def test_configure_writes_once_then_reloads_on_change(tmp_path, monkeypatch):
    p = mk_server(tmp_path, "k")
    st.init(p)
    import yaml
    d = yaml.safe_load((p.state / "settings.yaml").read_text()); d["cluster"] = {"vip": "10.1.1.9"}
    (p.state / "settings.yaml").write_text(yaml.safe_dump(d)); st.commit(p, "c")
    nodemod.save(p, nodemod.Node(name="k", peer_address="10.1.1.2", priority=120, interface="eth0"))
    p.keepalived_conf = tmp_path / "ka" / "keepalived.conf"
    log = tmp_path / "ka.log"
    p.keepalived_cmd = (script(tmp_path / "start", f"echo start >> {log}"),)
    p.keepalived_reload = (script(tmp_path / "reload", f"echo reload >> {log}"),)
    monkeypatch.setattr(cluster, "iface_info", lambda p_, n_: {"dev": "eth0", "src": "10.1.1.1", "prefix": 24})
    assert "started" in cluster.configure(p)
    assert "unchanged" in cluster.configure(p)
    nodemod.save(p, nodemod.Node(name="k", peer_address="10.1.1.2", priority=130, interface="eth0"))
    assert "reloaded" in cluster.configure(p)
    assert log.read_text().split() == ["start", "reload"]
    assert (p.drain_file.read_text().strip()) == "0"


def test_configure_does_nothing_without_vip_or_peer(tmp_path):
    p = mk_server(tmp_path, "k2")
    p.keepalived_conf = tmp_path / "ka" / "keepalived.conf"
    st.init(p)
    assert "not configured" in cluster.configure(p)
    assert not p.keepalived_conf.exists()


def test_drain_and_restore_flow(tmp_path, monkeypatch):
    p = mk_server(tmp_path, "d")
    st.init(p)
    import yaml
    d = yaml.safe_load((p.state / "settings.yaml").read_text()); d["cluster"] = {"vip": "10.1.1.9"}
    (p.state / "settings.yaml").write_text(yaml.safe_dump(d)); st.commit(p, "c")
    nodemod.save(p, nodemod.Node(name="d", peer_address="10.1.1.2", priority=150))
    p.drain_file.write_text("0\n")
    p.vrrp_state.write_text(json.dumps({"state": "MASTER"}))
    twin = {"name": "twin", "cluster": {"healthy": True, "drained": False, "name": "twin"}}
    monkeypatch.setattr(peermod := cluster.peermod, "peer_status", lambda *_: twin)
    monkeypatch.setattr(cluster, "probe_vip", lambda vip, timeout=2: "twin")

    def release(*_a, **_k):                       # keepalived reacts to the drain file
        p.vrrp_state.write_text(json.dumps({"state": "BACKUP"}))
    out = []
    # drain: the file must hold the drain value, and the node must report released
    monkeypatch.setattr(cluster, "_wait", lambda cond, s, step=1.0: (release(), cond())[1])
    assert cluster.drain(p, out=out.append)
    assert p.drain_file.read_text().strip() == str(cluster.DRAIN_VALUE) and cluster.drained(p)
    assert any("safe to upgrade" in l for l in out)
    # a second drain is a no-op
    assert cluster.drain(p, out=out.append)
    # restore needs a healthy nginx
    monkeypatch.setattr(cluster, "health", lambda *_a, **_k: (False, "nginx down"))
    with pytest.raises(cluster.ClusterError):
        cluster.restore(p, out=out.append)
    assert not cluster.drained(p)             # eligibility is restored even if it will wait for health
    monkeypatch.setattr(cluster, "health", lambda *_a, **_k: (True, "ok d"))
    assert cluster.restore(p, out=out.append)


def test_drain_refuses_when_twin_not_ready(tmp_path, monkeypatch):
    p = mk_server(tmp_path, "d2")
    st.init(p)
    import yaml
    d = yaml.safe_load((p.state / "settings.yaml").read_text()); d["cluster"] = {"vip": "10.1.1.9"}
    (p.state / "settings.yaml").write_text(yaml.safe_dump(d)); st.commit(p, "c")
    nodemod.save(p, nodemod.Node(name="d2", peer_address="10.1.1.2"))
    p.drain_file.write_text("0\n")
    for twin in ({"cluster": {"healthy": False, "drained": False}}, {"cluster": {"healthy": True, "drained": True}}, {}):
        monkeypatch.setattr(cluster.peermod, "peer_status", lambda *_a, t=twin: t)
        with pytest.raises(cluster.ClusterError):
            cluster.drain(p, out=lambda *_: None)
        assert not cluster.drained(p)
    def down(*_a):
        raise cluster.peermod.PeerError("no route")
    monkeypatch.setattr(cluster.peermod, "peer_status", down)
    with pytest.raises(cluster.ClusterError, match="no route"):
        cluster.drain(p, out=lambda *_: None)


def test_health_check_against_a_stub_server(tmp_path):
    import http.server, threading
    p = mk_server(tmp_path, "h")

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            ok = self.path == cluster.HEALTH_PATH and self.headers["Host"] == "debrev-health.invalid"
            self.send_response(200 if ok else 404)
            self.end_headers()
            self.wfile.write(b"ok stubnode\n" if ok else b"no")
        def log_message(self, *a): pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    assert cluster.health(p, port=srv.server_port) == (True, "ok stubnode")
    srv.shutdown()
    ok, why = cluster.health(p, port=srv.server_port)
    assert not ok and "not answering" in why


def test_health_endpoint_rendered_and_nginx_accepts_it(tmp_path):
    from debrev.apply import apply
    from debrev.render import render
    p = mk_server(tmp_path, "he")
    st.init(p)
    files, _ = render(p, [], {}, {}, node_name="debrev-a")
    g = files["00-global.conf"]
    assert 'return 200 "ok debrev-a\\n";' in g and "deny all;" in g and "return 444;" in g
    if shutil.which("nginx"):
        assert apply(p, check_only=True).ok


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
def test_replicated_cert_gets_renewed_by_the_new_master(tmp_path):
    """After a failover the new master has a copy but no certbot lineage."""
    p = mk_server(tmp_path, "m2")
    st.init(p)
    log = fake_certbot(tmp_path, p)
    s = settings(p)
    hosts = host(p, "a.example.com")
    near = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "10", "-subj", "/CN=a.example.com",
                           "-addext", "subjectAltName=DNS:a.example.com", "-keyout", str(tmp_path / "k"), "-out", str(tmp_path / "c")],
                          capture_output=True)
    certs.install_cert(p, "a.example.com", (tmp_path / "c").read_bytes(), (tmp_path / "k").read_bytes())
    item = certs.plan(hosts)[0]
    assert "renewal due" in certs.reason(p, item, s)
    # with a lineage present, certbot's own timer is responsible
    (p.letsencrypt / "renewal").mkdir(parents=True)
    (p.letsencrypt / "renewal" / "a.example.com.conf").write_text("")
    assert certs.reason(p, item, s) is None
    (p.letsencrypt / "renewal" / "a.example.com.conf").unlink()
    # acme.auto off: only renewals are allowed, and they happen
    res = certs.issue_missing(p, hosts, s, renewals_only=True)
    assert res[0]["ok"] and log.exists()
    assert certs.cert_info(p, "a.example.com")["days_left"] > 60


def test_push_no_longer_requires_issuer_flag(tmp_path):
    p = mk_server(tmp_path, "ps")
    st.init(p)
    nodemod.save(p, nodemod.Node(name="ps", acme_issuer=False, peer_address="10.0.0.2"))
    r = certs.push(p)
    assert "no certificates" in r.message          # got past the old "not the issuer" early return


def _clustered(tmp_path, name="b"):
    import yaml
    p = mk_server(tmp_path, name)
    st.init(p)
    d = yaml.safe_load((p.state / "settings.yaml").read_text()); d["cluster"] = {"vip": "10.1.1.9"}
    (p.state / "settings.yaml").write_text(yaml.safe_dump(d)); st.commit(p, "c")
    nodemod.save(p, nodemod.Node(name=name, peer_address="10.1.1.2", priority=100))
    p.drain_file.write_text("0\n")
    return p


def test_take_over_asks_the_twin_to_drain_and_waits_for_the_vip(tmp_path, monkeypatch):
    p = _clustered(tmp_path)
    p.vrrp_state.write_text(json.dumps({"state": "BACKUP"}))
    asked = []
    monkeypatch.setattr(cluster, "health", lambda *_a, **_k: (True, "ok b"))
    monkeypatch.setattr(cluster.peermod, "ask_twin", lambda p_, n_, what, **k: asked.append(what) or "twin drained")
    monkeypatch.setattr(cluster, "probe_vip", lambda vip, timeout=2: "b")

    def promote(cond, s, step=1.0):
        p.vrrp_state.write_text(json.dumps({"state": "MASTER"}))
        return cond()
    monkeypatch.setattr(cluster, "_wait", promote)
    out = []
    assert cluster.take_over(p, out=out.append)
    assert asked == ["drain"] and any("now served by b" in l for l in out)
    # already master: nothing is asked of the twin
    asked.clear()
    assert cluster.take_over(p, out=out.append) and asked == []


def test_take_over_refusals(tmp_path, monkeypatch):
    p = _clustered(tmp_path)
    p.vrrp_state.write_text(json.dumps({"state": "BACKUP"}))
    monkeypatch.setattr(cluster, "health", lambda *_a, **_k: (False, "nginx down"))
    with pytest.raises(cluster.ClusterError, match="not healthy"):
        cluster.take_over(p)
    monkeypatch.setattr(cluster, "health", lambda *_a, **_k: (True, "ok"))
    p.drain_file.write_text("-100\n")
    with pytest.raises(cluster.ClusterError, match="out of service"):
        cluster.take_over(p)
    p.drain_file.write_text("0\n")

    def refuse(*_a, **_k):
        raise cluster.peermod.PeerError("the twin is not ready to take over")
    monkeypatch.setattr(cluster.peermod, "ask_twin", refuse)
    with pytest.raises(cluster.ClusterError, match="did not step down"):
        cluster.take_over(p)


def test_hand_back_restores_the_twin(tmp_path, monkeypatch):
    p = _clustered(tmp_path)
    asked = []
    monkeypatch.setattr(cluster.peermod, "ask_twin", lambda p_, n_, what, **k: asked.append(what) or "ok")
    assert cluster.hand_back(p, out=lambda *_: None) and asked == ["restore"]
