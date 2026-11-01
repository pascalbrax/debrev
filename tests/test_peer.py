"""Twin-server logic, tested with two scratch 'servers' on one machine."""
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conftest import write_host
from debrev import certs, node as nodemod, peer, state as st
from debrev.paths import APP_DIR, Paths

HAVE_OPENSSL = shutil.which("openssl") is not None
HOST = "domain: {d}\nupstream: http://10.0.0.1:80\ntls: false\n"


def mk_server(tmp_path, name):
    root = tmp_path / name
    p = Paths(etc=root / "etc", lib=root / "lib", cache=root / "cache", letsencrypt=root / "le",
              reload_cmd=("true",), health_check=False)
    p.etc.mkdir(parents=True)
    p.node_file.write_text("")
    return p


def script(path, body):
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


@pytest.fixture
def twins(tmp_path, monkeypatch):
    a, b = mk_server(tmp_path, "a"), mk_server(tmp_path, "b")
    st.init(a)
    for p, other in ((a, "127.0.0.2"), (b, "127.0.0.1")):
        nodemod.save(p, nodemod.Node(name=p.etc.parent.name, peer_address=other))
    # B starts as a clone of A (same first commit), like a joined twin
    shutil.copytree(a.state, b.state)
    applied = tmp_path / "applied.log"
    for p in (a, b):
        p.apply_cmd = (script(tmp_path / f"apply-{p.etc.parent.name}", f'echo applied-{p.etc.parent.name} >> {applied}'),)
    # a fake ssh that only records requests
    sshlog = tmp_path / "ssh.log"
    a.peer_ssh = (script(tmp_path / "fake-ssh", f'echo "$@" >> {sshlog}; echo accepted'),)
    b.peer_ssh = a.peer_ssh
    monkeypatch.setenv("DEBREV_PEER_GIT_URL", str(b.state))
    a.applied_log, a.ssh_log = applied, sshlog
    return a, b


def commit_host(p, d, msg=None):
    write_host(p, d, HOST.format(d=d))
    return st.commit(p, msg or f"add {d}")


def test_peer_ahead_we_fast_forward_and_apply(twins):
    a, b = twins
    commit_host(b, "x.example.com")
    r = peer.sync(a)
    assert r.ok and r.state == "updated"
    assert (a.state / "hosts" / "x.example.com.yaml").exists()
    assert "applied-a" in a.applied_log.read_text()
    assert peer.sync(a).state == "in-sync"


def test_we_ahead_notifies_peer(twins, monkeypatch):
    a, b = twins
    monkeypatch.setenv("DEBREV_PEER_GIT_URL", str(b.state))
    commit_host(a, "y.example.com")
    r = peer.sync(a)
    assert r.ok and r.state == "notified"
    assert a.ssh_log.read_text().strip().endswith("notify")
    assert not (b.state / "hosts" / "y.example.com.yaml").exists()      # peer pulls by itself


def test_diverged_is_never_merged(twins):
    a, b = twins
    commit_host(a, "a.example.com")
    commit_host(b, "b.example.com")
    r = peer.sync(a)
    assert not r.ok and r.state == "diverged"
    assert not (a.state / "hosts" / "b.example.com.yaml").exists()
    assert "diverged" in peer.read_status(a)["state"]
    assert not a.applied_log.exists()


def test_take_theirs_keeps_a_backup(twins):
    a, b = twins
    mine = commit_host(a, "a.example.com")
    commit_host(b, "b.example.com")
    r = peer.sync(a, mode="theirs")
    assert r.ok and (a.state / "hosts" / "b.example.com.yaml").exists()
    assert not (a.state / "hosts" / "a.example.com.yaml").exists()
    branches = subprocess.run(["git", "-C", str(a.state), "branch", "--list", "backup/*", "--format=%(objectname)"],
                              capture_output=True, text=True).stdout.split()
    assert mine in branches


def test_unrelated_history_is_refused(twins, tmp_path):
    a, b = twins
    shutil.rmtree(b.state)
    st.init(b)
    subprocess.run(["git", "-C", str(b.state), "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-q",
                    "--amend", "-m", "a different first commit"], check=True)
    r = peer.sync(a)
    assert not r.ok and r.state == "unrelated"


def test_failed_apply_reverts_and_is_not_retried_blindly(twins, tmp_path):
    a, b = twins
    a.apply_cmd = (script(tmp_path / "bad-apply", "echo nginx says no >&2; exit 1"),)
    before = st.head(a)
    commit_host(b, "x.example.com")
    r = peer.sync(a)
    assert not r.ok and "does not apply" in r.message
    assert st.head(a) == before and not (a.state / "hosts" / "x.example.com.yaml").exists()
    r = peer.sync(a)
    assert not r.ok and "--retry" in r.message
    a.apply_cmd = (script(tmp_path / "good-apply", "exit 0"),)
    assert peer.sync(a, retry=True).state == "updated"


def test_dirty_state_blocks_sync(twins):
    a, b = twins
    write_host(a, "dirty.example.com", HOST.format(d="dirty.example.com"))
    r = peer.sync(a)
    assert not r.ok and "uncommitted" in r.message


def test_unreachable_peer_reports_and_changes_nothing(twins, monkeypatch):
    a, b = twins
    monkeypatch.setenv("DEBREV_PEER_GIT_URL", str(a.state.parent / "nonexistent"))
    r = peer.sync(a)
    assert not r.ok and r.state == "unreachable"
    assert peer.read_status(a)["state"] == "unreachable"


def test_no_peer_configured(tmp_path):
    p = mk_server(tmp_path, "solo")
    st.init(p)
    assert peer.sync(p).state == "no-peer"


# ---- what the peer's key may do ----------------------------------------------

def test_serve_rejects_everything_but_the_whitelist(twins, capsys):
    a, _ = twins
    for cmd in ("", "bash", "ls /", "git-receive-pack '/state'", "rm -rf /", "status; id", "cert-import extra"):
        assert peer.serve(a, cmd) != 0, cmd
    assert peer.serve(a, "status") == 0
    out = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert out["head"] == st.head(a) and "format" in out


def test_authorize_writes_a_restricted_key(tmp_path):
    p = mk_server(tmp_path, "k")
    pub = "ssh-ed25519 " + "A" * 68 + " debrev-sync@other"
    peer.authorize(p, pub, from_ip="192.168.1.2")
    line = (p.ssh_dir / "authorized_keys").read_text().strip()
    assert line.startswith('from="192.168.1.2",command="') and ',restrict ssh-ed25519 ' in line
    peer.authorize(p, pub)                                   # same key again replaces, not duplicates
    assert len((p.ssh_dir / "authorized_keys").read_text().splitlines()) == 1
    for bad in ("ssh-rsa AAAA", 'ssh-ed25519 AAAA" ; evil', "ssh-ed25519 " + "A" * 68 + '"\nssh-ed25519 ' + "B" * 68):
        with pytest.raises(peer.PeerError):
            peer.authorize(p, bad)


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_keygen_is_idempotent(tmp_path):
    p = mk_server(tmp_path, "g")
    k1 = peer.ensure_key(p)
    assert k1.startswith("ssh-ed25519 ") and peer.ensure_key(p) == k1
    assert (p.ssh_key.stat().st_mode & 0o077) == 0


# ---- ACME fallback -----------------------------------------------------------

def test_acme_fallback_rendered_only_with_peer_and_passes_nginx(tmp_path):
    from debrev.apply import apply
    from debrev.render import render
    p = mk_server(tmp_path, "r")
    st.init(p)
    commit_host(p, "a.example.com")
    hosts, acls, _, _ = st.load(p)
    plain, _ = render(p, hosts, acls, {})
    assert "debrev_acme_peer" not in plain["host-a_example_com.conf"]
    withpeer, _ = render(p, hosts, acls, {}, peer_ip="192.168.1.9")
    conf = withpeer["host-a_example_com.conf"]
    assert "try_files $uri @debrev_acme_peer;" in conf and "proxy_pass http://192.168.1.9:80;" in conf
    assert "X-Debrev-Acme-Hop" in conf and "return 404" in conf          # loop guard
    if shutil.which("nginx"):
        nodemod.save(p, nodemod.Node(name="r", peer_address="192.168.1.9"))
        assert apply(p, check_only=True).ok


# ---- certificates between nodes ----------------------------------------------

def make_pair(tmp_path, names, days=30):
    d = tmp_path / ("c-" + names[0])
    d.mkdir(exist_ok=True)
    san = ",".join(f"DNS:{n}" for n in names)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", str(days), "-subj", f"/CN={names[0]}",
                    "-addext", f"subjectAltName={san}", "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem")],
                   check=True, capture_output=True)
    return {"fullchain": (d / "c.pem").read_text(), "privkey": (d / "k.pem").read_text()}


@pytest.mark.skipif(not HAVE_OPENSSL, reason="needs openssl")
def test_import_validates_before_installing(tmp_path):
    p = mk_server(tmp_path, "imp")
    st.init(p)
    write_host(p, "a.example.com", "domain: a.example.com\naliases: [www.a.example.com]\nupstream: http://10.0.0.1:80\n")
    st.commit(p, "h")
    hosts = st.load(p)[0]
    good = make_pair(tmp_path, ["a.example.com", "www.a.example.com"])
    other_key = make_pair(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path, ["z.example.com"])["privkey"]
    cases = {
        "unknown.example.com": good,                                                    # not a host we know
        "a.example.com": {"fullchain": good["fullchain"], "privkey": other_key},        # key mismatch
    }
    res = {r["name"]: r for r in certs.import_certs(p, {"certs": cases}, hosts)}
    assert not res["unknown.example.com"]["ok"] and "unknown host" in res["unknown.example.com"]["message"]
    assert not res["a.example.com"]["ok"] and "does not match" in res["a.example.com"]["message"]
    wrong_names = make_pair(tmp_path, ["a.example.com"])
    r = certs.import_certs(p, {"certs": {"a.example.com": wrong_names}}, hosts)[0]
    assert not r["ok"] and "names do not match" in r["message"]
    assert not (p.certs_dir / "a.example.com").exists()                                 # nothing installed so far
    r = certs.import_certs(p, {"certs": {"a.example.com": good}}, hosts)[0]
    assert r["ok"] and r["message"] == "installed"
    assert (p.certs_dir / "a.example.com" / "privkey.pem").stat().st_mode & 0o077 == 0
    r = certs.import_certs(p, {"certs": {"a.example.com": good}}, hosts)[0]
    assert r["message"] == "already up to date"
    older = make_pair(tmp_path / "o" if (tmp_path / "o").mkdir() is None else tmp_path, ["a.example.com", "www.a.example.com"], days=5)
    assert certs.import_certs(p, {"certs": {"a.example.com": older}}, hosts)[0]["message"] == "already up to date"
