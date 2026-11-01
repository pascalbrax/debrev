"""Failure cases: what happens when the peer, certbot or the log is broken. Nothing may be lost or half-applied."""
import json
import shutil
import stat

import pytest

from conftest import write_host
from debrev import certs, node as nodemod, peer, state as st, traffic
from test_certs import fake_certbot, host, settings
from test_web import client  # noqa: F401  (fixture)
from debrev.paths import APP_DIR
from test_peer import commit_host, mk_server, script, twins  # noqa: F401  (twins is a fixture)

HAVE_OPENSSL = shutil.which("openssl") is not None


# ------------------------------------------------------------------ certificate renewal failures
@pytest.mark.skipif(not HAVE_OPENSSL, reason="needs openssl")
def test_failed_renewal_keeps_the_old_certificate_and_does_not_stop_the_others(paths, tmp_path, monkeypatch):
    monkeypatch.setenv("DEBREV_ROOT", str(tmp_path))
    good_certbot = fake_certbot(tmp_path, paths)
    s = settings(paths)
    host(paths, "good.example.com")
    host(paths, "bad.example.com")
    hosts = st.load(paths)[0]
    assert all(r["ok"] for r in certs.issue_missing(paths, hosts, s))
    live = paths.letsencrypt / "live"
    old = {n: (live / n / "fullchain.pem").read_bytes() for n in ("good.example.com", "bad.example.com")}

    real = paths.certbot_cmd[0]
    wrapper = tmp_path / "flaky-certbot"
    wrapper.write_text(f'#!/bin/bash\ncase "$*" in *bad.example.com*) echo "Detail: DNS problem"; exit 1;; esac\nexec {real} "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    paths.certbot_cmd = (str(wrapper),)

    out = certs.issue_missing(paths, hosts, s, force=True, only={"good.example.com", "bad.example.com"})
    res = {r["name"]: r for r in out}
    assert res["good.example.com"]["ok"] and not res["bad.example.com"]["ok"]
    assert "DNS problem" in res["bad.example.com"]["message"]
    assert (live / "bad.example.com" / "fullchain.pem").read_bytes() == old["bad.example.com"]      # untouched
    assert (live / "good.example.com" / "fullchain.pem").read_bytes() != old["good.example.com"]    # renewed
    rows = {r["name"]: r for r in certs.table(paths, hosts, s)}
    assert rows["bad.example.com"]["state"] == "ok" and rows["bad.example.com"]["last_error"]       # still valid, error visible
    assert rows["good.example.com"].get("last_error") is None
    # later success clears the error
    paths.certbot_cmd = (real,)
    assert certs.issue_missing(paths, hosts, s, force=True, only={"bad.example.com"})[0]["ok"]
    status = json.loads(paths.cert_status.read_text())
    assert "bad.example.com" not in status or not status["bad.example.com"].get("last_error")


# ------------------------------------------------------------------ twin problems
def test_peer_down_does_not_block_changes_and_it_catches_up_later(twins, tmp_path, monkeypatch):
    a, b = twins
    monkeypatch.setenv("DEBREV_PEER_GIT_URL", str(a.state))
    down = script(tmp_path / "ssh-down", "echo 'ssh: connect to host: No route to host' >&2; exit 255")
    a.peer_ssh = (down,)
    commit_host(a, "new.example.com")
    assert peer.notify(a, nodemod.load(a)) is False                      # reported, not raised
    assert peer.notify(a, nodemod.load(a), force=True) is False
    assert (a.state / "hosts" / "new.example.com.yaml").exists()         # local state is intact
    r = peer.sync(b)                                                     # the peer comes back and pulls by itself
    assert r.ok and r.state == "updated" and (b.state / "hosts" / "new.example.com.yaml").exists()
    assert peer.sync(a).state == "in-sync"


def test_peer_with_a_newer_state_format_is_not_adopted(twins):
    a, b = twins
    (b.state / "settings.yaml").write_text("format: 99\n")
    st.commit(b, "from the future")
    before = st.head(a)
    # use the real validation as the apply step, like debrev-apply does
    a.apply_cmd = (script(a.etc.parent / "real-apply", f"cd {a.state}; python3 - <<'PY'\nimport sys; sys.path.insert(0, '{APP_DIR}')\n"
                          f"from debrev import state as st\nfrom debrev.paths import Paths\n"
                          f"p = Paths(lib=__import__('pathlib').Path('{a.lib}'))\n"
                          "try:\n    st.load(p)\nexcept st.StateError as e:\n    print(e); sys.exit(1)\nPY"),)
    r = peer.sync(a)
    assert not r.ok and "newer" in r.message
    assert st.head(a) == before and "format: 99" not in (a.state / "settings.yaml").read_text()


def test_peer_sends_a_hostile_snippet_nothing_goes_live(twins, tmp_path):
    a, b = twins
    write_host(b, "evil.example.com", "domain: evil.example.com\nupstream: http://10.0.0.1:80\ncustom_snippet: 'include /etc/passwd;'\n")
    st.commit(b, "evil")
    a.apply_cmd = (script(tmp_path / "validating-apply", "exit 1"),)
    before = st.head(a)
    assert not peer.sync(a).ok and st.head(a) == before
    hosts, acls, errors, _ = st.load(b)                                   # and the validator itself names the problem
    assert any("include" in e for e in errors)


def test_cert_push_with_the_peer_down_reports_and_keeps_local_certs(paths, tmp_path):
    if not HAVE_OPENSSL:
        pytest.skip("needs openssl")
    fake_certbot(tmp_path, paths)
    s = settings(paths)
    hosts = host(paths, "a.example.com")
    certs.issue_missing(paths, hosts, s)
    certs.publish(paths, hosts)
    nodemod.save(paths, nodemod.Node(name="x", peer_address="10.255.255.1"))
    paths.peer_ssh = (script(tmp_path / "ssh-down", "echo no route >&2; exit 255"),)
    r = certs.push(paths)
    assert not r.ok and "no route" in r.message
    assert certs.cert_info(paths, "a.example.com")["days_left"] > 60


# ------------------------------------------------------------------ statistics survive a damaged database or log
def test_corrupt_statistics_database_is_rebuilt(paths):
    import time
    paths.access_log.write_text(json.dumps({"t": time.time(), "ip": "1.1.1.1", "host": "a.example.com", "m": "GET", "u": "/",
                                             "s": 200, "b": 1, "rt": 0.01, "us": "", "ua": ""}) + "\n")
    paths.traffic_db.write_bytes(b"this is not a sqlite database" * 50)
    assert traffic.collect(paths) == 1
    assert traffic.totals(paths, "1h")["n"] == 1
    assert list(paths.lib.glob("traffic.db.corrupt*"))


def test_health_page_survives_missing_log_and_damaged_database(client, paths):
    from test_web import login
    paths.traffic_db.write_bytes(b"garbage" * 100)
    login(client)
    r = client.get("/health")
    assert r.status_code == 200 and "No access log yet" in r.text
