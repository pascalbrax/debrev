import os
import stat

from conftest import write_host
from debrev import state as st
from debrev.apply import apply

HOST = "domain: a.example.com\nupstream: http://127.0.0.1:1\ntls: false\n"


def fake_nginx(tmp_path, body):
    f = tmp_path / "fake-nginx"
    f.write_text("#!/bin/sh\n" + body + "\n")
    f.chmod(f.stat().st_mode | stat.S_IEXEC)
    return (str(f),)


def setup(paths, tmp_path, nginx_body="exit 0"):
    paths.nginx_cmd = fake_nginx(tmp_path, nginx_body)
    write_host(paths, "a.example.com", HOST)
    st.commit(paths, "add a")


def test_successful_apply_switches_live(paths, tmp_path):
    setup(paths, tmp_path)
    res = apply(paths)
    assert res.ok, res.message
    assert os.path.realpath(paths.live).endswith(res.release)
    assert (paths.live / "host-a_example_com.conf").exists()


def test_uncommitted_changes_block_apply(paths, tmp_path):
    setup(paths, tmp_path)
    write_host(paths, "b.example.com", HOST.replace("a.", "b."))
    assert not apply(paths).ok


def test_invalid_state_changes_nothing(paths, tmp_path):
    setup(paths, tmp_path)
    write_host(paths, "bad.example.com", "domain: bad.example.com\nupstream: nope\n")
    st.commit(paths, "bad")
    res = apply(paths)
    assert not res.ok and "validation failed" in res.message
    assert not paths.live.exists()


def test_failing_full_test_rolls_back_to_previous(paths, tmp_path):
    setup(paths, tmp_path)
    first = apply(paths)
    assert first.ok
    prev = os.path.realpath(paths.live)
    # isolated test passes ("-c" present), the full test (no -c) fails
    paths.nginx_cmd = fake_nginx(tmp_path, 'for a in "$@"; do [ "$a" = "-c" ] && exit 0; done; echo boom >&2; exit 1')
    write_host(paths, "b.example.com", HOST.replace("a.", "b."))
    st.commit(paths, "add b")
    res = apply(paths)
    assert not res.ok and "rolled back" in res.message
    assert os.path.realpath(paths.live) == prev


def test_isolated_test_failure_never_touches_live(paths, tmp_path):
    setup(paths, tmp_path, "echo bad config >&2; exit 1")
    res = apply(paths)
    assert not res.ok and "nothing was changed" in res.message
    assert not paths.live.exists()
    assert not any(paths.releases.iterdir())


def test_failed_reload_rolls_back(paths, tmp_path):
    setup(paths, tmp_path)
    assert apply(paths).ok
    prev = os.path.realpath(paths.live)
    write_host(paths, "b.example.com", HOST.replace("a.", "b."))
    st.commit(paths, "add b")
    paths.reload_cmd = ("false",)
    res = apply(paths)
    assert not res.ok and os.path.realpath(paths.live) == prev


def test_rollback_restores_earlier_state(paths, tmp_path):
    setup(paths, tmp_path)
    before = st.head(paths)
    write_host(paths, "b.example.com", HOST.replace("a.", "b."))
    st.commit(paths, "add b")
    st.restore(paths, before)
    assert not (paths.state / "hosts" / "b.example.com.yaml").exists()
    assert (paths.state / "hosts" / "a.example.com.yaml").exists()
    assert len(st.log(paths)) == 4  # init, add a, add b, rollback


def test_releases_are_pruned(paths, tmp_path):
    paths.keep_releases = 2
    setup(paths, tmp_path)
    for i in range(4):
        write_host(paths, f"h{i}.example.com", HOST.replace("a.", f"h{i}."))
        st.commit(paths, f"add {i}")
        assert apply(paths).ok
    assert len([d for d in paths.releases.iterdir()]) <= 3


def test_migrate_presets_copies_settings_into_hosts(paths):
    (paths.state / "presets").mkdir()
    (paths.state / "presets" / "big.yaml").write_text("max_body: 5g\ntimeouts: {read: 10m, send: 10m}\n")
    (paths.state / "presets" / "ws.yaml").write_text("websockets: true\n")
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:80\npreset: [big, ws]\ntimeouts: {send: 1m}\n")
    write_host(paths, "b.example.com", "domain: b.example.com\nupstream: http://10.0.0.1:80\n")
    st.commit(paths, "old style")
    assert st.load(paths)[2]                                   # presets are refused until migrated
    assert st.migrate_presets(paths) == ["a.example.com"]
    assert not (paths.state / "presets").exists() and not st.is_dirty(paths)
    h = {x["domain"]: x for x in st.load(paths)[0]}["a.example.com"]
    assert h["max_body"] == "5g" and h["websockets"] is True and h["timeouts"] == {"read": "10m", "send": "1m"}
    assert "preset" not in (paths.state / "hosts" / "a.example.com.yaml").read_text()
    assert not st.load(paths)[2]
