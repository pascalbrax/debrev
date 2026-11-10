import os
import subprocess
import time

from debrev import security as sc, updates

REAL_WAITING = updates.waiting          # conftest replaces the module attribute in every test

SIM = """Listing...
libc6/stable-security 2.41-12+deb13u1 amd64 [upgradable from: 2.41-12]
nginx/stable-security,stable 1.26.3-3+deb13u1 amd64 [upgradable from: 1.26.3-3]
vim-tiny/stable 2:9.1.1 amd64 [upgradable from: 2:9.1.0]
tzdata/stable 2025c-1 all [upgradable from: 2025b-1]
"""


def fake_run(out=SIM, rc=0, calls=None):
    def run(cmd, **kw):
        if calls is not None:
            calls.append(cmd)
        return subprocess.CompletedProcess(cmd, rc, out, "")
    return run


def test_parse_listing_marks_security_and_sorts_them_first():
    pk = updates.parse_listing(SIM)
    assert [x["name"] for x in pk] == ["libc6", "nginx", "tzdata", "vim-tiny"]
    assert [x["security"] for x in pk] == [True, True, False, False]
    assert pk[0]["old"] == "2.41-12" and pk[0]["new"] == "2.41-12+deb13u1"
    assert updates.parse_listing("Listing...\n") == []


def fresh_cache():
    updates._cache.update(t=0.0, key=None, v=None)


def test_waiting_is_read_only_and_asks_apt_only_when_something_changed(paths, monkeypatch, tmp_path):
    fresh_cache()
    status, pkgcache = tmp_path / "status", tmp_path / "pkgcache.bin"
    status.write_text("a"); pkgcache.write_text("a")
    monkeypatch.setattr(updates, "WATCH", (status, pkgcache))
    calls = []
    assert len(REAL_WAITING(paths, run=fake_run(calls=calls))) == 4
    assert calls == [["apt", "list", "--upgradable"]]                                   # read-only: never a real upgrade
    for _ in range(5):                                                                  # page loads: no new apt call
        REAL_WAITING(paths, run=fake_run(calls=calls))
    assert len(calls) == 1
    # an upgrade (dpkg status changes) -> asked again; the answer is current at once
    status.write_text("b"); os.utime(status, (time.time() + 5, time.time() + 5))
    assert REAL_WAITING(paths, run=fake_run(out="Listing...\n", calls=calls)) == [] and len(calls) == 2
    # 'apt update' (cache file) and the timer's stamp also invalidate it
    pkgcache.write_text("b"); os.utime(pkgcache, (time.time() + 9, time.time() + 9))
    REAL_WAITING(paths, run=fake_run(calls=calls)); assert len(calls) == 3
    updates.stamp(paths).write_text("")
    REAL_WAITING(paths, run=fake_run(calls=calls)); assert len(calls) == 4
    # and after two hours whatever happened
    updates._cache["t"] -= updates.CACHE_SECONDS + 1
    REAL_WAITING(paths, run=fake_run(calls=calls)); assert len(calls) == 5
    # apt failing is "unknown", never "up to date"
    fresh_cache()
    assert REAL_WAITING(paths, run=fake_run(rc=100)) is None
    fresh_cache()


def test_security_page_levels(paths, monkeypatch):
    def levels(pk, **kw):
        return {c["id"]: c for c in sc.update_checks(paths, reboot="", pk=pk, **kw)}
    stamp = updates.stamp(paths)
    assert levels([])["updates-old"]["level"] == "info"                                 # timer has not run yet
    stamp.write_text("")
    assert "updates-old" not in levels([])
    c = levels(updates.parse_listing(SIM))["updates"]
    assert c["level"] == "warn" and "2 security update(s)" in c["title"] and "libc6, nginx" in c["detail"] and "full-upgrade" in c["detail"]
    assert "2 other update(s)" in c["detail"]
    c = levels(updates.parse_listing("vim-tiny/stable 2 amd64 [upgradable from: 1]\n"))["updates"]
    assert c["level"] == "info" and "1 software update(s)" in c["title"]
    assert levels([])["updates"]["level"] == "ok"                                       # all installed by hand -> instantly ok
    monkeypatch.setattr(updates, "waiting", lambda *a, **k: None)                       # apt cannot be asked
    assert levels(None)["updates"]["level"] == "info"
    old = time.time() - 9 * 86400
    os.utime(stamp, (old, old))
    assert "9 days ago" in levels([])["updates-old"]["title"] and levels([])["updates-old"]["level"] == "warn"


def test_reboot_detection(tmp_path):
    boot = tmp_path / "boot"; boot.mkdir()
    flag = tmp_path / "reboot-required"
    for v in ("6.12.9-amd64", "6.12.113+deb13-amd64", "6.1.0-1-amd64"):
        (boot / f"vmlinuz-{v}").write_text("")
    assert updates.reboot_needed(boot, "6.12.113+deb13-amd64", flag) == ""             # newest kernel is running
    assert "6.12.113+deb13-amd64 is installed" in updates.reboot_needed(boot, "6.12.9-amd64", flag)
    assert updates.reboot_needed(boot, "6.12.200-amd64", flag) == ""                   # running newer than installed: fine
    flag.write_text("")
    assert "asked for a restart" in updates.reboot_needed(boot, "6.12.113+deb13-amd64", flag)
    assert updates.reboot_needed(tmp_path / "none", "6.1", tmp_path / "nope") == ""


def test_reboot_check_appears(paths):
    c = {x["id"]: x for x in sc.update_checks(paths, reboot="kernel X is installed, Y is running", pk=[])}
    assert c["reboot"]["level"] == "info" and "restart is needed" in c["reboot"]["title"]


def test_timer_only_runs_apt_update():
    from debrev.paths import APP_DIR
    inst = (APP_DIR / "install.sh").read_text()
    unit = inst[inst.index("debrev-updates.service <<"):inst.index("debrev-updates.timer <<")]
    assert "ExecStart=/usr/bin/apt-get update -q" in unit and "upgrade" not in unit and "apt-updated" in unit
