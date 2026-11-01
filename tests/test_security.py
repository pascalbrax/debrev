import yaml

from conftest import write_host
from debrev import security as sc, state as st

SSH_BAD = "PermitRootLogin yes\nPasswordAuthentication yes\n"
SS = "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\nLISTEN 0 4 [::]:8443 [::]:*\nLISTEN 0 4 0.0.0.0:9999 0.0.0.0:*\n"


def run(paths, ssh=SSH_BAD, probe=lambda: True):
    return {c["id"]: c for c in sc.audit(paths, [ssh], SS, probe)}


def test_parse_helpers():
    assert sc.parse_sshd(["PermitRootLogin no\n", "PermitRootLogin yes\n# PasswordAuthentication no\n"]) == {"permitrootlogin": "no"}
    assert sc.parse_listening(SS)[2] == ("127.0.0.1", 5432)


def test_default_state_is_not_blocked_but_warns(paths):
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:80\nenabled: true\n")
    st.commit(paths, "t")
    c = run(paths)
    assert c["rate"]["level"] == "ok" and c["default"]["level"] == "ok"
    assert c["ssh"]["level"] == "warn" and c["http01"]["level"] == "info"
    assert "9999" in c["ports"]["detail"] and "5432" not in c["ports"]["detail"]
    assert c["web"]["level"] == "info"
    assert sc.verdict(list(c.values())) == "caution"


def test_blockers(paths):
    (paths.state / "settings.yaml").write_text("format: 1\nsecurity: {rate_limit: false}\n")
    c = run(paths, "PermitRootLogin no\nPasswordAuthentication no\n", probe=lambda: False)
    assert c["rate"]["level"] == "fail" and c["default"]["level"] == "fail" and c["ssh"]["level"] == "ok"
    assert sc.verdict(list(c.values())) == "blocked"
    assert [x["level"] for x in sc.audit(paths, [""], SS, lambda: None)][0] == "fail"


def test_host_with_limit_off_and_plain_http_listed(paths):
    write_host(paths, "s.example.com", "domain: s.example.com\nupstream: http://10.0.0.1:80\nrate_limit: false\ntls: false\n")
    st.commit(paths, "t")
    c = run(paths)
    assert "s.example.com" in c["rate-off"]["detail"] and "s.example.com" in c["plain"]["detail"]


def test_fail2ban_bans_are_replayed_from_its_log(paths):
    from debrev import fail2ban as f2b, traffic
    paths.fail2ban_log.parent.mkdir(parents=True, exist_ok=True)
    paths.fail2ban_log.with_name("fail2ban.log.1").write_text(
        "2026-11-01 10:00:00,100 fail2ban.actions [1]: NOTICE  [nginx-limit-req] Ban 203.0.113.1\n")
    paths.fail2ban_log.write_text(
        "2026-11-01 10:30:00,100 fail2ban.filter [1]: INFO    [nginx-limit-req] Found 203.0.113.2 - 2026-11-01 10:30:00\n"
        "2026-11-01 11:00:00,100 fail2ban.actions [1]: NOTICE  [nginx-limit-req] Ban 203.0.113.2\n"
        "2026-11-01 11:05:00,100 fail2ban.actions [1]: NOTICE  [nginx-limit-req] Ban 203.0.113.3\n"
        "2026-11-01 11:06:00,100 fail2ban.actions [1]: NOTICE  [sshd] Ban 198.51.100.7\n"
        "2026-11-01 11:10:00,100 fail2ban.actions [1]: NOTICE  [nginx-limit-req] Unban 203.0.113.1\n"
        "2026-11-01 11:20:00,100 fail2ban.actions [1]: NOTICE  [nginx-limit-req] Restore Ban 203.0.113.4\n"
        "garbage line\n")
    bans, readable = f2b.banned(paths)
    assert readable and [b["ip"] for b in bans] == ["203.0.113.4", "203.0.113.3", "203.0.113.2"]    # newest first; sshd jail ignored
    assert bans[2]["since"] == "2026-11-01 11:00:00"
    # which hosts the address was rate limited on comes from the statistics
    with traffic._db(paths) as db:
        import time
        h = int(time.time()) // 3600 * 3600
        db.execute("INSERT INTO lim VALUES(?,?,?,?)", (h, "app.example.com", "203.0.113.3", 120))
        db.execute("INSERT INTO lim VALUES(?,?,?,?)", (h, "blog.example.com", "203.0.113.3", 7))
    paths.fail2ban_jail.parent.mkdir(parents=True, exist_ok=True)
    paths.fail2ban_jail.write_text("[nginx-limit-req]\n")
    ov = f2b.overview(paths)
    b3 = next(b for b in ov["bans"] if b["ip"] == "203.0.113.3")
    assert [(x["host"], x["hits"]) for x in b3["hosts"]] == [("app.example.com", 120), ("blog.example.com", 7)]
    assert next(b for b in ov["bans"] if b["ip"] == "203.0.113.2")["hosts"] == []


def test_security_page_lists_bans_or_says_none(paths, monkeypatch):
    from fastapi.testclient import TestClient
    from test_web import PW, login
    from debrev import auth, web
    (paths.lib / "web").mkdir(parents=True, exist_ok=True)
    auth.add_user(paths, "alice", PW)
    c = TestClient(web.create_app(paths, secure_cookie=False), client=("192.168.1.50", 5000), follow_redirects=False)
    login(c)
    monkeypatch.setattr("debrev.fail2ban.shutil.which", lambda name: None)
    assert "Banned by fail2ban" not in c.get("/security").text                                              # not installed: no section
    paths.fail2ban_jail.parent.mkdir(parents=True, exist_ok=True)
    paths.fail2ban_jail.write_text("[nginx-limit-req]\n")
    paths.fail2ban_log.parent.mkdir(parents=True, exist_ok=True)
    paths.fail2ban_log.write_text("")
    assert "Nobody is banned right now" in c.get("/security").text
    paths.fail2ban_log.write_text("2026-11-01 11:00:00,1 fail2ban.actions [1]: NOTICE  [nginx-limit-req] Ban 203.0.113.9\n")
    r = c.get("/security").text
    assert "203.0.113.9" in r and "unbanip" in r and "no host recorded" in r
    paths.fail2ban_log.unlink()
    assert "cannot be read" in c.get("/security").text
