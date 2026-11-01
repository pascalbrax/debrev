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
