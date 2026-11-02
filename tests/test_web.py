import re

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from debrev import auth, state as st, web  # noqa: E402

PW = "correct horse battery"


@pytest.fixture
def client(paths, monkeypatch, tmp_path):
    (paths.lib / "web").mkdir(parents=True, exist_ok=True)
    auth._fails.clear()
    auth.add_user(paths, "alice", PW)
    app = web.create_app(paths, secure_cookie=False)
    monkeypatch.setattr(web, "APP_DIR", web.APP_DIR)
    return TestClient(app, client=("192.168.1.50", 5000), follow_redirects=False)


def csrf_of(c, url="/hosts/new"):
    r = c.get(url)
    assert r.status_code == 200, r.text[:200]
    return re.search(r'name="csrf" value="([^"]+)"', r.text).group(1)


def login(c, user="alice", pw=PW, code=""):
    return c.post("/login", data={"user": user, "password": pw, "code": code})


def test_requires_login(client):
    for url in ("/", "/hosts", "/certs", "/history", "/cluster", "/settings", "/account", "/files/access_lists"):
        r = client.get(url)
        assert r.status_code == 303 and r.headers["location"] == "/login", url


def test_wrong_network_is_forbidden(paths):
    app = web.create_app(paths, secure_cookie=False)
    c = TestClient(app, client=("8.8.8.8", 1), follow_redirects=False)
    assert c.get("/login").status_code == 403
    c2 = TestClient(app, client=("10.1.2.3", 1), follow_redirects=False)
    assert c2.get("/login").status_code == 200
    assert not web.client_allowed("203.0.113.5", [])
    assert web.client_allowed("203.0.113.5", ["203.0.113.0/24"])
    assert web.client_allowed("::ffff:192.168.1.1", [])


def test_login_and_security_headers(client):
    r = client.get("/login")
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "<script>" not in r.text
    assert login(client, pw="nope").status_code == 401
    assert login(client, user="ghost").status_code == 401
    r = login(client)
    assert r.status_code == 303
    assert client.get("/").status_code == 200
    assert "HttpOnly" in r.headers["set-cookie"] and "samesite=strict" in r.headers["set-cookie"].lower()


def test_throttle(client):
    for _ in range(auth.MAX_FAILS):
        login(client, pw="bad")
    r = login(client)          # correct password, but locked out
    assert r.status_code == 401 and "too many" in r.text


def test_csrf_enforced(client):
    login(client)
    r = client.post("/hosts/new", data={"domain": "a.example.com", "upstream": "http://10.0.0.1"})
    assert r.status_code == 403
    r = client.post("/hosts/new", data={"csrf": "wrong", "domain": "a.example.com", "upstream": "http://10.0.0.1"})
    assert r.status_code == 403


def test_host_lifecycle(client, paths):
    login(client)
    tok = csrf_of(client)
    r = client.post("/hosts/new", data={"csrf": tok, "domain": "App.Example.com", "upstream": "http://10.0.0.5:3000",
                                       "enabled": "on", "tls": "on", "force_https": "on", "then": "save"})
    assert r.status_code == 303
    f = paths.state / "hosts" / "app.example.com.yaml"
    assert f.exists()
    # defaults are not written out
    assert "tls" not in f.read_text() and "enabled" not in f.read_text()
    assert "(web)" in st.log(paths, 1)[0]["message"] and st.log(paths, 1)[0]["author"] == "alice"
    assert "app.example.com" in client.get("/hosts").text
    # edit: websockets + cache on
    r = client.post("/hosts/app.example.com", data={"csrf": tok, "upstream": "http://10.0.0.6:3000", "enabled": "on",
                                                   "tls": "on", "force_https": "on", "websockets": "on", "cache": "on",
                                                   "aliases": "www.example.com\nx.example.com", "then": "save"})
    assert r.status_code == 303
    hosts = st.load(paths)[0]
    h = hosts[0]
    assert h["websockets"] and h["cache"]["enabled"] and h["aliases"] == ["www.example.com", "x.example.com"]
    assert h["upstream"] == "http://10.0.0.6:3000"
    # bad input is rejected and the file is untouched
    before = f.read_text()
    r = client.post("/hosts/app.example.com", data={"csrf": tok, "upstream": "javascript:alert(1)", "enabled": "on", "tls": "on", "force_https": "on"})
    assert r.status_code == 400 and f.read_text() == before
    # duplicate
    r = client.post("/hosts/new", data={"csrf": tok, "domain": "app.example.com", "upstream": "http://10.0.0.1"})
    assert r.status_code == 400
    # delete
    r = client.post("/hosts/app.example.com", data={"csrf": tok, "action": "delete"})
    assert r.status_code == 303 and not f.exists()


def test_advanced_fields_and_rate_limit_override(client, paths):
    login(client)
    tok = csrf_of(client)
    base = {"csrf": tok, "adv": "1", "upstream": "http://10.0.0.5", "enabled": "on", "tls": "on", "force_https": "on",
            "buffering": "on", "request_buffering": "on", "rate_limit": "on"}
    f = paths.state / "hosts" / "a.example.com.yaml"
    client.post("/hosts/new", data={**base, "domain": "a.example.com"})
    assert "buffering" not in f.read_text() and "rate_limit" not in f.read_text() and "timeouts" not in f.read_text()
    adv = {**base, "to_read": "10m", "to_send": "10m", "custom_snippet": "location /x { return 204; }",
           "rl_rate": "200", "rl_burst": "2000", "rl_connections": "500", "websockets": "on"}
    client.post("/hosts/a.example.com", data=adv)
    h = st.load(paths)[0][0]
    assert h["timeouts"] == {"read": "10m", "send": "10m"} and "return 204" in h["custom_snippet"]
    assert h["rate_limits"] == {"rate": 200, "burst": 2000, "connections": 500} and h["websockets"] is True
    assert "open" in client.get("/hosts/a.example.com").text.split("details")[1]
    client.post("/hosts/a.example.com", data={k: v for k, v in base.items() if k not in ("buffering", "rate_limit")})
    h = st.load(paths)[0][0]
    assert h["rate_limit"] is False and h["buffering"] is False and h["request_buffering"] is True
    assert "timeouts" not in f.read_text() and "custom_snippet" not in f.read_text()
    r = client.post("/hosts/a.example.com", data={**base, "rl_rate": "fast"})
    assert r.status_code == 400
    client.post("/hosts/b.example.com", data={**base, "upstream": "http://10.0.0.6"})   # unknown host: not created by edit


def test_yaml_editor_validates_and_keeps_domain(client, paths):
    login(client)
    tok = csrf_of(client)
    client.post("/hosts/new", data={"csrf": tok, "domain": "a.example.com", "upstream": "http://10.0.0.5", "enabled": "on", "tls": "on", "force_https": "on"})
    f = paths.state / "hosts" / "a.example.com.yaml"
    good = f.read_text()
    r = client.post("/hosts/a.example.com", data={"csrf": tok, "action": "yaml", "yaml": "domain: b.example.com\nupstream: http://1.1.1.1\n"})
    assert r.status_code == 400 and f.read_text() == good
    r = client.post("/hosts/a.example.com", data={"csrf": tok, "action": "yaml", "yaml": "domain: a.example.com\nupstream: http://1.1.1.1\ncustom_snippet: 'include /etc/passwd;'\n"})
    assert r.status_code == 400 and f.read_text() == good
    r = client.post("/hosts/a.example.com", data={"csrf": tok, "action": "yaml", "yaml": "domain: a.example.com\nupstream: http://1.1.1.1\ndomain: x\n"})
    assert r.status_code == 400
    r = client.post("/hosts/a.example.com", data={"csrf": tok, "action": "yaml", "yaml": "domain: a.example.com\nupstream: http://1.1.1.1\n"})
    assert r.status_code == 303 and "1.1.1.1" in f.read_text()


def test_path_traversal(client):
    login(client)
    assert client.get("/hosts/..%2Fsettings").status_code in (404, 422)
    assert client.get("/files/access_lists/..%2F..%2Fsettings").status_code == 404
    assert client.get("/files/nope").status_code == 404
    assert client.get("/history/zzzz").status_code == 404


def test_access_list_editor_and_history(client, paths):
    login(client)
    tok = csrf_of(client, "/files/access_lists/_new")
    r = client.post("/files/access_lists/_new", data={"csrf": tok, "name": "office", "yaml": "allow: ['10.0.0.0/8']\n"})
    assert r.status_code == 303 and (paths.state / "access_lists" / "office.yaml").exists()
    r = client.post("/files/access_lists/_new", data={"csrf": tok, "name": "bad", "yaml": "nonsense_key: 1\n"})
    assert r.status_code in (303, 400)       # unknown keys are ignored or rejected, never crash
    h = client.get("/history")
    assert h.status_code == 200 and "office (web)" in h.text
    rev = st.log(paths, 5)[1]["rev"]
    d = client.get(f"/history/{rev[:12]}")
    assert d.status_code == 200
    r = client.post(f"/history/{rev[:12]}/rollback", data={"csrf": tok})
    assert r.status_code == 303


def test_settings_acme(client, paths):
    login(client)
    tok = csrf_of(client, "/settings")
    r = client.post("/settings", data={"csrf": tok, "email": "me@example.com", "server": "staging", "auto": "on"})
    assert r.status_code == 303
    s, _ = st.load_settings(paths)
    assert s["acme"]["email"] == "me@example.com" and s["acme"]["server"] == "staging" and s["acme"]["auto"]
    r = client.post("/settings", data={"csrf": tok, "email": "not-an-email", "server": "staging"})
    assert r.status_code == 400
    assert st.load_settings(paths)[0]["acme"]["email"] == "me@example.com"


def test_password_change_and_totp(client, paths):
    login(client)
    tok = csrf_of(client, "/account")
    r = client.post("/account", data={"csrf": tok, "action": "password", "current": "wrong", "new": "x" * 12, "new2": "x" * 12})
    assert r.status_code == 400
    r = client.post("/account", data={"csrf": tok, "action": "password", "current": PW, "new": "short", "new2": "short"})
    assert r.status_code == 400
    # enable 2FA
    page = client.get("/account").text
    secret = re.search(r'<code class="break">([A-Z2-7]+)</code>', page).group(1)
    token = re.search(r'name="token" value="([^"]+)"', page).group(1)
    import pyotp
    r = client.post("/account", data={"csrf": tok, "action": "totp_on", "current": PW, "token": token, "code": "000000"})
    assert r.status_code == 400
    r = client.post("/account", data={"csrf": tok, "action": "totp_on", "current": PW, "token": token, "code": pyotp.TOTP(secret).now()})
    assert r.status_code == 303
    # a fresh client now needs the code
    c2 = TestClient(client.app, client=("192.168.1.51", 1), follow_redirects=False)
    assert login(c2).status_code == 401
    assert login(c2, code=pyotp.TOTP(secret).now()).status_code == 303
    # password change kills other sessions
    tok2 = csrf_of(c2, "/account")
    r = c2.post("/account", data={"csrf": tok2, "action": "password", "current": PW, "new": "a brand new passphrase", "new2": "a brand new passphrase"})
    assert r.status_code == 303
    assert client.get("/").status_code == 303          # first session is gone
    assert c2.get("/").status_code == 200              # the one that changed it stays


def test_user_files_private(paths):
    auth.add_user(paths, "bob", PW)
    for f in (paths.lib / "web").iterdir():
        assert (f.stat().st_mode & 0o077) == 0, f
    assert (paths.lib / "web").stat().st_mode & 0o077 == 0
    with pytest.raises(auth.AuthError):
        auth.add_user(paths, "bob", PW)
    with pytest.raises(auth.AuthError):
        auth.add_user(paths, "Bad Name!", PW)
    with pytest.raises(auth.AuthError):
        auth.add_user(paths, "carol", "short")


def test_cert_source_and_challenge_options(client, paths):
    login(client)
    tok = csrf_of(client)
    base = {"csrf": tok, "upstream": "http://10.0.0.5", "enabled": "on", "tls": "on", "force_https": "on"}
    client.post("/hosts/new", data={**base, "domain": "a.example.com", "cert": "auto", "challenge": "dns"})
    h = st.load(paths)[0][0]
    assert h["tls"]["challenge"] == "dns" and h["tls"]["cert"] == "auto"
    client.post("/hosts/a.example.com", data={**base, "cert": "custom", "challenge": "http"})
    h = st.load(paths)[0][0]
    assert h["tls"]["cert"] == "custom" and h["tls"]["challenge"] == "http" and not h["tls"]["cert_path"]
    text = (paths.state / "hosts" / "a.example.com.yaml").read_text()
    assert "challenge" not in text                      # default value is not written
    page = client.get("/hosts/a.example.com").text
    assert 'id="owncert"' in page and 'id="owncert" hidden' not in page and 'name="fullchain"' in page
    client.post("/hosts/a.example.com", data={**base, "cert": "auto", "challenge": "http"})
    assert 'id="owncert" hidden' in client.get("/hosts/a.example.com").text


@pytest.mark.skipif(not __import__("shutil").which("openssl"), reason="needs openssl")
def test_upload_certificate_through_ui(client, paths, tmp_path, monkeypatch):
    import subprocess
    monkeypatch.setenv("DEBREV_ROOT", str(tmp_path))     # take the direct (root) path instead of sudo
    login(client)
    tok = csrf_of(client)
    base = {"csrf": tok, "upstream": "http://10.0.0.5", "enabled": "on", "tls": "on", "force_https": "on", "cert": "custom"}
    client.post("/hosts/new", data={**base, "domain": "own.example.com"})
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "5",
                    "-subj", "/CN=own.example.com", "-addext", "subjectAltName=DNS:own.example.com",
                    "-keyout", str(tmp_path / "k.pem"), "-out", str(tmp_path / "c.pem")], check=True, capture_output=True)
    r = client.post("/hosts/own.example.com", data={"csrf": tok, "action": "upload_cert", "fullchain": (tmp_path / "c.pem").read_text(),
                                                   "privkey": (tmp_path / "k.pem").read_text()})
    assert r.status_code == 200 and "installed certificate" in r.text
    assert (paths.certs_dir / "own.example.com" / "privkey.pem").exists()
    keybody = (tmp_path / "k.pem").read_text().splitlines()[1]
    assert keybody not in client.get("/hosts/own.example.com").text                                 # key never echoed
    r = client.post("/hosts/own.example.com", data={"csrf": tok, "action": "upload_cert", "fullchain": "junk", "privkey": "junk"})
    assert "Failed" in r.text
    assert "valid until" in client.get("/hosts/own.example.com").text
    assert client.get("/certs").status_code == 200 and "own certificate" in client.get("/certs").text


def test_favicon_and_dns_settings(client, paths):
    assert client.get("/static/favicon.svg").headers["content-type"].startswith("image/svg")
    assert client.get("/favicon.ico").status_code == 200
    assert 'rel="icon"' in client.get("/login").text
    login(client)
    tok = csrf_of(client, "/settings")
    base = {"csrf": tok, "email": "me@example.com", "server": "staging"}
    r = client.post("/settings", data={**base, "p_name": ["", "infomaniak"], "p_plugin": ["", "infomaniak"],
                                      "p_credentials": ["", "/etc/letsencrypt/x.ini"], "p_wait": ["60", "90"], "p_default": "1"})
    assert r.status_code == 303
    acme = st.load_settings(paths)[0]["acme"]
    assert acme["dns_providers"] == {"infomaniak": {"plugin": "infomaniak", "credentials": "/etc/letsencrypt/x.ini", "propagation_seconds": 90}}
    assert acme["dns_default"] == "infomaniak" and acme["dns"] is None
    r = client.post("/settings", data={**base, "p_name": ["infomaniak"], "p_plugin": ["infomaniak"],
                                      "p_credentials": ["relative/path"], "p_wait": ["90"], "p_default": "0"})
    assert r.status_code == 400 and "relative/path" in r.text


def test_named_dns_providers_in_ui(client, paths):
    login(client)
    tok = csrf_of(client, "/settings")
    base = {"csrf": tok, "email": "me@example.com", "server": "staging"}
    r = client.post("/settings", data={**base, "p_name": ["inf", "cf", ""], "p_plugin": ["infomaniak", "cloudflare", ""],
                                      "p_credentials": ["/etc/letsencrypt/i.ini", "/etc/letsencrypt/cf.ini", ""],
                                      "p_wait": ["90", "60", "60"], "p_default": "0"})
    assert r.status_code == 303
    acme = st.load_settings(paths)[0]["acme"]
    assert set(acme["dns_providers"]) == {"inf", "cf"} and acme["dns_default"] == "inf"
    page = client.get("/settings").text
    assert page.count('name="p_name"') == 3 and "default" in page          # two providers + the empty "add" card
    r = client.post("/settings", data={**base, "p_name": ["inf", "inf"], "p_plugin": ["infomaniak", "infomaniak"],
                                      "p_credentials": ["/etc/letsencrypt/i.ini"] * 2, "p_wait": ["60", "60"], "p_default": "0"})
    assert r.status_code == 400 and "two providers" in r.text
    r = client.post("/settings", data={**base, "p_name": ["inf", "cf"], "p_plugin": ["infomaniak", "cloudflare"],
                                      "p_credentials": ["/etc/letsencrypt/i.ini", "/etc/letsencrypt/cf.ini"],
                                      "p_wait": ["60", "60"], "p_default": "0", "p_remove": "1"})
    assert set(st.load_settings(paths)[0]["acme"]["dns_providers"]) == {"inf"}
    tok = csrf_of(client)
    h = {"csrf": tok, "upstream": "http://10.0.0.5", "enabled": "on", "tls": "on", "force_https": "on", "challenge": "dns", "dns_provider": "inf"}
    assert client.post("/hosts/new", data={**h, "domain": "a.example.com"}).status_code == 303
    assert st.load(paths)[0][0]["tls"]["dns_provider"] == "inf"
    # removing a provider that a host still names is refused
    r = client.post("/settings", data={**base, "p_name": [""], "p_plugin": [""], "p_credentials": [""], "p_wait": ["60"]})
    assert r.status_code == 400


def test_certs_page_select_and_inline_upload(client, paths, tmp_path, monkeypatch):
    import subprocess
    monkeypatch.setenv("DEBREV_ROOT", str(tmp_path))
    login(client)
    tok = csrf_of(client)
    base = {"csrf": tok, "upstream": "http://10.0.0.5", "enabled": "on", "tls": "on", "force_https": "on"}
    client.post("/hosts/new", data={**base, "domain": "le.example.com"})
    # custom host created WITHOUT a certificate: goes to its page to add one
    r = client.post("/hosts/new", data={**base, "domain": "own.example.com", "cert": "custom"})
    assert r.status_code == 303 and r.headers["location"] == "/hosts/own.example.com"
    page = client.get("/certs").text
    assert 'name="name" value="le.example.com"' in page and 'value="own.example.com"' not in page
    assert "Edit certificate" in page and "/hosts/own.example.com#owncert" in page
    assert client.post("/certs", data={"csrf": tok, "action": "selected"}).status_code == 303          # nothing ticked
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "5",
                    "-subj", "/CN=own.example.com", "-addext", "subjectAltName=DNS:own.example.com",
                    "-keyout", str(tmp_path / "k.pem"), "-out", str(tmp_path / "c.pem")], check=True, capture_output=True)
    # the certificate box is part of the normal host form
    r = client.post("/hosts/own.example.com", data={**base, "cert": "custom", "fullchain": (tmp_path / "c.pem").read_text(),
                                                   "privkey": (tmp_path / "k.pem").read_text()})
    assert r.status_code == 200 and "installed" in r.text and (paths.certs_dir / "own.example.com" / "fullchain.pem").exists()
    r = client.post("/hosts/own.example.com", data={**base, "cert": "custom", "fullchain": "only half"})
    assert "NOT installed" in r.text


def test_certificate_job_progress(client, paths, monkeypatch):
    import io
    import time

    class FakePopen:
        def __init__(self, cmd, **kw):
            self.cmd = cmd
            names = cmd[3:]
            lines = ["@@ total 2", f"@@ start {names[0]}", f"@@ done {names[0]} ok issued", f"@@ start {names[1]}",
                     f"@@ done {names[1]} fail Domain: x | Detail: nope", "@@ applying", "applied 3 host(s)"]
            self.stdout = io.StringIO("\n".join(lines) + "\n")

        def wait(self):
            return 1
    import subprocess
    import types
    monkeypatch.setattr(web, "subprocess", types.SimpleNamespace(
        Popen=FakePopen, run=subprocess.run, PIPE=subprocess.PIPE, STDOUT=subprocess.STDOUT,
        TimeoutExpired=subprocess.TimeoutExpired))
    login(client)
    tok = csrf_of(client, "/certs")
    assert client.post("/certs/job", data={"csrf": tok}).status_code == 400            # nothing ticked
    assert client.post("/certs/job", data={"name": ["a.example.com"]}).status_code == 403   # CSRF
    r = client.post("/certs/job", data={"csrf": tok, "name": ["a.example.com", "b.example.com"]})
    assert r.status_code == 200
    jid = r.json()["id"]
    for _ in range(50):
        v = client.get(f"/certs/job/{jid}").json()
        if v["state"] == "finished":
            break
        time.sleep(0.1)
    assert v["state"] == "finished" and v["done"] == 2 and v["total"] == 2 and v["ok"] is False
    states = {i["name"]: i["state"] for i in v["items"]}
    assert states == {"a.example.com": "ok", "b.example.com": "fail"}
    assert "applied 3" in v["log"] and "nope" in [i for i in v["items"] if i["name"] == "b.example.com"][0]["message"]
    assert client.get("/certs/job/nope").status_code == 404
    other = TestClient(client.app, client=("192.168.1.9", 1), follow_redirects=False)
    assert other.get(f"/certs/job/{jid}").status_code == 303                           # login required


def test_csp_allows_fetch_to_self(client):
    csp = client.get("/login").headers["content-security-policy"]
    assert "connect-src 'self'" in csp and "script-src 'self'" in csp and "unsafe-inline" not in csp


def test_job_for_request_missing_discovers_items(client, monkeypatch):
    import io
    import subprocess
    import time
    import types
    seen = {}

    class FakePopen:
        def __init__(self, cmd, **kw):
            seen["cmd"], seen["env"] = cmd, kw.get("env", {})
            self.stdout = io.StringIO("@@ total 2\n@@ start x.example.com\n@@ done x.example.com ok issued\n"
                                      "@@ done y.example.com fail backing off\n")

        def wait(self):
            return 1
    monkeypatch.setattr(web, "subprocess", types.SimpleNamespace(
        Popen=FakePopen, run=subprocess.run, PIPE=subprocess.PIPE, STDOUT=subprocess.STDOUT, TimeoutExpired=subprocess.TimeoutExpired))
    login(client)
    tok = csrf_of(client, "/certs")
    assert client.post("/certs/job", data={"csrf": tok, "action": "bogus"}).status_code == 400
    r = client.post("/certs/job", data={"csrf": tok, "action": "issue"})
    jid = r.json()["id"]
    for _ in range(50):
        v = client.get(f"/certs/job/{jid}").json()
        if v["state"] == "finished":
            break
        time.sleep(0.1)
    assert seen["cmd"][-2:] == ["certs", "issue"] and seen["env"]["DEBREV_PROGRESS"] == "1"
    assert v["total"] == 2 and v["done"] == 2 and v["title"].startswith("Requesting")
    assert {i["name"]: i["state"] for i in v["items"]} == {"x.example.com": "ok", "y.example.com": "fail"}
    r = client.post("/certs/job", data={"csrf": tok, "action": "renew"})
    assert r.status_code == 200


def test_running_job_indicator(client, monkeypatch):
    import subprocess
    import threading
    import time
    import types
    release = threading.Event()

    class Slow:
        def __init__(self, cmd, **kw):
            def lines():
                yield "@@ total 3\n"
                yield "@@ start a.example.com\n"
                release.wait(10)
            self.stdout = lines()

        def wait(self):
            return 0
    monkeypatch.setattr(web, "subprocess", types.SimpleNamespace(
        Popen=Slow, run=subprocess.run, PIPE=subprocess.PIPE, STDOUT=subprocess.STDOUT, TimeoutExpired=subprocess.TimeoutExpired))
    login(client)
    tok = csrf_of(client, "/certs")
    assert client.get("/jobs/active").json() == {"running": []}
    assert 'id="jobind"' in client.get("/").text and 'id="jobind" class="jobind" href="/certs" title="A background job is running" hidden' in client.get("/").text
    client.post("/certs/job", data={"csrf": tok, "action": "issue"})
    for _ in range(40):
        run = client.get("/jobs/active").json()["running"]
        if run and run[0]["total"] == 3:
            break
        time.sleep(0.1)
    assert run and run[0]["title"].startswith("Requesting") and run[0]["total"] == 3
    page = client.get("/hosts").text                       # any page shows it without JavaScript
    assert "hidden>" not in page.split('id="jobind"')[1].split(">")[0] + ">" and "Certs 0/3" in page
    release.set()
    for _ in range(50):
        if not client.get("/jobs/active").json()["running"]:
            break
        time.sleep(0.1)
    assert client.get("/jobs/active").json()["running"] == []
    other = TestClient(client.app, client=("192.168.1.9", 1), follow_redirects=False)
    assert other.get("/jobs/active").status_code == 303



def test_wildcard_checkbox(client, paths):
    login(client)
    base = {"csrf": csrf_of(client), "upstream": "http://10.0.0.5", "enabled": "on", "tls": "on", "force_https": "on", "cert": "auto", "challenge": "http"}
    client.post("/hosts/new", data={**base, "domain": "example.com", "wildcard": "on"})
    h = st.load(paths)[0][0]
    assert h["aliases"] == ["*.example.com"] and h["tls"]["challenge"] == "dns"
    assert "checked" in client.get("/hosts/example.com").text.split('name="wildcard"')[1][:30]
    client.post("/hosts/example.com", data=base)
    h = st.load(paths)[0][0]
    assert h["aliases"] == [] and h["tls"]["challenge"] == "http"


def test_security_page_and_settings(client, paths):
    login(client)
    assert "Security" in client.get("/security").text
    page = client.get("/settings").text
    assert 'name="rate"' in page and 'name="lan_exempt"' in page
    r = client.post("/settings", data={"csrf": csrf_of(client, "/settings"), "server": "production", "rate_limit": "on", "rate": "12", "burst": "50", "connections": "20"})
    assert r.status_code in (200, 303)
    sec = st.load_settings(paths)[0]["security"]
    assert sec == {"rate_limit": True, "rate": 12, "burst": 50, "connections": 20, "lan_exempt": False}
    r = client.post("/settings", data={"csrf": csrf_of(client, "/settings"), "server": "production", "rate": "x", "burst": "1", "connections": "1"})
    assert r.status_code == 400


def test_health_page(client, paths):
    import json, time
    login(client)
    paths.access_log.write_text(json.dumps({"t": time.time(), "ip": "8.8.8.8", "host": "a.example.com", "m": "GET", "u": "/x", "s": 200, "b": 5, "rt": 0.01, "us": "200", "ua": "u"}) + "\n")
    for rng in ("1h", "24h", "7d", "bogus"):
        r = client.get(f"/health?range={rng}")
        assert r.status_code == 200 and "8.8.8.8" in r.text and "<svg" in r.text
    assert "Errors only" in client.get("/health?only=errors").text


def test_health_shows_system_load(client):
    login(client)
    t = client.get("/health").text
    assert "<meter" in t and "Memory" in t and "CPU" in t


def test_multiline_snippet_is_stored_as_readable_block(client, paths):
    login(client)
    base = {"csrf": csrf_of(client), "adv": "1", "upstream": "http://10.0.0.5", "enabled": "on", "tls": "on", "force_https": "on",
            "buffering": "on", "request_buffering": "on", "rate_limit": "on", "custom_snippet": "location /a { return 204; }\nlocation /b { return 204; }"}
    client.post("/hosts/new", data={**base, "domain": "a.example.com"})
    text = (paths.state / "hosts" / "a.example.com.yaml").read_text()
    assert "custom_snippet: |" in text and "\n  location /b" in text


def test_export_download_and_import_preview_then_save(client, paths):
    from debrev import portable
    login(client)
    (paths.state / "hosts" / "a.example.com.yaml").write_text("domain: a.example.com\nupstream: http://10.0.0.1:3000\n")
    st.commit(paths, "seed", "t")
    r = client.get("/export")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and "a.example.com" in r.text
    assert "no-store" in r.headers["cache-control"]
    bundle = r.text.replace("a.example.com", "n.example.com")
    tok = csrf_of(client, "/import")
    assert client.post("/import/preview", data={"csrf": "x", "bundle": bundle}).status_code == 403
    r = client.post("/import/preview", data={"csrf": tok, "bundle": bundle})
    assert r.status_code == 200 and "n.example.com" in r.text and "Save 1 change" in r.text
    assert not (paths.state / "hosts" / "n.example.com.yaml").exists()        # a preview saves nothing
    r = client.post("/import/apply", data={"csrf": tok, "bundle": bundle})
    assert r.status_code == 200 and "Done." in r.text
    assert (paths.state / "hosts" / "n.example.com.yaml").exists()
    r = client.post("/import/preview", data={"csrf": tok, "bundle": "hosts: not-a-list"})
    assert r.status_code == 400
    r = client.post("/import/preview", data={"csrf": tok}, files={"file": ("x.yaml", b"hosts: [{domain: u.example.com, upstream: 'http://10.0.0.9:1'}]")})
    assert r.status_code == 200 and "u.example.com" in r.text


def test_import_page_needs_login(client):
    for url in ("/export", "/import"):
        assert client.get(url).status_code == 303


def test_host_can_use_an_installed_certificate(client, paths):
    from test_certs import _own_cert
    from conftest import write_host
    login(client)
    write_host(paths, "example.com", "domain: example.com\nupstream: http://10.0.0.1:80\naliases: ['*.example.com']\ntls:\n  challenge: dns\n")
    write_host(paths, "other.org", "domain: other.org\nupstream: http://10.0.0.1:81\n")
    st.commit(paths, "seed", "t")
    _own_cert(paths, "other.org", ["other.org"])
    _own_cert(paths, "example.com", ["example.com", "*.example.com"])
    page = client.get("/hosts/new").text
    assert 'value="shared"' in page and 'name="cert_from"' in page
    drop = page.split('name="cert_from"')[1].split("</select>")[0]
    assert drop.index("example.com &ndash;") < drop.index("other.org &ndash;")          # wildcard certificates first
    tok = csrf_of(client)
    r = client.post("/hosts/new", data={"csrf": tok, "domain": "app.example.com", "upstream": "http://10.0.0.2:80",
                                         "cert": "shared", "cert_from": "example.com", "tls": "on", "force_https": "on", "wildcard": "on", "enabled": "on"})
    assert r.status_code == 303, r.text[:300]
    saved = (paths.state / "hosts" / "app.example.com.yaml").read_text()
    assert "cert: shared" in saved and "cert_from: example.com" in saved and "*.app.example.com" not in saved
    assert "cert:example.com" in client.get("/hosts").text
    certs_html = client.get("/certs").text
    assert "also used by: app.example.com" in certs_html
    r = client.post("/hosts/example.com", data={"csrf": tok, "action": "delete"})
    assert r.status_code == 200 and "Cannot remove" in r.text and (paths.state / "hosts" / "example.com.yaml").exists()
    r = client.post("/hosts/new", data={"csrf": tok, "domain": "x.other.org", "upstream": "http://10.0.0.2:80",
                                         "cert": "shared", "cert_from": "other.org", "tls": "on", "enabled": "on"})
    assert r.status_code == 400 and "does not cover x.other.org" in r.text                   # certificate must fit the host


def test_cli_cert_from_and_remove_protection(paths, tmp_path):
    import subprocess, sys
    from test_certs import _own_cert
    from conftest import write_host
    from debrev.paths import APP_DIR
    write_host(paths, "example.com", "domain: example.com\nupstream: http://10.0.0.1:80\naliases: ['*.example.com']\ntls:\n  challenge: dns\n")
    st.commit(paths, "seed", "t")
    _own_cert(paths, "example.com", ["example.com", "*.example.com"])
    root = tmp_path / "r"
    (root / "var/lib/debrev").mkdir(parents=True)
    (root / "etc/debrev").mkdir(parents=True)
    import shutil
    env = {"PATH": "/usr/bin:/bin", "DEBREV_ROOT": str(root), "DEBREV_AUTHOR": "t"}
    run = lambda *a: subprocess.run([sys.executable, "-m", "debrev", *a], cwd=APP_DIR, capture_output=True, text=True, env=env)
    assert run("init").returncode == 0
    shutil.copy(paths.state / "hosts" / "example.com.yaml", root / "var/lib/debrev/state/hosts/example.com.yaml")
    shutil.copy(paths.lib / "certs.json", root / "var/lib/debrev/certs.json")
    r = run("host", "add", "app.example.com", "http://10.0.0.2:80", "--cert-from", "example.com")
    assert r.returncode == 0, r.stdout + r.stderr
    r = run("host", "rm", "example.com")
    assert r.returncode != 0 and "other hosts use its certificate" in (r.stdout + r.stderr)
    assert (root / "var/lib/debrev/state/hosts/example.com.yaml").exists()


def test_restoring_a_version_identical_to_the_newest_changes_nothing(client, paths):
    from conftest import write_host
    login(client)
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:1\n")
    base = st.commit(paths, "one", "t")
    write_host(paths, "b.example.com", "domain: b.example.com\nupstream: http://10.0.0.1:2\n")
    st.commit(paths, "add b", "t")
    (paths.state / "hosts" / "b.example.com.yaml").unlink()
    st.commit(paths, "remove b", "t")                    # same files as `base` again
    assert base in st.same_as_head(paths)
    page = client.get("/history").text
    assert "same as newest" in page and page.count("/rollback") == 2           # not the newest, not the identical one: just the first commit and "add b"
    before = len(st.log(paths, 20))
    r = client.post(f"/history/{base[:12]}/rollback", data={"csrf": csrf_of(client, "/history")})
    assert r.status_code == 303 and len(st.log(paths, 20)) == before
    msg = client.get("/history").text
    assert "Nothing changed" in msg and "Not live until you apply" not in msg
