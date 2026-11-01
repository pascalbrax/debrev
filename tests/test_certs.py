import json
import shutil
import stat
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from conftest import write_host
from debrev import certs, state as st

HAVE_OPENSSL = shutil.which("openssl") is not None


def fake_certbot(tmp_path, paths, fail=False):
    """A certbot stand-in that records its arguments and writes a self-signed cert."""
    log = tmp_path / "certbot.log"
    f = tmp_path / "fake-certbot"
    body = f'''#!/bin/bash
echo "$@" >> {log}
{"echo 'Domain: x.example.com'; echo 'Detail: nope'; exit 1" if fail else ""}
name=""; doms=(); while [ $# -gt 0 ]; do case "$1" in --cert-name) name="$2"; shift;; -d) doms+=("$2"); shift;; esac; shift; done
d={paths.letsencrypt}/live/$name; mkdir -p $d
san=$(printf "DNS:%s," "${{doms[@]}}"); san=${{san%,}}
openssl req -x509 -newkey rsa:2048 -nodes -days 90 -subj "/CN=${{doms[0]}}" -addext "subjectAltName=$san" -keyout $d/privkey.pem -out $d/fullchain.pem 2>/dev/null
'''
    f.write_text(body)
    f.chmod(f.stat().st_mode | stat.S_IEXEC)
    paths.certbot_cmd = (str(f),)
    return log


def settings(paths, **acme):
    import yaml
    f = paths.state / "settings.yaml"
    d = yaml.safe_load(f.read_text())
    d["acme"] = {"email": "a@example.org", **acme}
    f.write_text(yaml.safe_dump(d))
    st.commit(paths, "settings")
    return st.load_settings(paths)[0]


def host(paths, name, extra=""):
    write_host(paths, name, f"domain: {name}\nupstream: http://10.0.0.1:80\n{extra}")
    st.commit(paths, f"add {name}")
    return st.load(paths)[0]


def test_http_command_line(paths):
    s = settings(paths)
    hosts = host(paths, "a.example.com", "aliases: [www.a.example.com]\n")
    item = certs.plan(hosts)[0]
    cmd = certs.build_cmd(paths, s, item)
    assert cmd[0] == "certbot" and "--webroot" in cmd and str(paths.acme) in cmd
    assert cmd.count("-d") == 2 and "--cert-name" in cmd and "a.example.com" in cmd
    assert certs.PRODUCTION_URL in cmd and "--non-interactive" in cmd


def test_wildcard_forces_dns_and_names_cert_without_star(paths):
    s = settings(paths, dns={"plugin": "cloudflare", "credentials": "/etc/debrev/cf.ini", "propagation_seconds": 30})
    hosts = host_wild = None
    write_host(paths, "wild", "domain: '*.example.com'\naliases: [example.com]\nupstream: http://10.0.0.1:80\n")
    st.commit(paths, "wild")
    hosts = st.load(paths)[0]
    item = certs.plan(hosts)[0]
    assert item.name == "example.com" and item.challenge == "dns"
    cmd = certs.build_cmd(paths, s, item)
    assert "dns-cloudflare" in cmd and "--authenticator" in cmd and "--dns-cloudflare-credentials" in cmd and "30" in cmd
    assert "--webroot" not in cmd


def test_dns_without_settings_or_credentials_is_reported_not_run(paths, tmp_path):
    log = fake_certbot(tmp_path, paths)
    s = settings(paths)
    hosts = host(paths, "a.example.com", "tls:\n  challenge: dns\n")
    r = certs.issue_missing(paths, hosts, s)
    assert not r[0]["ok"] and "DNS challenge" in r[0]["message"] and not log.exists()
    s = settings(paths, dns={"plugin": "cloudflare", "credentials": "/nonexistent/cf.ini"})
    r = certs.issue_missing(paths, hosts, s)
    assert "not found" in r[0]["message"] and not log.exists()


def test_no_email_is_reported_not_run(paths, tmp_path):
    log = fake_certbot(tmp_path, paths)
    hosts = host(paths, "a.example.com")
    s = st.load_settings(paths)[0]
    r = certs.issue_missing(paths, hosts, s)
    assert "email" in r[0]["message"] and not log.exists()


@pytest.mark.skipif(not HAVE_OPENSSL, reason="needs openssl")
def test_issue_then_nothing_more_to_do_and_expansion(paths, tmp_path):
    log = fake_certbot(tmp_path, paths)
    s = settings(paths)
    hosts = host(paths, "a.example.com")
    r = certs.issue_missing(paths, hosts, s)
    assert r[0]["ok"] and len(log.read_text().splitlines()) == 1
    assert certs.issue_missing(paths, hosts, s) == []          # nothing to do
    assert len(log.read_text().splitlines()) == 1
    hosts = host(paths, "a.example.com", "aliases: [b.example.com]\n")
    r = certs.issue_missing(paths, hosts, s)                   # names changed
    assert r[0]["reason"] == "host names changed" and r[0]["ok"]
    assert certs.cert_info(paths, "a.example.com")["sans"] == {"a.example.com", "b.example.com"}


@pytest.mark.skipif(not HAVE_OPENSSL, reason="needs openssl")
def test_failure_backs_off_and_force_overrides(paths, tmp_path):
    log = fake_certbot(tmp_path, paths, fail=True)
    s = settings(paths)
    hosts = host(paths, "a.example.com")
    now = datetime.now(timezone.utc)
    r = certs.issue_missing(paths, hosts, s, now=now)
    assert not r[0]["ok"] and "nope" in r[0]["message"]
    r = certs.issue_missing(paths, hosts, s, now=now + timedelta(minutes=5))
    assert "backing off" in r[0]["message"] and len(log.read_text().splitlines()) == 1
    r = certs.issue_missing(paths, hosts, s, now=now + timedelta(minutes=5), force=True)
    assert len(log.read_text().splitlines()) == 2
    r = certs.issue_missing(paths, hosts, s, now=now + timedelta(hours=3))   # backoff expired (2nd failure -> 2h)
    assert len(log.read_text().splitlines()) == 3
    status = json.loads(paths.cert_status.read_text())["a.example.com"]
    assert status["failures"] >= 2


@pytest.mark.skipif(not HAVE_OPENSSL, reason="needs openssl")
def test_staging_cert_is_replaced_when_production_configured(paths, tmp_path):
    log = fake_certbot(tmp_path, paths)
    s = settings(paths, server="staging")
    hosts = host(paths, "a.example.com")
    certs.issue_missing(paths, hosts, s)
    cert = paths.certs_dir / "a.example.com" / "fullchain.pem"
    key = paths.certs_dir / "a.example.com" / "privkey.pem"
    (paths.certs_dir / "a.example.com").unlink()      # it is a symlink to a version dir
    (paths.certs_dir / "a.example.com").mkdir()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "60", "-subj",
                    "/O=(STAGING) Let's Encrypt/CN=x", "-addext", "subjectAltName=DNS:a.example.com",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    assert certs.reason(paths, certs.plan(hosts)[0], s) is None
    prod = settings(paths, server="production")
    assert "staging" in certs.reason(paths, certs.plan(hosts)[0], prod)
    certs.issue_missing(paths, hosts, prod)
    assert "--force-renewal" in log.read_text().splitlines()[-1]


def test_settings_validation(paths):
    import yaml
    f = paths.state / "settings.yaml"
    for bad in ({"email": "not an email"}, {"server": "mars"}, {"server": "custom"},
                {"dns": {"plugin": "Cloud Flare", "credentials": "/x"}}, {"dns": {"plugin": "x", "credentials": "rel"}},
                {"bogus": 1}):
        d = yaml.safe_load(f.read_text()); d["acme"] = bad; f.write_text(yaml.safe_dump(d))
        assert st.load_settings(paths)[1], bad


def test_cert_name_collision_detected(paths):
    write_host(paths, "a", "domain: example.com\nupstream: http://10.0.0.1:80\n")
    write_host(paths, "b", "domain: '*.example.com'\nupstream: http://10.0.0.1:80\n")
    errs = st.load(paths)[2]
    assert any("collides" in e for e in errs)


@pytest.mark.skipif(not HAVE_OPENSSL, reason="needs openssl")
def test_summary_is_readable_without_access_to_live(paths, tmp_path, monkeypatch):
    fake_certbot(tmp_path, paths)
    s = settings(paths)
    hosts = host(paths, "a.example.com")
    certs.issue_missing(paths, hosts, s)
    certs.refresh_summary(paths, hosts)
    real = certs.Path.exists

    def denied(self, *a, **k):
        if "fullchain.pem" in str(self):
            raise PermissionError
        return real(self, *a, **k)
    monkeypatch.setattr(certs.Path, "exists", denied)
    info = certs.cert_info(paths, "a.example.com")
    assert info["sans"] == {"a.example.com"} and info["days_left"] > 80
    assert certs.table(paths, hosts, s)[0]["state"] == "ok"


def _dns_settings(p, path):
    import yaml
    f = p.state / "settings.yaml"
    d = yaml.safe_load(f.read_text())
    d["acme"] = {"email": "a@example.com", "dns": {"plugin": "infomaniak", "credentials": str(path)}}
    f.write_text(yaml.safe_dump(d))


def test_dns_credentials_propagate(paths, tmp_path):
    import os
    from debrev import certs as cr
    paths.letsencrypt.mkdir(parents=True)
    cred = paths.letsencrypt / "infomaniak.ini"
    _dns_settings(paths, cred)
    assert cr.export_credentials(paths) == []              # nothing to send yet
    cred.write_text("dns_infomaniak_token = SECRET\n")
    os.utime(cred, (1000, 1000))
    sent = cr.export_credentials(paths)[0]
    assert sent["content"].startswith("dns_infomaniak_token") and sent["mtime"] == 1000
    # the twin has the same settings but no file: installed 0600
    other = Paths_like(paths, tmp_path / "twin")
    _dns_settings(other, other.letsencrypt / "infomaniak.ini")
    sent["path"] = str(other.letsencrypt / "infomaniak.ini")
    r = cr.import_credentials(other, sent)
    assert r["ok"] and r["message"] == "installed"
    f = other.letsencrypt / "infomaniak.ini"
    assert f.read_text() == cred.read_text() and (f.stat().st_mode & 0o777) == 0o600
    assert cr.import_credentials(other, sent)["message"] == "already up to date"
    # a different local file that is newer is kept
    f.write_text("dns_infomaniak_token = OTHER\n")
    assert "newer" in cr.import_credentials(other, sent)["message"] and "OTHER" in f.read_text()
    # path must be the one named in the settings; junk is refused
    assert not cr.import_credentials(other, {**sent, "path": "/etc/passwd"})["ok"]
    assert not cr.import_credentials(other, {**sent, "content": "x" * 5000})["ok"]
    assert not cr.import_credentials(other, {**sent, "content": ""})["ok"]


def Paths_like(base, root):
    import dataclasses
    from debrev import state as st
    p = dataclasses.replace(base, etc=root / "etc", lib=root / "lib", letsencrypt=root / "le", cache=root / "cache")
    st.init(p)
    p.letsencrypt.mkdir(parents=True)
    return p


# ---- uploaded (custom) certificates -------------------------------------------

def _selfsigned(tmp_path, names, days=30, tag="a"):
    import subprocess
    key, crt = tmp_path / f"{tag}.key", tmp_path / f"{tag}.crt"
    san = ",".join(f"DNS:{n}" for n in names)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-days", str(days), "-subj", f"/CN={names[0]}", "-addext", f"subjectAltName={san}",
                    "-keyout", str(key), "-out", str(crt)], check=True, capture_output=True)
    return crt.read_bytes(), key.read_bytes()


def _custom_host(paths, domain="own.example.com", extra=""):
    (paths.state / "hosts" / f"{domain}.yaml").write_text(
        f"domain: {domain}\nupstream: http://127.0.0.1:1\ntls:\n  cert: custom\n{extra}")


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs openssl")
def test_upload_custom_certificate(paths, tmp_path):
    from debrev import certs as cr
    _custom_host(paths)
    assert st.load(paths)[2] == []
    hosts = st.load(paths)[0]
    assert [i.kind for i in cr.plan(hosts, custom=True)] == ["custom"] and cr.plan(hosts) == []
    crt, key = _selfsigned(tmp_path, ["own.example.com"])
    r = cr.upload_custom(paths, "own.example.com", crt, key)
    assert "installed certificate" in r.message
    assert (paths.certs_dir / "own.example.com" / "fullchain.pem").read_bytes() == crt
    assert oct((paths.certs_dir / "own.example.com" / "privkey.pem").stat().st_mode & 0o777) == "0o600"
    row = [x for x in cr.table(paths, st.load(paths)[0], st.load_settings(paths)[0]) if x["name"] == "own.example.com"][0]
    assert row["kind"] == "custom" and row["state"] == "ok" and "needs" not in row
    # rendered config serves the uploaded files
    from debrev.render import render
    files, warns = render(paths, st.load(paths)[0], {}, resolved={})
    assert any("own.example.com/fullchain.pem" in t for t in files.values())


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs openssl")
def test_upload_rejections(paths, tmp_path):
    from debrev import certs as cr
    _custom_host(paths, extra="")
    crt, key = _selfsigned(tmp_path, ["other.example.com"])
    assert "does not cover" in cr.upload_custom(paths, "own.example.com", crt, key).message
    crt2, key2 = _selfsigned(tmp_path, ["own.example.com"], tag="b")
    assert "does not match" in cr.upload_custom(paths, "own.example.com", crt2, key).message
    assert "not a PEM" in cr.upload_custom(paths, "own.example.com", b"junk", key2).message
    assert "not a PEM" in cr.upload_custom(paths, "own.example.com", crt2, b"junk").message
    enc = key2.replace(b"PRIVATE KEY", b"ENCRYPTED PRIVATE KEY")
    assert "password protected" in cr.upload_custom(paths, "own.example.com", crt2, enc).message
    assert "not an enabled HTTPS host" in cr.upload_custom(paths, "nothere.example.com", crt2, key2).message
    # a host using Let's Encrypt cannot take an upload
    write_host(paths, "le", "domain: le.example.com\nupstream: http://127.0.0.1:1\n")
    assert "own certificate" in cr.upload_custom(paths, "le.example.com", crt2, key2).message
    assert not (paths.certs_dir / "own.example.com").exists()


def test_wildcard_coverage():
    from debrev.certs import covers
    assert covers({"*.example.com"}, "a.example.com")
    assert not covers({"*.example.com"}, "a.b.example.com")
    assert not covers({"*.example.com"}, "example.com")
    assert covers({"example.com", "www.example.com"}, "www.example.com")
    assert covers({"*.example.com"}, "*.example.com") and not covers({"example.com"}, "*.example.com")


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs openssl")
def test_custom_certificate_sync_rules(paths, tmp_path):
    """The more recently installed copy wins, in both directions, and identical content is a no-op."""
    import dataclasses
    from debrev import certs as cr
    _custom_host(paths)
    hosts = st.load(paths)[0]
    old_crt, old_key = _selfsigned(tmp_path, ["own.example.com"], days=90, tag="o")
    new_crt, new_key = _selfsigned(tmp_path, ["own.example.com"], days=10, tag="n")   # shorter life but uploaded later
    cr.install_cert(paths, "own.example.com", old_crt, old_key, mtime=1000)
    res = cr.import_certs(paths, {"certs": {"own.example.com": {"fullchain": new_crt.decode(), "privkey": new_key.decode(), "mtime": 2000}}}, hosts)
    assert res[0]["message"] == "installed"                       # older expiry, newer upload: accepted
    assert (paths.certs_dir / "own.example.com" / "fullchain.pem").read_bytes() == new_crt
    res = cr.import_certs(paths, {"certs": {"own.example.com": {"fullchain": old_crt.decode(), "privkey": old_key.decode(), "mtime": 1500}}}, hosts)
    assert "newer; kept" in res[0]["message"]                     # stale copy cannot overwrite
    res = cr.import_certs(paths, {"certs": {"own.example.com": {"fullchain": new_crt.decode(), "privkey": new_key.decode(), "mtime": 2000}}}, hosts)
    assert res[0]["message"] == "already up to date"
    bad = cr.import_certs(paths, {"certs": {"own.example.com": {"fullchain": new_crt.decode(), "privkey": old_key.decode(), "mtime": 9}}}, hosts)
    assert not bad[0]["ok"]


def test_named_dns_providers(paths):
    import yaml
    from debrev import certs as cr
    f = paths.state / "settings.yaml"
    d = yaml.safe_load(f.read_text())
    d["acme"] = {"email": "a@example.com", "server": "staging",
                 "dns": {"plugin": "infomaniak", "credentials": "/etc/letsencrypt/i.ini"},
                 "dns_providers": {"cf": {"plugin": "cloudflare", "credentials": "/etc/letsencrypt/cf.ini", "propagation_seconds": 30}}}
    f.write_text(yaml.safe_dump(d))
    write_host(paths, "a", "domain: a.example.com\nupstream: http://127.0.0.1:1\ntls: {challenge: dns}\n")
    write_host(paths, "b", "domain: b.example.org\nupstream: http://127.0.0.1:1\ntls: {challenge: dns, dns_provider: cf}\n")
    hosts, _, errs, _ = st.load(paths)
    assert errs == []
    settings = st.load_settings(paths)[0]
    items = {i.name: i for i in cr.plan(hosts)}
    cmd_a = cr.build_cmd(paths, settings, items["a.example.com"])
    cmd_b = cr.build_cmd(paths, settings, items["b.example.org"])
    assert "dns-infomaniak" in cmd_a and "/etc/letsencrypt/i.ini" in cmd_a
    assert "dns-cloudflare" in cmd_b and "/etc/letsencrypt/cf.ini" in cmd_b and "30" in cmd_b
    assert [str(x) for x in cr.creds_paths(paths)] == []     # outside the test's letsencrypt dir -> never synced
    write_host(paths, "c", "domain: c.example.org\nupstream: http://127.0.0.1:1\ntls: {challenge: dns, dns_provider: nope}\n")
    assert any("dns_provider 'nope'" in e for e in st.load(paths)[2])


@pytest.mark.skipif(not HAVE_OPENSSL, reason="needs openssl")
def test_renew_selected_only_touches_chosen(paths, tmp_path, monkeypatch):
    monkeypatch.setenv("DEBREV_ROOT", str(tmp_path))
    log = fake_certbot(tmp_path, paths)
    s = settings(paths)
    hosts = host(paths, "a.example.com")
    write_host(paths, "b", "domain: b.example.com\nupstream: http://127.0.0.1:1\n")
    hosts = st.load(paths)[0]
    assert all(r["ok"] for r in certs.issue_missing(paths, hosts, s))
    log.write_text("")
    # nothing is due, but the admin picked b: only b is renewed, with --force-renewal
    r = certs.issue_missing(paths, hosts, s, force=True, only={"b.example.com"})
    assert [x["name"] for x in r] == ["b.example.com"] and r[0]["ok"]
    lines = log.read_text().splitlines()
    assert len(lines) == 1 and "b.example.com" in lines[0] and "--force-renewal" in lines[0]
    # failures of other certificates do not block a selected one (backoff is ignored for picks)
    res = certs.run_selected(paths, ["nope.example.com"])
    assert not res.ok and "not a Let's Encrypt certificate" in res.message
    assert not certs.run_selected(paths, []).ok


def test_credentials_files_are_made_private(paths):
    from debrev import certs as cr
    paths.letsencrypt.mkdir(parents=True)
    cred = paths.letsencrypt / "cf.ini"
    _dns_settings(paths, cred)
    cred.write_text("dns_cloudflare_api_token = x\n")
    cred.chmod(0o644)
    assert cr.secure_creds(paths) == [str(cred)] and (cred.stat().st_mode & 0o777) == 0o600
    assert cr.secure_creds(paths) == []


@pytest.mark.skipif(not HAVE_OPENSSL, reason="needs openssl")
def test_table_flags_certificate_that_no_longer_matches_the_host(paths, tmp_path):
    fake_certbot(tmp_path, paths)
    s = settings(paths)
    certs.issue_missing(paths, host(paths, "a.example.com"), s)
    assert certs.table(paths, st.load(paths)[0], s)[0]["state"] == "ok"
    hosts = host(paths, "a.example.com", "aliases: ['*.example.com']\n")        # the admin adds a wildcard name
    row = certs.table(paths, hosts, s)[0]
    assert row["state"] == "outdated" and row["needs"] == "host names changed"


def test_names_covered_by_a_wildcard_are_not_requested_separately(paths):
    write_host(paths, "w", "domain: example.com\naliases: ['*.example.com', a.example.com, b.c.example.com, other.org]\nupstream: http://10.0.0.1:80\n")
    item = certs.plan(st.load(paths)[0])[0]
    assert item.domains == ["example.com", "*.example.com", "b.c.example.com", "other.org"]
