import shutil
import subprocess

import pytest
import yaml

from conftest import have_nginx, write_host
from debrev import state as st
from debrev.render import render

SAMPLE = {
    "domain": "app.example.com", "upstream": "http://127.0.0.1:3000",
    "websockets": True, "max_body": "100m",
    "cache": {"enabled": True, "ttl": "5m", "bypass_cookies": ["session"]},
    "response_headers": {"X-Frame-Options": "SAMEORIGIN"},
    "request_headers": {"X-Env": "prod"},
    "access_list": "office",
    "custom_locations": [{"path": "/api/", "upstream": "http://127.0.0.1:8080"}],
    "custom_snippet": 'location /healthz { return 200 "ok"; }',
}


def load(p):
    hosts, acls, errors, warnings = st.load(p)
    assert not errors, errors
    return hosts, acls


def mk_tls(p, domain):
    d = p.certs_dir / domain
    d.mkdir(parents=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", f"/CN={domain}", "-keyout", str(d / "privkey.pem"),
                    "-out", str(d / "fullchain.pem")], check=True, capture_output=True)


def test_features_render(paths):
    (paths.state / "access_lists" / "office.yaml").write_text(yaml.safe_dump({"allow": ["10.0.0.0/8"]}))
    write_host(paths, "app.example.com", yaml.safe_dump(SAMPLE))
    files, warns = render(paths, *load(paths))
    conf = files["host-app_example_com.conf"]
    assert "proxy_set_header Upgrade $http_upgrade;" in conf
    assert "client_max_body_size 100m;" in conf
    assert "proxy_cache debrev_app_example_com;" in conf
    assert "$cookie_session" in conf
    assert 'add_header X-Frame-Options "SAMEORIGIN" always;' in conf
    assert "allow 10.0.0.0/8;" in conf and "deny all;" in conf
    assert "location /api/ {" in conf and "location /healthz" in conf
    assert "proxy_cache_path" in files["00-global.conf"]
    assert warns  # no certificate yet -> plain HTTP warning
    assert "listen 443" not in conf


def test_no_cache_no_websockets_means_no_such_directives(paths):
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:1\n")
    files, _ = render(paths, *load(paths))
    conf = files["host-a_example_com.conf"]
    assert "Upgrade" not in conf and "proxy_cache" not in conf
    assert "proxy_cache_path" not in files["00-global.conf"]


def test_disabled_host_not_rendered(paths):
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:1\nenabled: false\n")
    files, _ = render(paths, *load(paths))
    assert list(files) == ["00-global.conf"]


def test_tls_redirects_and_hsts_when_cert_exists(paths):
    mk_tls(paths, "a.example.com")
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:1\ntls:\n  hsts: true\n")
    files, warns = render(paths, *load(paths))
    conf = files["host-a_example_com.conf"]
    assert not warns
    assert "return 301 https://$host$request_uri;" in conf
    assert "listen 443 ssl;" in conf and "http2 on;" in conf
    assert "Strict-Transport-Security" in conf


def test_duplicate_domain_is_an_error(paths):
    write_host(paths, "a", "domain: a.example.com\nupstream: http://10.0.0.1:1\n")
    write_host(paths, "b", "domain: b.example.com\naliases: [a.example.com]\nupstream: http://10.0.0.1:1\n")
    _, _, errors, _ = st.load(paths)
    assert any("already served" in e for e in errors)


def test_duplicate_yaml_keys_rejected(paths):
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:1\nupstream: http://y:1\n")
    _, _, errors, _ = st.load(paths)
    assert any("duplicate key" in e for e in errors)


@pytest.mark.skipif(not have_nginx or not shutil.which("openssl"), reason="needs nginx and openssl")
def test_generated_config_passes_nginx(paths):
    from debrev.apply import apply
    mk_tls(paths, "app.example.com")
    (paths.state / "access_lists" / "office.yaml").write_text(yaml.safe_dump({"allow": ["10.0.0.0/8"]}))
    write_host(paths, "app.example.com", yaml.safe_dump({**SAMPLE, "tls": {"hsts": True}}))
    write_host(paths, "plain.example.com", "domain: plain.example.com\nupstream: http://127.0.0.1:1\ntls: false\n")
    st.commit(paths, "test")
    res = apply(paths, check_only=True)
    assert res.ok, res.message


def test_hostname_upstream_is_pinned_to_cached_ip(paths):
    from debrev.render import render as rd
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: https://nas:8443/app\npreserve_host: false\n")
    hosts, acls = load(paths)
    files, w = rd(paths, hosts, acls, {"nas": "192.168.1.107"})
    conf = files["host-a_example_com.conf"]
    assert "proxy_pass https://192.168.1.107:8443/app;" in conf
    assert "proxy_ssl_name nas;" in conf and "proxy_set_header Host nas:8443;" in conf
    assert "nas" not in conf.replace("nas:8443", "").replace("proxy_ssl_name nas", "")


def test_unresolved_host_is_skipped_not_fatal(paths):
    from debrev.render import render as rd
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://nowhere:80\n")
    write_host(paths, "b.example.com", "domain: b.example.com\nupstream: http://10.0.0.1:80\n")
    files, w = rd(paths, *load(paths), {})
    assert "host-b_example_com.conf" in files and "host-a_example_com.conf" not in files
    assert any("could not be resolved" in x for x in w)


def test_minio_style_settings_render_and_passes_nginx(paths):
    import shutil
    from debrev.apply import apply
    from debrev import state as st2
    write_host(paths, "s3.example.com", "domain: s3.example.com\nupstream: http://127.0.0.1:9000\ntls: false\nwebsockets: true\nmax_body: 0\nbuffering: false\nrequest_buffering: false\ncustom_snippet: |\n  chunked_transfer_encoding off;\n  ignore_invalid_headers off;\n")
    st2.commit(paths, "s3")
    files, _ = render(paths, *load(paths))
    conf = files["host-s3_example_com.conf"]
    for needle in ("client_max_body_size 0;", "proxy_buffering off;", "proxy_request_buffering off;",
                   "ignore_invalid_headers off;", "chunked_transfer_encoding off;", "Upgrade $http_upgrade"):
        assert needle in conf, needle
    if shutil.which("nginx"):
        res = apply(paths, check_only=True)
        assert res.ok, res.message


def test_buffering_defaults_untouched(paths):
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:1\n")
    files, _ = render(paths, *load(paths))
    assert "proxy_buffering" not in files["host-a_example_com.conf"]


def test_nextcloud_style_settings_pass_nginx_and_keeps_acme_location(paths):
    import shutil
    from debrev.apply import apply
    write_host(paths, "cloud.example.com", "domain: cloud.example.com\nupstream: http://127.0.0.1:8080\ntls: false\nmax_body: 10g\ncustom_snippet: |\n  location ^~ /.well-known {\n      return 301 $scheme://$host/index.php$uri;\n  }\n")
    st.commit(paths, "nc")
    files, _ = render(paths, *load(paths))
    conf = files["host-cloud_example_com.conf"]
    assert "location ^~ /.well-known {" in conf and "client_max_body_size 10g;" in conf
    assert "location ^~ /.well-known/acme-challenge/ {" in conf
    assert "client_body_buffer_size" not in conf
    if shutil.which("nginx"):
        assert apply(paths, check_only=True).ok


def _conf(paths, security=None, host_extra=""):
    from debrev.render import render as rd
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:80\ntls: false\n" + host_extra)
    files, _ = rd(paths, *load(paths), {}, security=security)
    return files["00-global.conf"], files["host-a_example_com.conf"]


def test_rate_limit_rendered_by_default(paths):
    g, h = _conf(paths)
    assert "limit_req_zone $debrev_limit_key zone=debrev_req:10m rate=30r/s;" in g
    assert "client_header_timeout 15s;" in g and "geo $debrev_local" in g
    assert "limit_req zone=debrev_req burst=200 nodelay;" in h and "limit_conn debrev_conn 100;" in h


def test_rate_limit_can_be_off_globally_or_per_host(paths):
    g, h = _conf(paths, {"rate_limit": False})
    assert "limit_req" not in g and "limit_req" not in h and "client_header_timeout" in g
    g, h = _conf(paths, None, "rate_limit: false\n")
    assert "limit_req_zone" in g and "limit_req zone" not in h


def test_rate_limit_lan_not_exempt_and_values(paths):
    g, h = _conf(paths, {"lan_exempt": False, "rate": 5, "burst": 10, "connections": 7})
    assert "geo $debrev_local" not in g and "rate=5r/s" in g
    assert "burst=10 nodelay" in h and "limit_conn debrev_conn 7;" in h


def test_security_settings_validated(paths):
    (paths.state / "settings.yaml").write_text("format: 1\nsecurity: {rate: 0, burst: x, bogus: 1, rate_limit: maybe}\n")
    _, errs = st.load_settings(paths)
    assert len(errs) == 4


def test_per_host_rate_limit_override_gets_its_own_zone(paths):
    from debrev.render import render as rd
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:80\ntls: false\nrate_limit: {rate: 200, burst: 2000, connections: 500}\n")
    write_host(paths, "b.example.com", "domain: b.example.com\nupstream: http://10.0.0.1:80\ntls: false\nrate_limit: {burst: 7}\n")
    files, _ = rd(paths, *load(paths), {})
    g, a, b = files["00-global.conf"], files["host-a_example_com.conf"], files["host-b_example_com.conf"]
    assert "zone=debrev_req_200:10m rate=200r/s;" in g and g.count("limit_req_zone") == 2
    assert "limit_req zone=debrev_req_200 burst=2000 nodelay;" in a and "limit_conn debrev_conn 500;" in a
    assert "limit_req zone=debrev_req burst=7 nodelay;" in b and "limit_conn debrev_conn 100;" in b


@pytest.mark.parametrize("version,old", [("1.22.1", True), ("1.24.0", True), ("1.25.1", False), ("1.26.3", False)])
def test_http2_syntax_follows_the_nginx_version(paths, tmp_path, version, old):
    """Debian 12 ships nginx 1.22, where 'http2 on;' is an unknown directive."""
    fake = tmp_path / "nginx-v"
    fake.write_text(f"#!/bin/sh\necho 'nginx version: nginx/{version}' >&2\n")
    fake.chmod(0o755)
    paths.nginx_cmd = (str(fake),)
    mk_tls(paths, "a.example.com")
    write_host(paths, "a.example.com", "domain: a.example.com\nupstream: http://10.0.0.1:1\n")
    conf = render(paths, *load(paths))[0]["host-a_example_com.conf"]
    if old:
        assert "listen 443 ssl http2;" in conf and "http2 on;" not in conf
    else:
        assert "listen 443 ssl;" in conf and "http2 on;" in conf
