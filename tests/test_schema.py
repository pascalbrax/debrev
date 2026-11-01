import pytest

from debrev.schema import check_snippet, normalise_host


def norm(raw, acls=None):
    return normalise_host(raw, acls or {}, "t.yaml")


def test_minimal_host_gets_defaults():
    h, errs = norm({"domain": "A.Example.com", "upstream": "http://10.0.0.1:80"})
    assert not errs
    assert h["domain"] == "a.example.com"
    assert h["tls"]["force_https"] is True and h["cache"]["enabled"] is False


def test_presets_are_gone_with_a_helpful_message():
    h, errs = norm({"domain": "a.example.com", "upstream": "http://x:1", "preset": "ws"})
    assert any("migrate-presets" in e for e in errs)


def test_rate_limit_forms():
    base = {"domain": "a.example.com", "upstream": "http://x:1"}
    h, errs = norm(base)
    assert not errs and h["rate_limit"] is True and h["rate_limits"] == {}
    h, errs = norm({**base, "rate_limit": False})
    assert not errs and h["rate_limit"] is False
    h, errs = norm({**base, "rate_limit": {"rate": 200, "burst": 2000}})
    assert not errs and h["rate_limit"] is True and h["rate_limits"] == {"rate": 200, "burst": 2000}
    for bad in ({"rate": 0}, {"burst": "x"}, {"speed": 1}, {"connections": 10 ** 7}):
        assert norm({**base, "rate_limit": bad})[1], bad


@pytest.mark.parametrize("raw", [
    {"domain": "bad domain.com", "upstream": "http://x:1"},
    {"domain": "a.example.com", "upstream": "http://x:1; evil on"},
    {"domain": "a.example.com", "upstream": "ftp://x"},
    {"domain": "a.example.com", "upstream": "http://x:1", "max_body": "10 gigs"},
    {"domain": "a.example.com", "upstream": "http://x:1", "typo_key": 1},
    {"domain": "a.example.com", "upstream": "http://x:1", "preset": "nope"},
    {"domain": "a.example.com", "upstream": "http://x:1", "access_list": "nope"},
    {"domain": "a.example.com", "upstream": "http://x:1", "response_headers": {"X-A": 'v"; evil'}},
    {"domain": "a.example.com", "upstream": "http://x:1", "response_headers": {"X A": "v"}},
    {"domain": "a.example.com", "upstream": "http://x:1", "cache": {"bypass_cookies": ["a;b"]}},
    {"domain": "a.example.com", "upstream": "http://x:1", "tls": {"cert": "custom", "cert_path": "/etc/ssl/a.pem"}},
    {"upstream": "http://x:1"},
    {"domain": "a.example.com"},
])
def test_invalid_hosts_are_rejected(raw):
    h, errs = norm(raw)
    assert h is None and errs


def test_bool_shorthands():
    h, errs = norm({"domain": "a.example.com", "upstream": "http://x:1", "tls": False, "cache": True})
    assert not errs and h["tls"]["enabled"] is False and h["cache"]["enabled"] is True


@pytest.mark.parametrize("snippet", [
    "root /etc;", "include /etc/passwd;", "access_log /tmp/x;", "load_module m.so;",
    "location / { alias /etc/; }", "} server { listen 1;", "content_by_lua_block { }",
    "perl_set $x 'sub{}';", "location /x {",
])
def test_dangerous_snippets_rejected(snippet):
    assert check_snippet(snippet)


@pytest.mark.parametrize("snippet", [
    'location /healthz { return 200 "ok"; }',
    "add_header X-Test 1;\nlocation ~ ^/api/ { proxy_read_timeout 5m; }",
    "# root /etc; is only a comment\nrewrite ^/old /new permanent;",
    'set $x "include root; }";',
])
def test_reasonable_snippets_allowed(snippet):
    assert check_snippet(snippet) == []
