"""Validation and normalisation of host definitions.

Everything that ends up inside generated nginx config is checked against a
strict pattern here, so a typo or hostile value cannot inject directives.
The one deliberate exception is `custom_snippet`, which is raw nginx and gets
a separate (best-effort) guard in `check_snippet`.
"""
from __future__ import annotations

import copy
import re

DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$|^localhost$"
)
UPSTREAM_RE = re.compile(
    r"^https?://(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?|\[[0-9a-f:]+\])(?::\d{1,5})?(?:/[A-Za-z0-9._~/%-]*)?$",
    re.I,
)
SIZE_RE = re.compile(r"^\d{1,6}[kmg]?$", re.I)
DURATION_RE = re.compile(r"^\d{1,5}(?:ms|s|m|h|d)?$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
COOKIE_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/%-]*$")
CIDR_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|[0-9a-f:]+(?:/\d{1,3})?|all)$", re.I)

HOST_KEYS = {
    "domain", "aliases", "upstream", "enabled", "websockets",
    "preserve_host", "buffering", "request_buffering", "tls", "cache", "max_body", "timeouts",
    "request_headers", "response_headers", "access_list",
    "custom_locations", "custom_snippet", "note", "rate_limit",
}
CERT_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


def covers(sans, domain: str) -> bool:
    """Does a certificate with these names cover `domain` (exact, or a one-label wildcard)?"""
    if domain in sans:
        return True
    if domain.startswith("*."):
        return False
    return f"*.{domain.partition('.')[2]}" in sans


TLS_KEYS = {"enabled", "cert", "cert_from", "cert_path", "key_path", "force_https", "hsts", "http2", "challenge", "dns_provider"}
CACHE_KEYS = {"enabled", "ttl", "static_only", "bypass_cookies", "max_size"}
TIMEOUT_KEYS = {"connect", "read", "send"}
RATE_KEYS = {"rate", "burst", "connections"}
RATE_RANGES = {"rate": (1, 100000), "burst": (0, 1000000), "connections": (1, 100000)}
LOCATION_KEYS = {"path", "upstream", "websockets"}

DEFAULTS = {
    "aliases": [],
    "enabled": True,
    "websockets": False,
    "rate_limit": True,
    "preserve_host": True,
    "buffering": True,
    "request_buffering": True,
    "tls": {"enabled": True, "cert": "auto", "force_https": True, "hsts": False, "http2": True},
    "cache": {"enabled": False, "ttl": "10m", "static_only": True, "bypass_cookies": [], "max_size": "1g"},
    "max_body": None,
    "timeouts": {},
    "request_headers": {},
    "response_headers": {},
    "access_list": None,
    "custom_locations": [],
    "custom_snippet": "",
}

# Directives that can read/write arbitrary files, load code, or escape the
# server{} block. A guard against mistakes, not a security boundary: snippet
# editors are trusted admins.
BLOCKED_DIRECTIVES = {
    "include", "load_module", "access_log", "error_log", "root", "alias",
    "env", "user", "daemon", "pid", "lock_file", "working_directory",
    "server", "http", "events", "stream", "mail", "upstream", "map",
    "proxy_cache_path", "ssl_certificate", "ssl_certificate_key",
    "listen", "server_name",
}
BLOCKED_PREFIXES = ("lua_", "perl_", "js_", "njs_")
BLOCKED_SUBSTRINGS = ("_by_lua", "perl")


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def check_snippet(text: str) -> list[str]:
    """Best-effort checks on raw nginx text destined for a server{} block."""
    errs: list[str] = []
    if "\x00" in text:
        return ["snippet contains a NUL byte"]
    stripped = re.sub(r"#[^\n]*", "", text)
    stripped = re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', '""', stripped)
    depth = 0
    for ch in stripped:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                errs.append("snippet has an unmatched '}' (it would close the server block)")
                break
    if depth > 0:
        errs.append("snippet has an unclosed '{'")
    for m in re.finditer(r"(?:^|[;{}])\s*([A-Za-z_][A-Za-z0-9_]*)", stripped):
        d = m.group(1).lower()
        if (d in BLOCKED_DIRECTIVES or d.startswith(BLOCKED_PREFIXES)
                or any(s in d for s in BLOCKED_SUBSTRINGS)):
            errs.append(f"directive '{d}' is not allowed in a custom snippet")
    return sorted(set(errs))


def _check_keys(obj: dict, allowed: set, where: str, errs: list[str]) -> None:
    for k in obj:
        if k not in allowed:
            errs.append(f"{where}: unknown key '{k}'")


def _str(v, where: str, errs: list[str], regex=None, what="value") -> str | None:
    if not isinstance(v, (str, int)) or isinstance(v, bool):
        errs.append(f"{where}: must be a string")
        return None
    v = str(v)
    if regex is not None and not regex.match(v):
        errs.append(f"{where}: invalid {what} {v!r}")
        return None
    return v


def _bool(v, where: str, errs: list[str]) -> bool:
    if not isinstance(v, bool):
        errs.append(f"{where}: must be true or false")
        return False
    return v


def _headers(v, where: str, errs: list[str]) -> dict:
    out = {}
    if not isinstance(v, dict):
        errs.append(f"{where}: must be a mapping of header name to value")
        return out
    for name, val in v.items():
        if not isinstance(name, str) or not HEADER_NAME_RE.match(name):
            errs.append(f"{where}: invalid header name {name!r}")
            continue
        val = str(val)
        if len(val) > 512 or re.search(r'["\\\x00-\x1f\x7f]', val):
            errs.append(f"{where}.{name}: value may not contain quotes, backslashes or control characters")
            continue
        out[name] = val
    return out


def normalise_host(raw: dict, access_lists: dict, where: str) -> tuple[dict | None, list[str]]:
    """Return (normalised host, errors). Host is None when errors are fatal."""
    errs: list[str] = []
    if not isinstance(raw, dict):
        return None, [f"{where}: file must contain a mapping"]
    raw = copy.deepcopy(raw)
    if "preset" in raw:
        errs.append(f"{where}: presets no longer exist; run 'debrev migrate-presets' once to copy their settings into the hosts")
        raw.pop("preset")
    _check_keys(raw, HOST_KEYS, where, errs)

    own = dict(raw)
    if isinstance(own.get("tls"), bool):
        own["tls"] = {"enabled": own["tls"]}
    if isinstance(own.get("cache"), bool):
        own["cache"] = {"enabled": own["cache"]}
    cfg = deep_merge(DEFAULTS, own)

    h: dict = {}
    dom = _str(cfg.get("domain"), f"{where}.domain", errs) if "domain" in cfg else None
    if dom is None:
        errs.append(f"{where}: 'domain' is required")
    else:
        dom = dom.lower()
        if not DOMAIN_RE.match(dom):
            errs.append(f"{where}.domain: invalid domain {dom!r}")
    h["domain"] = dom

    aliases = []
    if not isinstance(cfg["aliases"], list):
        errs.append(f"{where}.aliases: must be a list")
    else:
        for a in cfg["aliases"]:
            a = str(a).lower()
            if not DOMAIN_RE.match(a):
                errs.append(f"{where}.aliases: invalid domain {a!r}")
            else:
                aliases.append(a)
    h["aliases"] = aliases

    up = _str(cfg.get("upstream"), f"{where}.upstream", errs, UPSTREAM_RE, "upstream URL (http[s]://host[:port][/path])") if "upstream" in cfg else None
    if "upstream" not in cfg:
        errs.append(f"{where}: 'upstream' is required")
    h["upstream"] = up

    h["enabled"] = _bool(cfg["enabled"], f"{where}.enabled", errs)
    h["websockets"] = _bool(cfg["websockets"], f"{where}.websockets", errs)
    rl = cfg["rate_limit"]
    h["rate_limits"] = {}
    if isinstance(rl, dict):                    # custom limits for this host: {rate, burst, connections}
        _check_keys(rl, RATE_KEYS, f"{where}.rate_limit", errs)
        for k, (lo, hi) in RATE_RANGES.items():
            if k in rl:
                v = rl[k]
                if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                    errs.append(f"{where}.rate_limit.{k}: must be a whole number {lo}-{hi}")
                else:
                    h["rate_limits"][k] = v
        h["rate_limit"] = True
    else:
        h["rate_limit"] = _bool(rl, f"{where}.rate_limit", errs)
    h["preserve_host"] = _bool(cfg["preserve_host"], f"{where}.preserve_host", errs)
    h["buffering"] = _bool(cfg["buffering"], f"{where}.buffering", errs)
    h["request_buffering"] = _bool(cfg["request_buffering"], f"{where}.request_buffering", errs)
    h["note"] = str(cfg.get("note", ""))[:200].replace("\n", " ")

    # TLS
    tls = cfg["tls"]
    if not isinstance(tls, dict):
        errs.append(f"{where}.tls: must be a mapping or true/false")
        tls = DEFAULTS["tls"]
    _check_keys(tls, TLS_KEYS, f"{where}.tls", errs)
    t = {k: _bool(tls[k], f"{where}.tls.{k}", errs) for k in ("enabled", "force_https", "hsts", "http2") if k in tls}
    t["challenge"] = tls.get("challenge", "http")
    if t["challenge"] not in ("http", "dns"):
        errs.append(f"{where}.tls.challenge: must be 'http' or 'dns'")
    t["dns_provider"] = tls.get("dns_provider")
    if t["dns_provider"] is not None and not (isinstance(t["dns_provider"], str) and NAME_RE.match(t["dns_provider"])):
        errs.append(f"{where}.tls.dns_provider: must be the name of a provider from settings (acme.dns_providers)")
    t["cert"] = tls.get("cert", "auto")
    if t["cert"] not in ("auto", "custom", "shared"):
        errs.append(f"{where}.tls.cert: must be 'auto', 'custom' or 'shared'")
    t["cert_from"] = None
    if t["cert"] == "shared":
        v = tls.get("cert_from")
        if not isinstance(v, str) or not CERT_NAME_RE.match(v):
            errs.append(f"{where}.tls.cert_from: must name the certificate to use, e.g. the domain of the host that owns it")
        else:
            t["cert_from"] = v
    elif tls.get("cert_from") is not None:
        errs.append(f"{where}.tls.cert_from: only valid with cert: shared")
    t["cert_path"] = t["key_path"] = None
    if t["cert"] == "custom":
        # Either both paths to files already on the server, or neither: then the certificate
        # is uploaded (web UI / 'debrev certs upload') and stored and synced by debrev itself.
        given = [k for k in ("cert_path", "key_path") if tls.get(k) is not None]
        if given and len(given) != 2:
            errs.append(f"{where}.tls: give both cert_path and key_path, or neither (to upload a certificate)")
        for k in given:
            v = tls.get(k)
            if not isinstance(v, str) or not re.match(r"^/[A-Za-z0-9._/@+-]+$", v):
                errs.append(f"{where}.tls.{k}: must be an absolute path")
            else:
                t[k] = v
    h["tls"] = t

    # cache
    cache = cfg["cache"]
    if not isinstance(cache, dict):
        errs.append(f"{where}.cache: must be a mapping or true/false")
        cache = DEFAULTS["cache"]
    _check_keys(cache, CACHE_KEYS, f"{where}.cache", errs)
    c = {
        "enabled": _bool(cache.get("enabled", False), f"{where}.cache.enabled", errs),
        "static_only": _bool(cache.get("static_only", True), f"{where}.cache.static_only", errs),
        "ttl": _str(cache.get("ttl", "10m"), f"{where}.cache.ttl", errs, DURATION_RE, "duration") or "10m",
        "max_size": _str(cache.get("max_size", "1g"), f"{where}.cache.max_size", errs, SIZE_RE, "size") or "1g",
        "bypass_cookies": [],
    }
    bc = cache.get("bypass_cookies", [])
    if not isinstance(bc, list):
        errs.append(f"{where}.cache.bypass_cookies: must be a list")
    else:
        for name in bc:
            if _str(name, f"{where}.cache.bypass_cookies", errs, COOKIE_RE, "cookie name"):
                c["bypass_cookies"].append(str(name))
    h["cache"] = c

    h["max_body"] = _str(cfg["max_body"], f"{where}.max_body", errs, SIZE_RE, "size") if cfg["max_body"] is not None else None

    to = cfg["timeouts"]
    h["timeouts"] = {}
    if not isinstance(to, dict):
        errs.append(f"{where}.timeouts: must be a mapping")
    else:
        _check_keys(to, TIMEOUT_KEYS, f"{where}.timeouts", errs)
        for k, v in to.items():
            if k in TIMEOUT_KEYS:
                s = _str(v, f"{where}.timeouts.{k}", errs, DURATION_RE, "duration")
                if s:
                    h["timeouts"][k] = s

    h["request_headers"] = _headers(cfg["request_headers"], f"{where}.request_headers", errs)
    h["response_headers"] = _headers(cfg["response_headers"], f"{where}.response_headers", errs)

    al = cfg["access_list"]
    if al is not None:
        if al not in access_lists:
            errs.append(f"{where}.access_list: unknown access list {al!r}")
            al = None
    h["access_list"] = al

    locs = []
    if not isinstance(cfg["custom_locations"], list):
        errs.append(f"{where}.custom_locations: must be a list")
    else:
        seen = set()
        for i, loc in enumerate(cfg["custom_locations"]):
            w = f"{where}.custom_locations[{i}]"
            if not isinstance(loc, dict):
                errs.append(f"{w}: must be a mapping")
                continue
            _check_keys(loc, LOCATION_KEYS, w, errs)
            path = _str(loc.get("path"), f"{w}.path", errs, PATH_RE, "path")
            lup = _str(loc.get("upstream"), f"{w}.upstream", errs, UPSTREAM_RE, "upstream URL")
            ws = _bool(loc.get("websockets", h["websockets"]), f"{w}.websockets", errs)
            if path in seen:
                errs.append(f"{w}: duplicate path {path!r}")
            seen.add(path)
            if path and lup:
                locs.append({"path": path, "upstream": lup, "websockets": ws})
    h["custom_locations"] = locs

    snippet = cfg["custom_snippet"] or ""
    if not isinstance(snippet, str):
        errs.append(f"{where}.custom_snippet: must be text")
        snippet = ""
    errs += [f"{where}.custom_snippet: {e}" for e in check_snippet(snippet)]
    h["custom_snippet"] = snippet.strip("\n")

    return (None if errs else h), errs


def validate_access_list(raw, where: str) -> tuple[dict | None, list[str]]:
    errs: list[str] = []
    if not isinstance(raw, dict):
        return None, [f"{where}: must be a mapping"]
    _check_keys(raw, {"allow", "deny", "note"}, where, errs)
    out = {"allow": [], "deny": []}
    for k in ("allow", "deny"):
        v = raw.get(k, [])
        if not isinstance(v, list):
            errs.append(f"{where}.{k}: must be a list")
            continue
        for item in v:
            if not isinstance(item, str) or not CIDR_RE.match(item):
                errs.append(f"{where}.{k}: invalid address {item!r}")
            else:
                out[k].append(item)
    if not out["allow"] and not out["deny"]:
        errs.append(f"{where}: needs at least one allow or deny entry")
    return (None if errs else out), errs
