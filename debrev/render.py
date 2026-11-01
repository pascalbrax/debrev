"""Turn validated state into nginx config files."""
from __future__ import annotations

import re
from pathlib import Path

import jinja2

from . import dns
from .paths import Paths


def _slug(domain: str) -> str:
    return re.sub(r"[^a-z0-9]", "_", domain.lower())


def cert_files(p: Paths, h: dict) -> tuple[str, str]:
    if h["tls"]["cert"] == "custom" and h["tls"]["cert_path"]:
        return h["tls"]["cert_path"], h["tls"]["key_path"]
    if h["tls"]["cert"] == "shared":
        d = p.certs_dir / h["tls"]["cert_from"]
        return str(d / "fullchain.pem"), str(d / "privkey.pem")
    d = p.certs_dir / h["domain"].removeprefix("*.")
    return str(d / "fullchain.pem"), str(d / "privkey.pem")


def security_on(security: dict | None) -> dict | None:
    from .state import SECURITY_DEFAULTS
    sec = {**SECURITY_DEFAULTS, **(security or {})}
    return sec if sec["rate_limit"] else None


def legacy_http2(p: Paths) -> bool:
    """True for nginx older than 1.25.1 (Debian 12): there HTTP/2 is 'listen 443 ssl http2', not 'http2 on'."""
    import subprocess
    try:
        out = subprocess.run([*p.nginx_cmd, "-v"], capture_output=True, text=True, timeout=5)
        m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", out.stdout + out.stderr)
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(m) and tuple(int(x) for x in m.groups()) < (1, 25, 1)


def render(p: Paths, hosts: list[dict], acls: dict, resolved: dict | None = None, peer_ip: str | None = None, node_name: str = "debrev", security: dict | None = None, access_log: str | None = None):
    """Return (files, warnings). files maps file name -> content."""
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(p.templates)),
        trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True,
        undefined=jinja2.StrictUndefined, autoescape=False,
    )
    warnings: list[str] = []
    files: dict[str, str] = {}
    caches = []
    sec_on = security_on(security)
    extra_rates: set = set()
    host_tpl = env.get_template("host.conf.j2")
    old_http2 = legacy_http2(p)
    for h in sorted(hosts, key=lambda x: x["domain"]):
        if not h["enabled"]:
            continue
        h = dict(h)
        resolved_map = resolved if resolved is not None else {}
        main = dns.pin(h["upstream"], resolved_map)
        locs = [dns.pin(l["upstream"], resolved_map) for l in h["custom_locations"]]
        if main is None or any(x is None for x in locs):
            warnings.append(f"{h['domain']}: skipped, upstream name could not be resolved")
            continue
        h["up"] = main
        h["custom_locations"] = [{**l, "up": u} for l, u in zip(h["custom_locations"], locs)]
        h["slug"] = _slug(h["domain"])
        h["cache_zone"] = f"debrev_{h['slug']}"
        crt, key = cert_files(p, h)
        h["cert_path"], h["key_path"] = crt, key
        h["tls_active"] = False
        if h["tls"]["enabled"]:
            if Path(crt).exists() and Path(key).exists():
                h["tls_active"] = True
            else:
                warnings.append(f"{h['domain']}: no certificate at {crt} yet; serving plain HTTP until one is issued")
        if h["cache"]["enabled"]:
            caches.append({"dir": str(p.cache / h["slug"]), "zone": h["cache_zone"],
                           "max_size": h["cache"]["max_size"]})
        h["rl"] = None
        if sec_on and h["rate_limit"]:
            ov = h["rate_limits"]
            rate = ov.get("rate", sec_on["rate"])
            if rate != sec_on["rate"]:
                extra_rates.add(rate)
            h["rl"] = {"zone": "debrev_req" if rate == sec_on["rate"] else f"debrev_req_{rate}",
                       "burst": ov.get("burst", sec_on["burst"]), "conn": ov.get("connections", sec_on["connections"])}
        files[f"host-{h['slug']}.conf"] = host_tpl.render(
            h=h, acl=acls.get(h["access_list"]), acme_root=str(p.acme), peer_ip=peer_ip, old_http2=old_http2)
    from .state import SECURITY_DEFAULTS
    from .traffic import LOG_FORMAT
    sec = {**SECURITY_DEFAULTS, **(security or {})}
    files["00-global.conf"] = env.get_template("00-global.conf.j2").render(caches=caches, node_name=node_name, sec=sec, extra_rates=sorted(extra_rates), access_log=access_log, log_format=LOG_FORMAT)
    return files, warnings


def cache_dirs(files_text: str) -> list[str]:
    return re.findall(r"^proxy_cache_path (\S+)", files_text, re.M)
