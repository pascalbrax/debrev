"""Upstream name resolution with a persistent cache.

nginx resolves proxy_pass hostnames once, at config load, and refuses to load
if one fails. It also ignores the system search domain, so a LAN name such as
"nas" (really host.lan) only resolves through the libc resolver.
So debrev resolves names itself (libc: /etc/hosts, search domain, mDNS, DNS),
remembers the last good answer, and writes plain IPs into the nginx config.
A timer re-resolves periodically and re-applies only when an address changed.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .paths import Paths


def is_ip(name: str) -> bool:
    try:
        ipaddress.ip_address(name.strip("[]"))
        return True
    except ValueError:
        return False


def lookup(name: str) -> str:
    """Resolve via the system resolver, preferring IPv4. Raises OSError."""
    infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    v6 = [i[4][0] for i in infos if i[0] == socket.AF_INET6]
    if v4:
        return v4[0]
    if v6:
        return v6[0]
    raise OSError(f"no address for {name}")


def _load(p: Paths) -> dict:
    try:
        return json.loads((p.lib / "dns-cache.json").read_text())
    except (OSError, ValueError):
        return {}


def hostnames(hosts: list[dict]) -> set[str]:
    names = set()
    for h in hosts:
        if not h["enabled"]:
            continue
        for url in [h["upstream"], *[l["upstream"] for l in h["custom_locations"]]]:
            n = urlsplit(url).hostname
            if n and not is_ip(n):
                names.add(n.lower())
    return names


def resolve_all(p: Paths, hosts: list[dict], save: bool = True):
    """Return (name->ip, warnings). Falls back to the cached address when the
    live lookup fails; names with neither are absent from the result."""
    cache = _load(p)
    out: dict[str, str] = {}
    warnings: list[str] = []
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for name in sorted(hostnames(hosts)):
        try:
            ip = lookup(name)
            out[name] = ip
            if cache.get(name, {}).get("ip") != ip:
                cache[name] = {"ip": ip, "time": now}
        except OSError as e:
            if name in cache:
                out[name] = cache[name]["ip"]
                warnings.append(f"cannot resolve {name} ({e}); using cached address {cache[name]['ip']} from {cache[name]['time']}")
            else:
                warnings.append(f"cannot resolve {name} ({e}) and no cached address; hosts using it are skipped")
    if save:
        try:
            (p.lib / "dns-cache.json").write_text(json.dumps(cache, indent=1, sort_keys=True) + "\n")
        except OSError:
            pass
    return out, warnings


def pin(url: str, resolved: dict[str, str]) -> dict | None:
    """Rewrite an upstream URL to use its resolved IP.

    Returns {url, host_header, ssl_name} or None if the name is unresolved.
    host_header is the original host[:port]; ssl_name is the original name
    for TLS (SNI/verification), None for IP literals or plain http.
    """
    u = urlsplit(url)
    name = u.hostname.lower()
    port = f":{u.port}" if u.port else ""
    literal = is_ip(name)
    if literal:
        ip = name
    elif name in resolved:
        ip = resolved[name]
    else:
        return None
    bracket = f"[{ip}]" if ":" in ip else ip
    pinned = f"{u.scheme}://{bracket}{port}{u.path}"
    return {"url": pinned, "host_header": f"{name}{port}",
            "ssl_name": name if (u.scheme == "https" and not literal) else None}
