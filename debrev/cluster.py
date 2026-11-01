"""Floating IP (keepalived/VRRP), health, drain and restore.

Both nodes run nginx all the time; keepalived decides which one owns the
virtual IP that the outside world is pointed at. Priorities: a healthy node
keeps its configured priority; a failed health check lowers it by 60; a
"drain" lowers it by 100 so the twin takes over before an upgrade. A drained
node still takes the IP if the twin is down (better than no service).
"""
from __future__ import annotations

import http.client
import json
import subprocess
import time
from datetime import datetime, timezone

from . import node as nodemod, peer as peermod, state as st
from .paths import APP_DIR, Paths

HEALTH_PATH = "/.debrev-health"
DRAIN_VALUE = -100
FAIL_WEIGHT = -60


class ClusterError(Exception):
    pass


def cluster_settings(p: Paths) -> dict:
    return st.load_settings(p)[0]["cluster"]


def iface_info(p: Paths, n: nodemod.Node) -> dict:
    """Interface, our address on it and the prefix length (towards the peer)."""
    def ip(*a):
        r = subprocess.run(["ip", "-j", *a], capture_output=True, text=True)
        if r.returncode != 0:
            raise ClusterError(f"ip {' '.join(a)} failed: {r.stderr.strip()}")
        return json.loads(r.stdout)
    dev = n.interface
    src = None
    if not dev:
        route = ip("route", "get", n.peer_address)[0]
        dev, src = route["dev"], route.get("prefsrc")
    for entry in ip("-4", "addr", "show", "dev", dev):
        for a in entry.get("addr_info", []):
            if src is None or a["local"] == src:
                return {"dev": dev, "src": a["local"], "prefix": a["prefixlen"]}
    raise ClusterError(f"no IPv4 address found on {dev}")


def render_keepalived(n: nodemod.Node, cl: dict, info: dict, app_dir=APP_DIR, drain_file="/var/lib/debrev/drain-weight") -> str:
    return f"""# Managed by debrev. Do not edit; regenerated on every apply.
global_defs {{
    router_id debrev_{n.name.replace('.', '_').replace('-', '_')}
    enable_script_security
    script_user root
}}

vrrp_script debrev_health {{
    script "{app_dir}/bin/debrev-health"
    interval 1
    timeout 2
    fall 2
    rise 2
    weight {FAIL_WEIGHT}
}}

track_file debrev_drain {{
    file {drain_file}
    weight 1
    init_file 0
}}

vrrp_instance DEBREV {{
    state BACKUP
    interface {info['dev']}
    virtual_router_id {cl['vrid']}
    priority {n.priority}
    advert_int 1
    unicast_src_ip {info['src']}
    unicast_peer {{
        {n.peer_address}
    }}
    virtual_ipaddress {{
        {cl['vip']}/{info['prefix']} dev {info['dev']}
    }}
    track_script {{
        debrev_health
    }}
    track_file {{
        debrev_drain
    }}
    notify "{app_dir}/bin/debrev-vrrp-notify"
}}
"""


def configure(p: Paths) -> str:
    """Root: write keepalived.conf from node + synced settings; start/reload on change."""
    n = nodemod.load(p)
    cl = cluster_settings(p)
    if not cl["vip"] or not n.has_peer:
        return "cluster not configured (needs a peer and 'debrev cluster set --vip ...')"
    p.drain_file.parent.mkdir(parents=True, exist_ok=True)
    if not p.drain_file.exists():
        p.drain_file.write_text("0\n")
        _chown_debrev(p.drain_file)
    text = render_keepalived(n, cl, iface_info(p, n), drain_file=str(p.drain_file))
    old = p.keepalived_conf.read_text() if p.keepalived_conf.exists() else None
    if old == text:
        return "keepalived unchanged"
    p.keepalived_conf.parent.mkdir(parents=True, exist_ok=True)
    p.keepalived_conf.write_text(text)
    p.keepalived_conf.chmod(0o644)
    cmd = p.keepalived_reload if old is not None else p.keepalived_cmd
    r = subprocess.run(list(cmd), capture_output=True, text=True)
    if r.returncode != 0:
        raise ClusterError(f"keepalived: {r.stderr.strip()[-200:]}")
    return "keepalived configured and started" if old is None else "keepalived reloaded"


def _chown_debrev(path) -> None:
    import shutil
    try:
        shutil.chown(path, "debrev", "debrev")
    except (LookupError, PermissionError):
        pass


# --------------------------------------------------------------- health / state

def health(p: Paths, n: nodemod.Node | None = None, port: int | None = None) -> tuple[bool, str]:
    """Is nginx answering locally? (Drain is handled by keepalived's track file, not here.)"""
    port = port or p.health_port
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        c.request("GET", HEALTH_PATH, headers={"Host": "debrev-health.invalid"})
        r = c.getresponse()
        body = r.read().decode(errors="replace").strip()
        c.close()
    except OSError as e:
        return False, f"nginx not answering on 127.0.0.1:{port}: {e}"
    if r.status != 200 or not body.startswith("ok"):
        return False, f"unexpected health answer {r.status} {body[:40]!r}"
    return True, body


def drained(p: Paths) -> bool:
    try:
        return int(p.drain_file.read_text().strip() or 0) < 0
    except (OSError, ValueError):
        return False


def vrrp_state(p: Paths) -> dict:
    try:
        return json.loads(p.vrrp_state.read_text())
    except (OSError, ValueError):
        return {}


def probe_vip(vip: str, timeout=2) -> str | None:
    """Which node answers on the virtual IP right now? (node name or None)"""
    try:
        c = http.client.HTTPConnection(vip, 80, timeout=timeout)
        c.request("GET", HEALTH_PATH, headers={"Host": "debrev-health.invalid"})
        body = c.getresponse().read().decode(errors="replace").strip()
        c.close()
        return body.split(" ", 1)[1] if body.startswith("ok ") else None
    except OSError:
        return None


def _wait(cond, seconds: int, step: float = 1.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


def local_view(p: Paths) -> dict:
    n = nodemod.load(p)
    ok, msg = health(p, n)
    return {"name": n.name, "healthy": ok, "health": msg, "drained": drained(p),
            "vrrp": vrrp_state(p).get("state"), "priority": n.priority}


def drain(p: Paths, force: bool = False, wait: int = 30, out=print) -> bool:
    n = nodemod.load(p)
    cl = cluster_settings(p)
    if not cl["vip"] or not n.has_peer:
        raise ClusterError("no cluster configured")
    if drained(p):
        out("already drained")
        return True
    try:
        theirs = peermod.peer_status(p, n)
    except (peermod.PeerError, ValueError) as e:
        if not force:
            raise ClusterError(f"cannot reach the twin ({e}); draining would leave no server. Use --force to override")
        theirs = {}
    pc = theirs.get("cluster") or {}
    if not force and not (pc.get("healthy") and not pc.get("drained")):
        raise ClusterError(f"the twin is not ready to take over (healthy={pc.get('healthy')}, drained={pc.get('drained')}); fix that first or use --force")
    out(f"twin {theirs.get('name', '?')} is healthy and not drained; lowering priority of {n.name}...")
    p.drain_file.write_text(f"{DRAIN_VALUE}\n")
    mine = vrrp_state(p).get("state")
    if mine == "MASTER":
        if not _wait(lambda: vrrp_state(p).get("state") != "MASTER", wait):
            raise ClusterError(f"{n.name} still holds the virtual IP after {wait}s; check 'journalctl -u keepalived'")
    out(f"{n.name} released the virtual IP {cl['vip']}")
    owner = None

    def twin_serves():
        nonlocal owner
        owner = probe_vip(cl["vip"])
        return owner is not None and owner != n.name
    if not _wait(twin_serves, wait):
        raise ClusterError(f"nobody else answers on {cl['vip']} yet; the twin may not have taken over (last answer: {owner})")
    out(f"{cl['vip']} is now served by {owner}. It is safe to upgrade {n.name}.")
    return True


def restore(p: Paths, wait: int = 30, out=print) -> bool:
    n = nodemod.load(p)
    cl = cluster_settings(p)
    p.drain_file.write_text("0\n")
    ok, msg = health(p, n)
    if not ok:
        raise ClusterError(f"{n.name} is not healthy yet ({msg}); the virtual IP stays on the twin until it is")
    out(f"{n.name} is eligible again (priority {n.priority}).")
    if cl["vip"]:
        expect_back = n.priority > 100
        owner = None

        def settled():
            nonlocal owner
            owner = probe_vip(cl["vip"])
            return owner is not None and (owner == n.name or not expect_back)
        _wait(settled, wait)
        out(f"{cl['vip']} is served by {owner or 'nobody (!)'}"
            + ("" if owner == n.name or not expect_back else " (the preferred node will take it back shortly)"))
    return True
