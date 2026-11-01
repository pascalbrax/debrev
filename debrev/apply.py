"""Safe apply pipeline.

validate -> render -> pre-test in isolation -> swap live symlink ->
nginx -t on the real config -> reload -> health check -> (auto rollback).
A release directory is only ever added, never edited in place, and 'live'
is switched with an atomic rename.
"""
from __future__ import annotations

import fcntl
import http.client
import json
import os
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import dns, node as nodemod, state as st
from .paths import Paths
from .render import cache_dirs, render


class ApplyError(Exception):
    pass


@dataclass
class Result:
    ok: bool
    message: str
    release: str | None = None
    warnings: list[str] = field(default_factory=list)


def _run(cmd, **kw):
    return subprocess.run(list(cmd), capture_output=True, text=True, **kw)


def _swap_live(p: Paths, target: Path | None) -> None:
    """Atomically point 'live' at target (or remove it when None)."""
    if target is None:
        if p.live.is_symlink():
            p.live.unlink()
        return
    tmp = p.live.with_name("live.new")
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    tmp.symlink_to(target)
    os.replace(tmp, p.live)


def _current(p: Paths) -> Path | None:
    return Path(os.readlink(p.live)) if p.live.is_symlink() else None


def isolated_test(p: Paths, release: Path) -> tuple[bool, str]:
    """Run nginx -t on only the generated files, wrapped in a minimal config."""
    wrapper = release.with_name(release.name + ".test.conf")
    wrapper.write_text(
        "user www-data;\n"
        f"pid {release}.pid;\n"
        "error_log /dev/null;\n"
        "events {}\n"
        "http {\n"
        "    include /etc/nginx/mime.types;\n"
        f"    include {release}/*.conf;\n"
        "}\n"
    )
    try:
        r = _run([*p.nginx_cmd, "-t", "-c", str(wrapper)])
    finally:
        wrapper.unlink(missing_ok=True)
    return r.returncode == 0, (r.stderr + r.stdout).strip()


def health(p: Paths, hosts: list[dict]) -> tuple[bool, str]:
    """Prove the *new* config is serving: drop a token in the ACME webroot and
    fetch it through nginx on port 80 using the first enabled host's name."""
    if not p.health_check:
        return True, "skipped"
    enabled = [h for h in hosts if h["enabled"]]
    if not enabled:
        return True, "no hosts"
    token = secrets.token_hex(8)
    web = p.acme / ".well-known" / "acme-challenge"
    web.mkdir(parents=True, exist_ok=True)
    probe = web / f"debrev-health-{token}"
    probe.write_text(token)
    probe.chmod(0o644)
    last = ""
    try:
        for _ in range(10):
            try:
                c = http.client.HTTPConnection("127.0.0.1", p.health_port, timeout=3)
                c.request("GET", f"/.well-known/acme-challenge/{probe.name}",
                          headers={"Host": enabled[0]["domain"]})
                body = c.getresponse().read().decode(errors="replace").strip()
                c.close()
                if body == token:
                    return True, "ok"
                last = "new config is not serving yet"
            except OSError as e:
                last = str(e)
            time.sleep(0.5)
    finally:
        probe.unlink(missing_ok=True)
    return False, f"nginx on 127.0.0.1:{p.health_port}: {last}"


def apply(p: Paths, check_only: bool = False, dns_only: bool = False) -> Result:
    p.lib.mkdir(parents=True, exist_ok=True)
    with open(p.lock, "w") as lockf:
        try:
            fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return Result(False, "another apply is already running")
        return _apply_locked(p, check_only, dns_only)


def _apply_locked(p: Paths, check_only: bool, dns_only: bool = False) -> Result:
    try:
        if st.is_dirty(p):
            return Result(False, "state has uncommitted changes; commit them (or discard) before applying")
        hosts, acls, errors, warnings = st.load(p)
    except st.StateError as e:
        return Result(False, str(e))
    if errors:
        return Result(False, "validation failed:\n  " + "\n  ".join(errors), warnings=warnings)
    resolved, dwarn = dns.resolve_all(p, hosts, save=not check_only)
    warnings += dwarn
    if dns_only:
        try:
            last = json.loads(p.applied.read_text()).get("resolved")
        except (OSError, ValueError):
            last = None
        if last == resolved:
            return Result(True, "upstream addresses unchanged", warnings=warnings)
    try:
        from . import certs
        certs.publish(p, hosts)          # certbot's lineages -> the dir nginx reads
    except OSError as e:
        warnings.append(f"could not publish certificates: {e}")
    try:
        node = nodemod.load(p)
    except nodemod.NodeError as e:
        return Result(False, f"node.toml invalid: {e}")
    files, rwarn = render(p, hosts, acls, resolved, peer_ip=node.peer_address, node_name=node.name,
                          security=st.load_settings(p)[0]["security"],
                          access_log=str(p.access_log) if p.access_log.parent.is_dir() else None)
    warnings += rwarn

    rev = (st.head(p) or "none")[:8]
    rid = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f") + "-" + rev
    p.releases.mkdir(parents=True, exist_ok=True)
    release = p.releases / rid
    staging = p.releases / (rid + ".tmp")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    for name, content in files.items():
        (staging / name).write_text(content)
    for d in cache_dirs("\n".join(files.values())):
        Path(d).mkdir(parents=True, exist_ok=True)
        _chown_www(Path(d))
    staging.rename(release)

    ok, out = isolated_test(p, release)
    if not ok:
        shutil.rmtree(release, ignore_errors=True)
        return Result(False, f"nginx rejected the generated config (nothing was changed):\n{out}", warnings=warnings)
    if check_only:
        shutil.rmtree(release, ignore_errors=True)
        return Result(True, f"check passed: {len(hosts)} host(s), config is valid", warnings=warnings)

    previous = _current(p)
    _swap_live(p, release)
    r = _run([*p.nginx_cmd, "-t"])
    if r.returncode != 0:
        _swap_live(p, previous)
        shutil.rmtree(release, ignore_errors=True)
        return Result(False, f"nginx -t failed on the full config; rolled back:\n{(r.stderr + r.stdout).strip()}", warnings=warnings)

    r = _run(p.reload_cmd)
    if r.returncode != 0:
        _swap_live(p, previous)
        _run(p.reload_cmd)
        return Result(False, f"reload failed; rolled back:\n{(r.stderr + r.stdout).strip()}", warnings=warnings)

    good, why = health(p, hosts)
    if not good:
        _swap_live(p, previous)
        _run(p.reload_cmd)
        return Result(False, f"health check failed ({why}); rolled back to the previous config", warnings=warnings)

    p.applied.write_text(json.dumps({"commit": st.head(p), "release": rid, "resolved": resolved,
                                     "time": datetime.now(timezone.utc).isoformat()}) + "\n")
    _prune(p, keep=release)
    try:
        from . import certs
        certs.refresh_summary(p, hosts)
    except OSError:
        pass
    warn_more = []
    try:
        from . import cluster
        msg = cluster.configure(p)
        if "unchanged" not in msg and "not configured" not in msg:
            warn_more.append(msg)
    except Exception as e:      # failover config must never undo a good nginx apply
        warn_more.append(f"failover (keepalived) not configured: {e}")
    warnings += warn_more
    return Result(True, f"applied {len(hosts)} host(s) from commit {rev}", release=rid, warnings=warnings)


def _chown_www(path: Path) -> None:
    try:
        shutil.chown(path, "www-data", "www-data")
    except (LookupError, PermissionError):
        pass


def _prune(p: Paths, keep: Path) -> None:
    rels = sorted(d for d in p.releases.iterdir() if d.is_dir() and not d.name.endswith(".tmp"))
    live = _current(p)
    for d in rels[:-p.keep_releases]:
        if d != keep and d != live:
            shutil.rmtree(d, ignore_errors=True)
