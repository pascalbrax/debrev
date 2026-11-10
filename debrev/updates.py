"""Software updates: what is waiting, and whether a restart is needed. Never installs anything.

A root timer (`debrev-updates.timer`) only runs `apt-get update` and touches a stamp file when it
worked. The Security page asks apt itself, unprivileged and read-only (`apt list --upgradable`), but
only when something changed, so the answer is current right after an upgrade done by hand and a page
load normally costs nothing. Upgrading stays manual:
`apt update && apt full-upgrade` (on a pair, `debrev drain` first).
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

from .paths import Paths

# apt/stable-security 3.0.4 amd64 [upgradable from: 3.0.3]
LISTED = re.compile(r"^(\S+?)/(\S+) (\S+) \S+ \[upgradable from: ([^\]]+)\]")
STALE_DAYS = 7
CACHE_SECONDS = 2 * 3600
WATCH = (Path("/var/lib/dpkg/status"), Path("/var/cache/apt/pkgcache.bin"))   # change on an upgrade / an 'apt update'
_cache: dict = {"t": 0.0, "key": None, "v": None}


def stamp(p: Paths) -> Path:
    return p.lib / "apt-updated"


def parse_listing(text: str) -> list[dict]:
    pkgs = []
    for line in text.splitlines():
        m = LISTED.match(line)
        if m:
            name, suites, new, old = m.groups()
            pkgs.append({"name": name, "old": old, "new": new, "security": "security" in suites.lower()})
    return sorted(pkgs, key=lambda x: (not x["security"], x["name"]))


def _key(p: Paths | None) -> tuple:
    out = []
    for f in (*WATCH, *((stamp(p),) if p else ())):
        try:
            out.append(f.stat().st_mtime_ns)
        except OSError:
            out.append(0)
    return tuple(out)


def waiting(p: Paths | None = None, run=subprocess.run) -> list[dict] | None:
    """Packages that an upgrade would install (None if apt cannot be asked).

    apt is asked only when something changed (dpkg's status file or apt's cache: an upgrade, an
    `apt update`, the timer's stamp), or after two hours; otherwise the last answer is reused.
    `apt list --upgradable` is read-only, needs no root and takes a fraction of a second."""
    key = _key(p)
    if _cache["v"] is not None and _cache["key"] == key and time.time() - _cache["t"] < CACHE_SECONDS:
        return _cache["v"]
    try:
        r = run(["apt", "list", "--upgradable"], capture_output=True, text=True, timeout=60,
                env=dict(os.environ, LC_ALL="C"))
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    pk = parse_listing(r.stdout)
    _cache.update(t=time.time(), key=key, v=pk)
    return pk


def age_days(p: Paths) -> float | None:
    """Days since the last successful `apt-get update` by the timer; None if it never ran."""
    try:
        return (time.time() - stamp(p).stat().st_mtime) / 86400
    except OSError:
        return None


def _vkey(s: str) -> list:
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", s) if x]


def reboot_needed(boot: Path = Path("/boot"), running: str | None = None, flag: Path = Path("/run/reboot-required")) -> str:
    """'' when no restart is needed, else a short reason (a newer kernel is installed, or the flag file exists)."""
    running = running or os.uname().release
    try:
        newest = max((f.name[len("vmlinuz-"):] for f in boot.glob("vmlinuz-*")), key=_vkey, default="")
    except OSError:
        newest = ""
    if newest and newest != running and _vkey(newest) > _vkey(running):
        return f"kernel {newest} is installed, {running} is running"
    if flag.exists():
        return "an installed update asked for a restart"
    return ""
