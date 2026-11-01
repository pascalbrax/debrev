"""Which addresses fail2ban has banned right now (read from its log; the web service needs no root for this)."""
from __future__ import annotations

import re
import shutil
from pathlib import Path

from .paths import Paths

JAIL = "nginx-limit-req"
LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)[,.]\d+ .*?\[([\w.-]+)\]\s+(Ban|Restore Ban|Unban)\s+(\S+)\s*$")
TAIL = 4 * 1024 * 1024


def _lines(path: Path):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - TAIL))
            data = f.read()
    except OSError:
        return None
    return data.decode("utf-8", "replace").splitlines()


def installed(p: Paths) -> bool:
    return p.fail2ban_jail.exists() or shutil.which("fail2ban-client") is not None


def banned(p: Paths, jail: str = JAIL) -> tuple[list[dict], bool]:
    """([{ip, since}], log_readable). Replays Ban / Unban lines of the current and the previous log file."""
    active: dict[str, str] = {}
    readable = False
    for path in (p.fail2ban_log.with_name(p.fail2ban_log.name + ".1"), p.fail2ban_log):
        lines = _lines(path)
        if lines is None:
            continue
        readable = readable or path == p.fail2ban_log
        for ln in lines:
            m = LINE.match(ln)
            if not m or m.group(2) != jail:
                continue
            when, _, act, ip = m.groups()
            if act == "Unban":
                active.pop(ip, None)
            else:
                active[ip] = when
    return [{"ip": ip, "since": t} for ip, t in sorted(active.items(), key=lambda kv: kv[1], reverse=True)], readable


def overview(p: Paths) -> dict:
    """Everything the Security page shows about fail2ban."""
    from . import traffic
    if not installed(p):
        return {"installed": False, "bans": [], "readable": True, "jail": JAIL}
    bans, readable = banned(p)
    try:
        hit = traffic.hosts_hit_by(p, [b["ip"] for b in bans])
    except Exception:                                   # a damaged statistics database must not break the page
        hit = {}
    for b in bans:
        b["hosts"] = hit.get(b["ip"], [])
    return {"installed": True, "bans": bans, "readable": readable, "jail": JAIL}
