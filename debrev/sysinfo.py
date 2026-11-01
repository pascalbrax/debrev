"""CPU, memory, disk and load of this server, read from /proc (no extra packages)."""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path


def _cpu_times(proc: str = "/proc/stat") -> tuple[int, int]:
    parts = Path(proc).read_text().splitlines()[0].split()[1:]
    vals = [int(x) for x in parts]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)       # idle + iowait
    return sum(vals[:8]), idle


def cpu_percent(interval: float = 0.25, proc: str = "/proc/stat") -> float:
    t1, i1 = _cpu_times(proc)
    time.sleep(interval)
    t2, i2 = _cpu_times(proc)
    return round(100 * (1 - (i2 - i1) / (t2 - t1)), 1) if t2 > t1 else 0.0


def meminfo(text: str | None = None) -> dict:
    d = {}
    for line in (text if text is not None else Path("/proc/meminfo").read_text()).splitlines():
        k, _, v = line.partition(":")
        if v.split():
            d[k] = int(v.split()[0]) * 1024
    total = d.get("MemTotal", 0)
    avail = d.get("MemAvailable", d.get("MemFree", 0))
    swap_t, swap_f = d.get("SwapTotal", 0), d.get("SwapFree", 0)
    return {"total": total, "used": total - avail, "percent": round(100 * (total - avail) / total, 1) if total else 0.0,
            "swap_total": swap_t, "swap_used": swap_t - swap_f}


def snapshot(interval: float = 0.25) -> dict:
    try:
        load = os.getloadavg()
    except OSError:
        load = (0.0, 0.0, 0.0)
    try:
        up = float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError):
        up = 0.0
    disks = []
    for label, path in (("system", "/"), ("state", "/var/lib/debrev"), ("logs", "/var/log")):
        try:
            u = shutil.disk_usage(path)
        except OSError:
            continue
        if not any(d["total"] == u.total and d["used"] == u.used for d in disks):
            disks.append({"label": label, "path": path, "total": u.total, "used": u.used, "percent": round(100 * u.used / u.total, 1)})
    return {"cpu": cpu_percent(interval) if Path("/proc/stat").exists() else 0.0, "cores": os.cpu_count() or 1,
            "load": [round(x, 2) for x in load], "mem": meminfo(), "disks": disks, "uptime": up}


def human_uptime(sec: float) -> str:
    d, r = divmod(int(sec), 86400)
    h, r = divmod(r, 3600)
    return (f"{d}d " if d else "") + f"{h}h {r // 60}m"
