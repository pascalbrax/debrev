"""Exposure checklist: is this server reasonable to put on the internet?

`audit()` returns checks (id, level ok|warn|fail|info, title, detail). `fail` means
"do not open the firewall yet". Everything is read-only.
"""
from __future__ import annotations

import http.client
import re
import shutil
import subprocess
from pathlib import Path

from . import auth, certs as cr, state as st, updates
from .paths import Paths

LEVEL_ORDER = {"fail": 0, "warn": 1, "info": 2, "ok": 3}


def check(cid: str, level: str, title: str, detail: str = "") -> dict:
    return {"id": cid, "level": level, "title": title, "detail": detail}


def parse_sshd(texts: list[str]) -> dict:
    """First value wins, as in sshd. Returns lower-cased option -> value."""
    out: dict = {}
    for t in texts:
        for line in t.splitlines():
            m = re.match(r"\s*([A-Za-z]+)\s+(\S+)", line)
            if m and not line.lstrip().startswith("#") and m.group(1).lower() not in out:
                out[m.group(1).lower()] = m.group(2).lower()
    return out


def _sshd_files() -> list[str]:
    texts = []
    base = Path("/etc/ssh")
    for f in sorted((base / "sshd_config.d").glob("*.conf")) + [base / "sshd_config"]:
        try:
            texts.append(f.read_text())
        except OSError:
            pass
    return texts


def parse_listening(ss_text: str) -> list[tuple[str, int]]:
    """(address, port) of TCP listeners from `ss -ltnH`."""
    res = []
    for line in ss_text.splitlines():
        cols = line.split()
        if len(cols) >= 4:
            addr, _, port = cols[3].rpartition(":")
            if port.isdigit():
                res.append((addr.strip("[]"), int(port)))
    return res


def _ss() -> str:
    if not shutil.which("ss"):
        return ""
    return subprocess.run(["ss", "-ltnH"], capture_output=True, text=True).stdout


def drops_unknown_host(port: int = 80) -> bool | None:
    """Does nginx hang up on a request for a name it does not serve? None = nginx not reachable."""
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.request("GET", "/", headers={"Host": "unknown.invalid"})
        c.getresponse().read()
        return False
    except (http.client.RemoteDisconnected, ConnectionResetError):
        return True
    except OSError:
        return None


def _reboot_reason() -> str:
    return updates.reboot_needed()


def update_checks(p: Paths, reboot: str | None = None, pk: list[dict] | None = None) -> list[dict]:
    res = []
    pk = updates.waiting(p) if pk is None else pk
    age = updates.age_days(p)
    hint = "Install with: sudo apt update && sudo apt full-upgrade. On a pair, run 'debrev drain' first and 'debrev restore' afterwards."
    if pk is None:
        res.append(check("updates", "info", "Could not ask apt for updates", "apt list --upgradable did not answer."))
    else:
        sec = [x for x in pk if x["security"]]
        names = lambda xs: ", ".join(x["name"] for x in xs[:8]) + (f" and {len(xs) - 8} more" if len(xs) > 8 else "")
        if sec:
            rest = f" ({len(pk) - len(sec)} other update(s) waiting too.)" if len(pk) > len(sec) else ""
            res.append(check("updates", "warn", f"{len(sec)} security update(s) waiting", f"{names(sec)}. {hint}{rest}"))
        elif pk:
            res.append(check("updates", "info", f"{len(pk)} software update(s) available", f"{names(pk)}. {hint}"))
        else:
            res.append(check("updates", "ok", "Software is up to date"))
    if age is None:
        res.append(check("updates-old", "info", "The package lists have not been refreshed by debrev yet",
                         "A daily timer runs 'apt-get update' (debrev-updates.timer); the first run comes shortly after the install."))
    elif age > updates.STALE_DAYS:
        res.append(check("updates-old", "warn", f"'apt update' last worked {int(age)} days ago",
                         "The list above may be out of date. Check: systemctl status debrev-updates"))
    why = _reboot_reason() if reboot is None else reboot
    if why:
        res.append(check("reboot", "info", "A restart is needed", why + ". On a pair, drain the server first."))
    return res


def audit(p: Paths, sshd_texts: list[str] | None = None, ss_text: str | None = None, probe=drops_unknown_host) -> list[dict]:
    out: list[dict] = []
    settings, serrs = st.load_settings(p)
    sec = settings["security"]
    hosts = st.load(p)[0]
    live = [h for h in hosts if h["enabled"]]

    # --- abuse protection
    if sec["rate_limit"]:
        out.append(check("rate", "ok", "Rate limiting is on",
                         f"{sec['rate']} requests/s per address (burst {sec['burst']}), {sec['connections']} connections; "
                         + ("local networks exempt" if sec["lan_exempt"] else "local networks limited too")))
        off = [h["domain"] for h in live if not h["rate_limit"]]
        if off:
            out.append(check("rate-off", "info", f"{len(off)} host(s) without rate limiting", ", ".join(off)))
        own = [h["domain"] for h in live if h["rate_limit"] and h["rate_limits"]]
        if own:
            out.append(check("rate-own", "info", f"{len(own)} host(s) with their own rate limits", ", ".join(own)))
    else:
        out.append(check("rate", "fail", "Rate limiting is off", "Turn it on in Settings > Security before opening the firewall."))

    r = probe()
    if r is True:
        out.append(check("default", "ok", "Unknown host names and bare-IP requests are dropped"))
    elif r is False:
        out.append(check("default", "fail", "nginx answers requests for unknown host names", "The catch-all server should close the connection."))
    else:
        out.append(check("default", "warn", "Could not test the catch-all server", "nginx did not answer on 127.0.0.1:80"))

    # --- certificates
    tls = [h for h in live if h["tls"]["enabled"]]
    if serrs:
        out.append(check("settings", "fail", "Settings are invalid", "; ".join(serrs)))
    if settings["acme"]["server"] != "production":
        out.append(check("acme", "warn", "Let's Encrypt is set to " + settings["acme"]["server"], "Visitors would get certificate warnings."))
    try:
        rows = cr.table(p, hosts, settings)
    except OSError:
        rows = []
    bad = [r_["name"] for r_ in rows if r_["state"] != "ok" or r_.get("needs")]
    if bad:
        out.append(check("certs", "warn", f"{len(bad)} certificate(s) not ready", ", ".join(sorted(bad))))
    http_hosts = [h["domain"] for h in tls if h["tls"]["cert"] == "auto" and h["tls"]["challenge"] == "http" and not h["domain"].startswith("*.")]
    if http_hosts:
        out.append(check("http01", "info", f"{len(http_hosts)} host(s) validate with HTTP-01",
                         "Port 80 must reach this server from the internet for issuing and renewal: " + ", ".join(http_hosts)))
    plain = [h["domain"] for h in live if not h["tls"]["enabled"]]
    if plain:
        out.append(check("plain", "warn", f"{len(plain)} host(s) have HTTPS turned off", ", ".join(plain)))

    # --- software updates (the root timer refreshes the package lists; installing stays manual)
    out.extend(update_checks(p))

    # --- admin surfaces
    listeners = parse_listening(_ss() if ss_text is None else ss_text)
    open_ports = sorted({port for addr, port in listeners if addr in ("0.0.0.0", "*", "::", "")})
    web = [port for port in open_ports if port == 8443]
    if web:
        out.append(check("web", "info", "Web interface listens on port 8443",
                         "It refuses requests from outside local networks, but never forward this port on the router."))
    extra = [x for x in open_ports if x not in (22, 80, 443, 8443)]
    if extra:
        out.append(check("ports", "info", "Other ports listen on all addresses", ", ".join(map(str, extra)) + " (keep them closed on the router)"))

    users = auth.load_users(p)
    if not users:
        out.append(check("users", "warn", "No web interface login exists yet", "debrev user add NAME"))
    else:
        no2fa = sorted(n for n, u in users.items() if not u.get("totp"))
        if no2fa:
            out.append(check("2fa", "info", "Web logins without two-factor", ", ".join(no2fa)))

    ssh = parse_sshd(_sshd_files() if sshd_texts is None else sshd_texts)
    root = ssh.get("permitrootlogin", "prohibit-password")
    pw = ssh.get("passwordauthentication", "yes")
    if root == "yes" and pw == "yes":
        out.append(check("ssh", "warn", "SSH allows root login with a password",
                         "Only matters if port 22 is reachable from the internet. Disable it before the project goes live (PermitRootLogin no)."))
    elif pw == "yes":
        out.append(check("ssh", "info", "SSH accepts passwords", "Keys only (PasswordAuthentication no) is safer if port 22 is ever exposed."))
    else:
        out.append(check("ssh", "ok", "SSH uses keys only"))

    if shutil.which("fail2ban-client"):
        out.append(check("fail2ban", "ok", "fail2ban is installed", "Repeated offenders can be banned (see README, Security)."))
    else:
        out.append(check("fail2ban", "info", "fail2ban is not installed", "Optional: sudo ./install.sh --fail2ban bans addresses that keep hitting the rate limit."))

    out.sort(key=lambda c: LEVEL_ORDER[c["level"]])
    return out


def verdict(checks: list[dict]) -> str:
    """'blocked' (a fail), 'caution' (warnings), or 'ready'."""
    levels = {c["level"] for c in checks}
    return "blocked" if "fail" in levels else "caution" if "warn" in levels else "ready"
