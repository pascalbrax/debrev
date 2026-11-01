"""Let's Encrypt certificates via certbot (webroot or DNS challenge).

One certificate per host, named after the host's main domain (wildcard
prefix removed): <letsencrypt>/live/<name>/{fullchain,privkey}.pem. The
rendered nginx config looks for exactly those files, so a host starts
serving HTTPS on the first apply after its certificate exists.
Renewal is left to Debian's certbot.timer; a deploy hook reloads nginx.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import apply as ap, node as nodemod, peer as peermod, state as st
from .paths import Paths

STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
PRODUCTION_URL = "https://acme-v02.api.letsencrypt.org/directory"
RENEW_WARN_DAYS = 14
RENEW_BEFORE_DAYS = 30


def _has_lineage(p: Paths, name: str) -> bool:
    try:
        return (p.letsencrypt / "renewal" / f"{name}.conf").exists()
    except PermissionError:
        return True      # cannot tell as an unprivileged user; do not raise false alarms


@dataclass
class Item:
    name: str
    domains: list[str]
    challenge: str
    host_file: str
    kind: str = "acme"          # "acme" (Let's Encrypt) or "custom" (uploaded by the admin)
    dns_provider: str | None = None


def plan(hosts: list[dict], custom: bool = False) -> list[Item]:
    """Certificates debrev manages. By default only Let's Encrypt ones (what can be issued);
    custom=True also lists uploaded certificates (what can be shown and synced)."""
    items = []
    for h in sorted(hosts, key=lambda x: x["domain"]):
        if not (h["enabled"] and h["tls"]["enabled"]):
            continue
        domains = [h["domain"], *h["aliases"]]
        name = h["domain"].removeprefix("*.")
        if h["tls"]["cert"] == "auto":
            wildcard = any(d.startswith("*.") for d in domains)
            # Let's Encrypt refuses a request naming both *.x and a.x ("redundant"); the wildcard covers a.x
            domains = [d for d in domains if d.startswith("*.") or f"*.{d.partition('.')[2]}" not in domains]
            items.append(Item(name, domains, "dns" if wildcard or h["tls"]["challenge"] == "dns" else "http", h["file"],
                              dns_provider=h["tls"].get("dns_provider")))
        elif custom and h["tls"]["cert"] == "custom" and not h["tls"]["cert_path"]:
            items.append(Item(name, domains, "custom", h["file"], kind="custom"))
    return items


from .schema import covers  # noqa: E402,F401  (kept here: callers use certs.covers)


def _summary_file(p: Paths) -> Path:
    return p.lib / "certs.json"


def _read_summary(p: Paths) -> dict:
    try:
        raw = json.loads(_summary_file(p).read_text())
    except (OSError, ValueError):
        return {}
    raw.pop("_credentials", None)
    for v in raw.values():
        if "expires" in v:
            v["expires"] = datetime.fromisoformat(v["expires"])
            v["sans"] = set(v["sans"])
            v["days_left"] = (v["expires"] - datetime.now(timezone.utc)).days
    return raw


def refresh_summary(p: Paths, hosts: list[dict]) -> None:
    """Root-only: publish non-secret certificate facts so unprivileged users
    (the CLI, later the web UI) never need to read /etc/letsencrypt."""
    out = {}
    for item in plan(hosts, custom=True):
        info = cert_info(p, item.name)
        if info and "expires" in info:
            out[item.name] = {**info, "expires": info["expires"].isoformat(), "sans": sorted(info["sans"])}
            if item.kind == "custom":
                out[item.name].update(fingerprint(p, item.name))
    fp = creds_fingerprint(p)
    if fp:
        out["_credentials"] = fp
    tmp = _summary_file(p).with_suffix(".tmp")
    tmp.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    tmp.chmod(0o644)
    tmp.replace(_summary_file(p))


def fingerprint(p: Paths, name: str) -> dict:
    """Content hash and install time of a certificate we hold (used to sync uploaded certificates)."""
    d = p.certs_dir / name
    try:
        return {"fp": hashlib.sha256((d / "fullchain.pem").read_bytes()).hexdigest(),
                "installed": int(d.resolve().stat().st_mtime)}
    except OSError:
        return {}


def cert_info(p: Paths, name: str) -> dict | None:
    """Parse the live certificate (root) or fall back to the published summary."""
    f = p.certs_dir / name / "fullchain.pem"
    try:
        present = f.exists()
    except PermissionError:
        return _read_summary(p).get(name)
    if not present:
        return None
    r = subprocess.run([*p.openssl_cmd, "x509", "-in", str(f), "-noout", "-enddate", "-issuer",
                        "-ext", "subjectAltName"], capture_output=True, text=True)
    if r.returncode != 0:
        return {"error": r.stderr.strip() or "unreadable certificate"}
    out = r.stdout
    m = re.search(r"notAfter=(.+)", out)
    expires = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    issuer = (re.search(r"issuer=(.+)", out) or [None, ""])[1]
    sans = set(re.findall(r"DNS:([^\s,]+)", out))
    return {"expires": expires, "days_left": (expires - datetime.now(timezone.utc)).days,
            "issuer": issuer.strip(), "sans": sans, "staging": "STAGING" in issuer.upper()}


def reason(p: Paths, item: Item, settings: dict) -> str | None:
    """Why this item needs (re)issuing now, or None."""
    info = cert_info(p, item.name)
    if item.kind == "custom":
        if info is None:
            return "upload a certificate"
        if "error" in info:
            return f"certificate unreadable ({info['error']})"
        missing = [d for d in item.domains if not covers(info["sans"], d)]
        return f"certificate does not cover {', '.join(missing)}" if missing else None
    if info is None:
        return "no certificate yet"
    if "error" in info:
        return f"certificate unreadable ({info['error']})"
    if info["sans"] != set(item.domains):
        return "host names changed"
    if settings["acme"]["server"] == "production" and info["staging"]:
        return "issued by the staging CA, production is configured"
    if info["days_left"] < RENEW_BEFORE_DAYS and not _has_lineage(p, item.name):
        # certbot's timer only renews what certbot itself issued here. After a failover the
        # new master holds a replicated certificate, so it must request a fresh one itself.
        return "renewal due and this node holds no certbot lineage for it"
    return None


# ---- the directory nginx reads ----------------------------------------------

def install_cert(p: Paths, name: str, fullchain: bytes, privkey: bytes, mtime: int | None = None) -> None:
    """Atomically make <certs_dir>/<name> point at a new version directory."""
    p.certs_dir.mkdir(parents=True, exist_ok=True)
    p.certs_dir.chmod(0o700)
    ver = p.certs_dir / f".{name}.{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}"
    ver.mkdir(mode=0o700)
    (ver / "fullchain.pem").write_bytes(fullchain)
    key = ver / "privkey.pem"
    key.write_bytes(privkey)
    key.chmod(0o600)
    if mtime:
        os.utime(ver, (mtime, mtime))
    link, tmp = p.certs_dir / name, p.certs_dir / f".{name}.link"
    old = os.readlink(link) if link.is_symlink() else None
    if tmp.is_symlink():
        tmp.unlink()
    tmp.symlink_to(ver.name)
    if link.exists() and not link.is_symlink():
        shutil.rmtree(link)
    os.replace(tmp, link)
    for d in p.certs_dir.glob(f".{name}.2*"):       # keep this and the previous version
        if d.name not in (ver.name, old):
            shutil.rmtree(d, ignore_errors=True)


def publish(p: Paths, hosts: list[dict]) -> list[str]:
    """Copy certbot's current lineages into the directory nginx reads."""
    changed = []
    for item in plan(hosts):
        src = p.letsencrypt / "live" / item.name
        if not (src / "fullchain.pem").exists():
            continue
        new = (src / "fullchain.pem").read_bytes()
        dst = p.certs_dir / item.name / "fullchain.pem"
        if dst.exists() and dst.read_bytes() == new:
            continue
        install_cert(p, item.name, new, (src / "privkey.pem").read_bytes())
        changed.append(item.name)
    return changed


CRED_MAX = 4096


def dns_for(acme: dict, provider: str | None) -> dict | None:
    """The DNS provider settings a certificate uses: a named one, or the default."""
    provs = acme.get("dns_providers") or {}
    if provider:
        return provs.get(provider)
    return acme.get("dns") or provs.get(acme.get("dns_default"))


def creds_paths(p: Paths) -> list[Path]:
    """Every DNS credentials file named in the synced settings (default provider and named ones)."""
    try:
        acme = st.load_settings(p)[0]["acme"]
    except st.StateError:
        return []
    allowed = (f"{p.letsencrypt}/", f"{p.etc}/")
    paths = []
    for d in [acme.get("dns"), *(acme.get("dns_providers") or {}).values()]:
        path = (d or {}).get("credentials")
        if path and path.startswith(allowed) and ".." not in path and Path(path) not in paths:
            paths.append(Path(path))
    return paths


def secure_creds(p: Paths) -> list[str]:
    """Root: make sure DNS token files are not readable by other users. Returns the files fixed."""
    fixed = []
    for f in creds_paths(p):
        try:
            if f.exists() and f.stat().st_mode & 0o077:
                f.chmod(0o600)
                fixed.append(str(f))
        except OSError:
            pass
    return fixed


def _fp_of(f: Path) -> dict | None:
    try:
        data = f.read_bytes()
        return {"sha256": hashlib.sha256(data).hexdigest(), "mtime": int(f.stat().st_mtime)} if data else None
    except OSError:
        return None


def creds_fingerprint(p: Paths) -> dict:
    """path -> {sha256, mtime} of the credential files we hold (non-secret; published for the twin)."""
    return {str(f): fp for f in creds_paths(p) if (fp := _fp_of(f))}


def creds_published(p: Paths) -> dict:
    """path -> {sha256, mtime} as published by root (readable by the web UI, which cannot read the files)."""
    try:
        return json.loads(_summary_file(p).read_text()).get("_credentials") or {}
    except (OSError, ValueError):
        return {}


def export_credentials(p: Paths) -> list[dict]:
    out = []
    for f in creds_paths(p):
        fp = _fp_of(f)
        if fp:
            out.append({"path": str(f), "content": f.read_text(), **fp})
    return out


def import_credentials(p: Paths, c: dict) -> dict:
    """Accept one DNS credentials file from the twin. Only paths named in the synced settings are
    writable, and only when the sender's copy is new or newer."""
    res = {"name": "dns credentials", "ok": False, "message": ""}
    f = next((x for x in creds_paths(p) if str(x) == c.get("path")), None)
    content = c.get("content")
    if f is None:
        res["message"] = "path is not a credentials file named in the settings (sync the state first)"
    elif not isinstance(content, str) or not content.strip() or len(content) > CRED_MAX or "\0" in content:
        res["message"] = "malformed credentials"
    else:
        mine = _fp_of(f)
        theirs_mtime = int(c.get("mtime") or 0)
        if mine and (mine["sha256"] == hashlib.sha256(content.encode()).hexdigest()):
            res["ok"], res["message"] = True, "already up to date"
        elif mine and mine["mtime"] >= theirs_mtime:
            res["ok"], res["message"] = True, "local copy is newer; kept"
        else:
            f.parent.mkdir(parents=True, exist_ok=True)
            tmp = f.with_name(f.name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(content)
            os.utime(tmp, (theirs_mtime, theirs_mtime))
            tmp.replace(f)
            res["ok"], res["message"] = True, "installed"
    return res


def export_all(p: Paths) -> dict:
    out = {}
    if p.certs_dir.is_dir():
        for d in sorted(p.certs_dir.iterdir()):
            if d.name.startswith(".") or not (d / "fullchain.pem").exists():
                continue
            out[d.name] = {"fullchain": (d / "fullchain.pem").read_text(), "privkey": (d / "privkey.pem").read_text()}
    return out


def _openssl(p: Paths, args: list[str], data: bytes) -> tuple[bool, str]:
    r = subprocess.run([*p.openssl_cmd, *args], input=data, capture_output=True)
    return r.returncode == 0, r.stdout.decode(errors="replace")


def check_pair(p: Paths, fullchain: bytes, privkey: bytes) -> tuple[datetime, set[str]]:
    """Validate a certificate + private key. Returns (expiry, names). Raises ValueError with a readable reason."""
    if b"BEGIN CERTIFICATE" not in fullchain:
        raise ValueError("this is not a PEM certificate")
    if b"PRIVATE KEY" not in privkey:
        raise ValueError("this is not a PEM private key")
    if b"ENCRYPTED" in privkey:
        raise ValueError("the private key is password protected; remove the passphrase first (openssl pkey -in key.pem -out plain.pem)")
    ok, txt = _openssl(p, ["x509", "-noout", "-enddate", "-ext", "subjectAltName"], fullchain)
    m = re.search(r"notAfter=(.+)", txt)
    if not ok or not m:
        raise ValueError("unreadable certificate")
    expires = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        raise ValueError("certificate already expired")
    ok1, pub1 = _openssl(p, ["x509", "-noout", "-pubkey"], fullchain)
    ok2, pub2 = _openssl(p, ["pkey", "-pubout", "-passin", "pass:"], privkey)
    if not (ok1 and ok2) or pub1.strip() != pub2.strip():
        raise ValueError("the private key does not match the certificate")
    return expires, set(re.findall(r"DNS:([^\s,]+)", txt))


def import_certs(p: Paths, payload: dict, hosts: list[dict]) -> list[dict]:
    """Accept certificates from the peer. Each is checked before it is installed:
    a known host, the expected names, key matches certificate, still valid, and
    (Let's Encrypt) newer than what we serve / (uploaded) newer than our copy."""
    expected = {i.name: i for i in plan(hosts, custom=True)}
    results = []
    for name, pair in sorted((payload.get("certs") or {}).items()):
        res = {"name": name, "ok": False, "message": ""}
        results.append(res)
        item = expected.get(name)
        if item is None:
            res["message"] = "unknown host (sync the state first)"
            continue
        try:
            fc, key = pair["fullchain"].encode(), pair["privkey"].encode()
        except (KeyError, AttributeError):
            res["message"] = "malformed entry"
            continue
        try:
            expires, sans = check_pair(p, fc, key)
        except ValueError as e:
            res["message"] = str(e)
            continue
        if item.kind == "custom":
            if any(not covers(sans, d) for d in item.domains):
                res["message"] = "certificate names do not cover this host"
                continue
            mine = fingerprint(p, name)
            if mine and mine["fp"] == hashlib.sha256(fc).hexdigest():
                res["ok"], res["message"] = True, "already up to date"
                continue
            incoming = int(pair.get("mtime") or 0)
            if mine and mine["installed"] >= incoming:
                res["ok"], res["message"] = True, "local copy is newer; kept"
                continue
            install_cert(p, name, fc, key, mtime=incoming or None)
            res["ok"], res["message"] = True, "installed"
            continue
        if sans != set(item.domains):
            res["message"] = "certificate names do not match this host"
            continue
        have = cert_info(p, name)
        if have and "expires" in have and have["expires"] >= expires:
            res["ok"], res["message"] = True, "already up to date"
            continue
        install_cert(p, name, fc, key)
        res["ok"], res["message"] = True, "installed"
    return results


def upload_custom(p: Paths, name: str, fullchain: bytes, privkey: bytes) -> ap.Result:
    """Install a certificate the admin supplied for a host that is set to use its own certificate."""
    if len(fullchain) > 100_000 or len(privkey) > 20_000:
        return ap.Result(False, "certificate or key is too large")
    try:
        hosts = st.load(p)[0]
    except st.StateError as e:
        return ap.Result(False, str(e))
    item = next((i for i in plan(hosts, custom=True) if i.name == name and i.kind == "custom"), None)
    if item is None:
        return ap.Result(False, f"{name} is not an enabled HTTPS host set to use its own certificate (tls.cert: custom)")
    try:
        expires, sans = check_pair(p, fullchain, privkey)
    except ValueError as e:
        return ap.Result(False, str(e))
    missing = [d for d in item.domains if not covers(sans, d)]
    if missing:
        return ap.Result(False, f"the certificate does not cover: {', '.join(missing)} (it has: {', '.join(sorted(sans)) or 'no names'})")
    install_cert(p, name, fullchain, privkey, mtime=int(datetime.now(timezone.utc).timestamp()))
    refresh_summary(p, hosts)
    res = ap.apply(p)
    lines = [f"installed certificate for {name}, valid until {expires.date()}", res.message]
    pr = push(p)
    lines.append(pr.message)
    return ap.Result(res.ok, "\n".join(lines))


def upload(p: Paths, name: str, fullchain: str, privkey: str) -> ap.Result:
    """Entry point for the CLI and web UI: runs upload_custom as root (directly, or through the sudo helper)."""
    if os.geteuid() == 0 or os.environ.get("DEBREV_ROOT"):
        return upload_custom(p, name, fullchain.encode(), privkey.encode())
    try:
        r = subprocess.run([*p.apply_cmd, "--cert-upload"], capture_output=True, text=True, timeout=180,
                           input=json.dumps({"name": name, "fullchain": fullchain, "privkey": privkey}))
    except subprocess.TimeoutExpired:
        return ap.Result(False, "timed out")
    return ap.Result(r.returncode == 0, (r.stdout + r.stderr).strip() or "(no output)")


def push(p: Paths, force: bool = False) -> ap.Result:
    """Issuer -> peer: send certificates the peer lacks or holds an older version of."""
    n = nodemod.load(p)
    if not n.has_peer:
        return ap.Result(True, "nothing to push (no peer configured)")
    secure_creds(p)
    try:                       # keep the non-secret summary the twin reads (certs.json) in step with the files
        refresh_summary(p, st.load(p)[0])
    except (st.StateError, OSError):
        pass
    mine = export_all(p)
    mycreds = export_credentials(p)
    if not mine and not mycreds:
        return ap.Result(True, "no certificates to push")
    try:
        r = peermod.remote(p, n, "cert-list", timeout=20)
        theirs = json.loads(r.stdout) if r.returncode == 0 else {}
    except (peermod.PeerError, ValueError) as e:
        return ap.Result(False, f"peer unreachable: {e}")
    todo = {}
    customs = {i.name for i in plan(st.load(p)[0], custom=True) if i.kind == "custom"}
    for name, pair in mine.items():
        info = cert_info(p, name)
        t = theirs.get(name, {})
        their = t.get("expires")
        if name in customs:       # uploaded certificates: the more recently installed copy wins
            fp = fingerprint(p, name)
            if force or not their or (fp and t.get("fp") != fp["fp"] and int(t.get("installed") or 0) < fp["installed"]):
                todo[name] = {**pair, "mtime": fp.get("installed")}
        elif force or not their or (info and "expires" in info and datetime.fromisoformat(their) < info["expires"]):
            todo[name] = pair
    send_creds = []
    tc_all = theirs.get("_credentials") or {}
    for cf in mycreds:
        tc = tc_all.get(cf["path"]) or {}
        if force or not tc or (tc.get("sha256") != cf["sha256"] and int(tc.get("mtime") or 0) < cf["mtime"]):
            send_creds.append(cf)
    if not todo and not send_creds:
        return ap.Result(True, "peer already has all certificates")
    try:
        r = peermod.remote(p, n, "cert-import", stdin=json.dumps({"certs": todo, **({"credentials": send_creds} if send_creds else {})}).encode(), timeout=120)
    except peermod.PeerError as e:
        return ap.Result(False, str(e))
    msg = r.stdout.decode(errors="replace").strip() or r.stderr.decode(errors="replace").strip()
    what = list(todo) + (["dns credentials"] * len(send_creds))
    return ap.Result(r.returncode == 0, f"pushed {', '.join(what)}: {msg[-600:]}")


def import_and_apply(p: Paths, raw: bytes) -> ap.Result:
    try:
        payload = json.loads(raw)
        hosts = st.load(p)[0]
    except (ValueError, st.StateError) as e:
        return ap.Result(False, f"bad request: {e}")
    results = import_certs(p, payload, hosts)
    creds = payload.get("credentials")
    for cf in ([creds] if isinstance(creds, dict) else creds if isinstance(creds, list) else []):
        if isinstance(cf, dict):
            results.append(import_credentials(p, cf))
    refresh_summary(p, hosts)
    lines = [f"{'ok  ' if r['ok'] else 'FAIL'} {r['name']}: {r['message']}" for r in results]
    if any(r["ok"] and r["message"] == "installed" for r in results):
        res = ap.apply(p)
        lines.append(res.message)
        return ap.Result(res.ok and all(r["ok"] for r in results), "\n".join(lines))
    return ap.Result(all(r["ok"] for r in results), "\n".join(lines))


def publish_and_reload(p: Paths) -> ap.Result:
    """Deploy-hook entry: new certbot material -> nginx dir -> reload -> tell the peer."""
    try:
        hosts = st.load(p)[0]
    except st.StateError as e:
        return ap.Result(False, str(e))
    changed = publish(p, hosts)
    refresh_summary(p, hosts)
    lines = [f"published: {', '.join(changed) or 'nothing new'}"]
    ok = True
    if changed:
        t = subprocess.run([*p.nginx_cmd, "-t"], capture_output=True, text=True)
        if t.returncode == 0:
            subprocess.run(list(p.reload_cmd), capture_output=True)
        else:
            ok = False
            lines.append("nginx -t failed, not reloaded: " + (t.stderr or t.stdout).strip()[-300:])
    pr = push(p)
    lines.append(pr.message)
    return ap.Result(ok and pr.ok, "\n".join(lines))


def server_url(acme: dict) -> str:
    return {"production": PRODUCTION_URL, "staging": STAGING_URL}.get(acme["server"]) or acme["directory_url"]


def build_cmd(p: Paths, settings: dict, item: Item, force_renewal: bool = False) -> list[str]:
    acme = settings["acme"]
    cmd = [*p.certbot_cmd, "certonly", "--non-interactive", "--agree-tos",
           "--email", acme["email"], "--cert-name", item.name, "--expand",
           "--config-dir", str(p.letsencrypt), "--server", server_url(acme)]
    if force_renewal:
        cmd.append("--force-renewal")
    if item.challenge == "http":
        cmd += ["--webroot", "-w", str(p.acme)]
    else:
        dns = dns_for(acme, item.dns_provider)
        plug = dns["plugin"]
        cmd += ["--authenticator", f"dns-{plug}", f"--dns-{plug}-credentials", dns["credentials"],
                f"--dns-{plug}-propagation-seconds", str(dns.get("propagation_seconds", 60))]
    for d in item.domains:
        cmd += ["-d", d]
    return cmd


def _explain(out: str) -> str:
    """The useful lines of certbot's output (Domain/Type/Detail), else its tail."""
    keys = ("Domain:", "Type:", "Detail:", "Error:", "Rate limit", "too many")
    lines = [l.strip() for l in out.splitlines() if any(k in l for k in keys)]
    return " | ".join(lines)[:500] or " ".join(out.splitlines()[-4:])[:400]


def _load_status(p: Paths) -> dict:
    try:
        return json.loads(p.cert_status.read_text())
    except (OSError, ValueError):
        return {}


def _save_status(p: Paths, data: dict) -> None:
    p.cert_status.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")


def issue_missing(p: Paths, hosts: list[dict], settings: dict, force: bool = False,
                  now: datetime | None = None, timeout: int = 300, renewals_only: bool = False,
                  only: set[str] | None = None, progress=None) -> list[dict]:
    """Request certificates for every item that needs one. Failed items back
    off (1h, 2h, 4h ... max 24h) so a misconfigured host cannot hit Let's
    Encrypt's rate limits; `force` ignores the backoff."""
    now = now or datetime.now(timezone.utc)
    acme = settings["acme"]
    results = []
    status = _load_status(p)
    reported: set[str] = set()
    for item in plan(hosts):
        if only is not None and item.name not in only:
            continue
        why = reason(p, item, settings)
        if only is not None and why is None:
            why = "renewal requested"          # the admin picked it: renew even if not due
        if why is None or (renewals_only and not why.startswith("renewal due")):
            continue
        res = {"name": item.name, "reason": why, "ok": False, "message": ""}
        results.append(res)
        if not acme["email"]:
            res["message"] = "set an email first: debrev acme set --email you@example.com"
            continue
        if item.challenge == "dns":
            dns = dns_for(acme, item.dns_provider)
            if not dns:
                res["message"] = ("DNS challenge needs a DNS provider: 'debrev acme set --dns-plugin ... --dns-credentials ...' "
                                  "(or the provider named by tls.dns_provider)")
                continue
            if not Path(dns["credentials"]).is_file():
                res["message"] = f"DNS credentials file {dns['credentials']} not found"
                continue
        s = status.get(item.name, {})
        if not force and s.get("next_try") and now < datetime.fromisoformat(s["next_try"]):
            res["message"] = f"backing off after earlier failure; next try {s['next_try'][:16]}Z ({s.get('last_error', '')[:120]})"
            continue
        force_renewal = "staging" in why or only is not None
        if progress:
            progress("start", item.name, True, "")
        try:
            r = subprocess.run(build_cmd(p, settings, item, force_renewal), capture_output=True,
                               text=True, timeout=timeout)
            ok, out = r.returncode == 0, (r.stdout + r.stderr).strip()
        except subprocess.TimeoutExpired:
            ok, out = False, f"certbot timed out after {timeout}s"
        if ok:
            publish(p, hosts)
            res.update(ok=True, message="issued")
            status.pop(item.name, None)
        else:
            fails = s.get("failures", 0) + 1
            wait = timedelta(hours=min(24, 2 ** (fails - 1)))
            res["message"] = _explain(out)
            hint = ""
            if item.challenge == "dns" and "unrecognized arguments" in out:
                hint = f" (is python3-certbot-dns-{dns_for(acme, item.dns_provider)['plugin']} installed?)"
            res["message"] += hint
            status[item.name] = {"failures": fails, "last_error": res["message"],
                                 "last_attempt": now.isoformat(timespec="seconds"),
                                 "next_try": (now + wait).isoformat(timespec="seconds")}
        if progress:
            progress("done", item.name, res["ok"], res["message"])
            reported.add(item.name)
    if progress:
        for r_ in results:                      # skipped before certbot ran (no e-mail, token file missing, ...)
            if r_["name"] not in reported:
                progress("done", r_["name"], False, r_["message"])
    _save_status(p, status)
    return results


def run(p: Paths, force: bool = False, auto: bool = False, progress: bool = False) -> ap.Result:
    """Make sure the plain-HTTP config is live, get missing certificates, then
    re-apply so the new certificates start serving."""
    try:
        hosts, _, errors, _ = st.load(p)
        settings, _ = st.load_settings(p)
    except st.StateError as e:
        return ap.Result(False, str(e))
    if errors:
        return ap.Result(False, "validation failed:\n  " + "\n  ".join(errors))
    if not nodemod.load(p).acme_issuer:
        return ap.Result(True, "this node is not the certificate issuer (the peer gets certificates from its twin)")
    renewals_only = auto and not settings["acme"]["auto"]      # acme.auto gates NEW certificates only
    wanted = [reason(p, i, settings) for i in plan(hosts)]
    if not any(w and (not renewals_only or w.startswith("renewal due")) for w in wanted):
        return ap.Result(True, "nothing to issue" if not renewals_only else "automatic issuing is off (acme.auto) and no renewals are due")
    first = ap.apply(p)
    if not first.ok:
        return first
    if progress:
        print(f"@@ total {sum(1 for w in wanted if w and (not renewals_only or w.startswith('renewal due')))}", flush=True)
    results = issue_missing(p, hosts, settings, force=force, renewals_only=renewals_only,
                            progress=print_progress if progress else None)
    lines = [f"{'OK  ' if r['ok'] else 'FAIL'} {r['name']}: {r['message'] or r['reason']}" for r in results]
    if any(r["ok"] for r in results):
        if progress:
            print("@@ applying", flush=True)
        refresh_summary(p, hosts)
        push(p)
        second = ap.apply(p)
        lines.append(second.message)
        if not second.ok:
            return ap.Result(False, "\n".join(lines))
    return ap.Result(all(r["ok"] for r in results), "\n".join(lines), warnings=first.warnings)


def print_progress(ev: str, name: str, ok: bool, msg: str) -> None:
    """Machine-readable progress lines; the web UI turns them into a progress bar."""
    print(f"@@ start {name}" if ev == "start" else
          f"@@ done {name} {'ok' if ok else 'fail'} {msg.splitlines()[0][:200] if msg else ''}", flush=True)


def run_selected(p: Paths, names: list[str]) -> ap.Result:
    """Renew exactly these Let's Encrypt certificates now (even if not due; backoff ignored)."""
    try:
        hosts, _, errors, _ = st.load(p)
        settings, _ = st.load_settings(p)
    except st.StateError as e:
        return ap.Result(False, str(e))
    if errors:
        return ap.Result(False, "validation failed:\n  " + "\n  ".join(errors))
    known = {i.name for i in plan(hosts)}
    bad = [n for n in names if n not in known]
    if bad or not names:
        return ap.Result(False, "not a Let's Encrypt certificate of an enabled host: " + (", ".join(bad) or "(none selected)"))
    if not nodemod.load(p).acme_issuer:
        return ap.Result(False, "this node is not the certificate issuer; do it on the node that holds the virtual IP")
    first = ap.apply(p)
    if not first.ok:
        return first
    print(f"@@ total {len(names)}", flush=True)
    results = issue_missing(p, hosts, settings, force=True, only=set(names), progress=print_progress)
    lines = [f"{'OK  ' if r['ok'] else 'FAIL'} {r['name']}: {r['message'] or r['reason']}" for r in results]
    if any(r["ok"] for r in results):
        print("@@ applying", flush=True)
        refresh_summary(p, hosts)
        push(p)
        second = ap.apply(p)
        lines.append(second.message)
    return ap.Result(all(r["ok"] for r in results), "\n".join(lines), warnings=first.warnings)


def renew_selected(p: Paths, names: list[str]) -> ap.Result:
    """CLI/web entry: run_selected as root (directly or through the sudo helper)."""
    if os.geteuid() == 0 or os.environ.get("DEBREV_ROOT"):
        return run_selected(p, names)
    try:
        proc = subprocess.Popen([*p.apply_cmd, "--certs-select"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        proc.stdin.write(json.dumps({"names": names}))
        proc.stdin.close()
        out = []
        for line in proc.stdout:               # pass lines on as they arrive (progress for the web UI)
            if line.startswith("@@") and not os.environ.get("DEBREV_PROGRESS"):
                continue                       # machine-readable progress: only the web UI wants it
            print(line, end="", flush=True)
            out.append(line)
        rc = proc.wait(timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        return ap.Result(False, f"could not run the helper: {e}")
    return ap.Result(rc == 0, "", warnings=[])


def renew(p: Paths) -> ap.Result:
    r = subprocess.run([*p.certbot_cmd, "renew", "--non-interactive", "--config-dir", str(p.letsencrypt)],
                       capture_output=True, text=True)
    try:
        refresh_summary(p, st.load(p)[0])
    except st.StateError:
        pass
    return ap.Result(r.returncode == 0, (r.stdout + r.stderr).strip()[-1500:])


def table(p: Paths, hosts: list[dict], settings: dict) -> list[dict]:
    rows = []
    status = _load_status(p)
    for item in plan(hosts, custom=True):
        info = cert_info(p, item.name)
        row = {"name": item.name, "domains": item.domains, "challenge": item.challenge, "kind": item.kind,
               "used_by": sorted(h["domain"] for h in hosts if h["enabled"] and h["tls"]["cert"] == "shared" and h["tls"]["cert_from"] == item.name)}
        if info is None:
            row["state"] = "missing"
        elif "error" in info:
            row["state"] = "error"
        else:
            row.update(expires=info["expires"].date().isoformat(), days_left=info["days_left"],
                       staging=info["staging"])
            row["state"] = ("expired" if info["days_left"] < 0 else
                            "expiring" if info["days_left"] < RENEW_WARN_DAYS else "ok")
        why = reason(p, item, settings)
        if why:
            row["needs"] = why
            if row["state"] == "ok":
                row["state"] = "outdated"           # valid, but not what the host needs (names changed, staging CA ...)
        if item.name in status:
            row["last_error"] = status[item.name].get("last_error")
            row["next_try"] = status[item.name].get("next_try")
        rows.append(row)
    return rows
