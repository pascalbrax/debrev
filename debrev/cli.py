"""Command line interface: `debrev <command>`."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from . import __version__, apply as ap, certs as cr, cluster as cl_, dns, node as nodemod, peer as pr_, state as st
from .paths import APP_DIR, Paths
from .render import render
from .schema import DOMAIN_RE, NAME_RE, normalise_host


def _load_or_exit(p: Paths):
    hosts, acls, errors, warnings = st.load(p)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if errors:
        print("validation errors:\n  " + "\n  ".join(errors), file=sys.stderr)
        sys.exit(1)
    return hosts, acls


def _author() -> str:
    return os.environ.get("DEBREV_AUTHOR") or os.environ.get("SUDO_USER") or os.environ.get("USER") or "debrev"


def _validate_all(p: Paths) -> list[str]:
    _, _, errors, _ = st.load(p)
    return errors


def cmd_init(a, p):
    p.lib.mkdir(parents=True, exist_ok=True)
    created = st.init(p)
    print("created state repository at" if created else "state repository already exists at", p.state)


def cmd_host_list(a, p):
    hosts, _ = _load_or_exit(p)
    for h in sorted(hosts, key=lambda x: x["domain"]):
        flags = [k for k in ("websockets",) if h[k]] + (["cache"] if h["cache"]["enabled"] else []) \
            + ([] if h["tls"]["enabled"] else ["no-tls"]) + ([] if h["enabled"] else ["DISABLED"])
        print(f"{h['domain']:40} -> {h['upstream']:30} {' '.join(flags)}")


def cmd_host_show(a, p):
    hosts, _ = _load_or_exit(p)
    for h in hosts:
        if h["domain"] == a.domain.lower():
            h = {k: v for k, v in h.items() if k != "file"}
            print(yaml.safe_dump(h, sort_keys=False), end="")
            return
    sys.exit(f"no such host: {a.domain}")


def cmd_host_add(a, p):
    dom = a.domain.lower()
    if not DOMAIN_RE.match(dom):
        sys.exit(f"invalid domain: {a.domain}")
    f = p.state / "hosts" / f"{dom}.yaml"
    if f.exists():
        sys.exit(f"{dom} already exists (use 'debrev host edit {dom}')")
    doc: dict = {"domain": dom, "upstream": a.upstream}
    if a.websockets:
        doc["websockets"] = True
    if a.cache:
        doc["cache"] = {"enabled": True}
    if a.no_tls:
        doc["tls"] = False
    elif a.cert_from:
        doc["tls"] = {"cert": "shared", "cert_from": a.cert_from}
    elif a.own_cert or a.challenge or a.wildcard:
        doc["tls"] = {**({"cert": "custom"} if a.own_cert else {}),
                      **({"challenge": "dns"} if a.wildcard else {"challenge": a.challenge} if a.challenge else {})}
    if a.wildcard and not dom.startswith("*."):
        doc["aliases"] = [*doc.get("aliases", []), f"*.{dom}"]
    if a.access_list:
        doc["access_list"] = a.access_list
    f.write_text(st.dump_yaml(doc))
    errors = _validate_all(p)
    if errors:
        f.unlink()
        sys.exit("not added:\n  " + "\n  ".join(errors))
    st.commit(p, f"host add: {dom}", _author())
    print(f"added {dom}; run 'debrev apply' to publish")


def cmd_host_rm(a, p):
    f = p.state / "hosts" / f"{a.domain.lower()}.yaml"
    if not f.exists():
        sys.exit(f"no such host: {a.domain}")
    old = f.read_text()
    f.unlink()
    users = [e for e in _validate_all(p) if "tls.cert_from" in e]
    if users:
        f.write_text(old)
        sys.exit(f"not removed: other hosts use its certificate:\n  " + "\n  ".join(users))
    st.commit(p, f"host remove: {a.domain}", _author())
    print(f"removed {a.domain}; run 'debrev apply' to publish")


def cmd_host_edit(a, p):
    f = p.state / "hosts" / f"{a.domain.lower()}.yaml"
    if not f.exists():
        sys.exit(f"no such host: {a.domain}")
    backup = f.read_text()
    subprocess.run([os.environ.get("EDITOR", "nano"), str(f)], check=False)
    if f.read_text() == backup:
        print("no changes")
        return
    errors = _validate_all(p)
    if errors:
        f.write_text(backup)
        sys.exit("changes discarded:\n  " + "\n  ".join(errors))
    st.commit(p, f"host edit: {a.domain}", _author())
    print("saved; run 'debrev apply' to publish")


def cmd_migrate_presets(a, p):
    done = st.migrate_presets(p)
    print("copied the preset settings into: " + ", ".join(done) if done else "no host used a preset")
    print("presets folder removed. Run 'debrev apply' to put the (unchanged) configuration live.")


def cmd_validate(a, p):
    hosts, acls, errors, warnings = st.load(p)
    for w in warnings:
        print(f"warning: {w}")
    if errors:
        print("validation errors:\n  " + "\n  ".join(errors))
        sys.exit(1)
    print(f"ok: {len(hosts)} host(s), {len(acls)} access list(s)")


def cmd_render(a, p):
    hosts, acls = _load_or_exit(p)
    resolved, dwarn = dns.resolve_all(p, hosts, save=False)
    files, warnings = render(p, hosts, acls, resolved, security=st.load_settings(p)[0]["security"])
    warnings = dwarn + warnings
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if a.out:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        for n, c in files.items():
            (out / n).write_text(c)
        print(f"wrote {len(files)} file(s) to {out}")
    else:
        for n, c in files.items():
            print(f"### {n}\n{c}")


def _via_root(flags: list[str]) -> None:
    """Re-run through the sudo-whitelisted helper when not root."""
    if os.geteuid() != 0 and not os.environ.get("DEBREV_ROOT"):
        os.execvp("sudo", ["sudo", "-n", str(APP_DIR / "bin" / "debrev-apply"), *flags])


def _finish(res) -> None:
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)
    print(res.message, file=sys.stdout if res.ok else sys.stderr)
    sys.exit(0 if res.ok else 1)


def cmd_apply(a, p):
    if os.geteuid() != 0 and not os.environ.get("DEBREV_ROOT"):
        r = subprocess.run(["sudo", "-n", str(APP_DIR / "bin" / "debrev-apply"), *(["--check"] if a.check else [])])
        if r.returncode == 0 and not a.check:
            _tell_peer(p)
        sys.exit(r.returncode)
    res = ap.apply(p, check_only=a.check)
    if res.ok and not a.check:
        _tell_peer(p)
    _finish(res)


def _tell_peer(p):
    try:
        n = nodemod.load(p)
    except nodemod.NodeError:
        return
    if n.has_peer:
        ok = pr_.notify(p, n)
        print("peer notified" if ok else "peer not reachable (it will catch up by itself)", file=sys.stderr)


def _stream_root(flags: list[str]) -> int:
    """Run the sudo helper and pass its output on live, hiding the machine-readable progress lines
    unless the web UI asked for them (DEBREV_PROGRESS=1)."""
    want = bool(os.environ.get("DEBREV_PROGRESS"))
    proc = subprocess.Popen(["sudo", "-n", str(APP_DIR / "bin" / "debrev-apply"), *flags], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        if line.startswith("@@") and not want:
            continue
        print(line, end="", flush=True)
    return proc.wait()


def cmd_certs_issue(a, p):
    if os.geteuid() != 0 and not os.environ.get("DEBREV_ROOT"):
        sys.exit(_stream_root(["--certs-force"] if a.force else ["--certs"]))
    _finish(cr.run(p, force=a.force, progress=bool(os.environ.get("DEBREV_PROGRESS"))))


def cmd_certs_upload(a, p):
    try:
        fc, key = Path(a.cert).read_text(), Path(a.key).read_text()
    except OSError as e:
        sys.exit(f"cannot read file: {e}")
    res = cr.upload(p, a.domain.lower().removeprefix("*."), fc, key)
    if res.ok:
        _tell_peer(p)
    _finish(res)


def cmd_certs_push(a, p):
    _via_root(["--cert-push"])
    _finish(cr.push(p))


def cmd_node_show(a, p):
    n = nodemod.load(p)
    print(f"name:         {n.name}\nacme issuer:  {'yes' if n.acme_issuer else 'no'}\npeer:         {n.peer_address or '-'}\n"
          f"priority:     {n.priority}\ninterface:    {n.interface or 'auto'}")


def cmd_node_set(a, p):
    n = nodemod.load(p)
    if a.name:
        n.name = a.name
    if a.issuer is not None:
        n.acme_issuer = a.issuer == "yes"
    if a.priority is not None:
        n.priority = a.priority
    if a.interface:
        n.interface = a.interface
    nodemod.save(p, n)
    cmd_node_show(a, p)


def cmd_traffic_collect(a, p):
    from . import traffic
    n = traffic.collect(p)
    if not a.quiet:
        print(f"counted {n} request(s)")


def cmd_security(a, p):
    from . import security as sc
    checks = sc.audit(p)
    mark = {"ok": "OK  ", "info": "info", "warn": "WARN", "fail": "FAIL"}
    for c in checks:
        print(f"{mark[c['level']]}  {c['title']}" + (f"\n        {c['detail']}" if c["detail"] else ""))
    v = sc.verdict(checks)
    print({"ready": "\nNo problems found.", "caution": "\nNo blockers, but read the warnings above.",
           "blocked": "\nNOT ready for the internet: fix the FAIL lines first."}[v])
    sys.exit(1 if v == "blocked" else 0)


def cmd_security_set(a, p):
    f = p.state / "settings.yaml"
    doc = st._load_yaml(f)
    sec = doc.setdefault("security", {})
    for key in ("rate_limit", "rate", "burst", "connections", "lan_exempt"):
        v = getattr(a, key)
        if v is not None:
            sec[key] = v
    old = f.read_text()
    f.write_text(yaml.safe_dump(doc, sort_keys=False))
    _, errs = st.load_settings(p)
    if errs:
        f.write_text(old)
        sys.exit("not saved:\n  " + "\n  ".join(errs))
    st.commit(p, "security settings", _author())
    print("saved. Run 'debrev apply' to put it live.")


def cmd_cluster_set(a, p):
    f = p.state / "settings.yaml"
    doc = yaml.safe_load(f.read_text()) or {}
    c = doc.setdefault("cluster", {})
    if a.vip:
        c["vip"] = a.vip
    if a.vrid:
        c["vrid"] = a.vrid
    old = f.read_text()
    f.write_text(yaml.safe_dump(doc, sort_keys=False))
    _, errs = st.load_settings(p)
    if errs:
        f.write_text(old)
        sys.exit("not saved:\n  " + "\n  ".join(errs))
    st.commit(p, "cluster settings", _author())
    print("saved. 'debrev apply' publishes it; the twin picks it up by sync and configures its own keepalived.")


def cmd_cluster_show(a, p):
    cl = cl_.cluster_settings(p)
    n = nodemod.load(p)
    me = cl_.local_view(p)
    print(f"virtual IP:   {cl['vip'] or '-'} (VRRP id {cl['vrid']})")
    print(f"this node:    {me['name']}  priority {n.priority}  VRRP {me['vrrp'] or '?'}  "
          f"{'healthy' if me['healthy'] else 'UNHEALTHY: ' + me['health']}{'  DRAINED' if me['drained'] else ''}")
    if n.has_peer:
        try:
            s = pr_.peer_status(p, n)["cluster"]
            print(f"twin:         {s['name']}  priority {s['priority']}  VRRP {s['vrrp'] or '?'}  "
                  f"{'healthy' if s['healthy'] else 'UNHEALTHY: ' + s['health']}{'  DRAINED' if s['drained'] else ''}")
        except (pr_.PeerError, ValueError, KeyError) as e:
            print(f"twin:         unreachable ({e})")
    if cl["vip"]:
        print(f"answering on the virtual IP right now: {cl_.probe_vip(cl['vip']) or 'nobody'}")


def cmd_drain(a, p):
    try:
        cl_.drain(p, force=a.force)
    except cl_.ClusterError as e:
        sys.exit(f"not drained: {e}")
    print("Next: apt update && apt full-upgrade (reboot if needed), then 'debrev restore'.")


def cmd_restore(a, p):
    try:
        cl_.restore(p)
    except cl_.ClusterError as e:
        sys.exit(f"not restored: {e}")


def cmd_peer_keygen(a, p):
    print(pr_.ensure_key(p))


def cmd_peer_authorize(a, p):
    n = nodemod.load(p)
    pr_.authorize(p, a.pubkey, from_ip=n.peer_address)
    print("peer key authorized (restricted to the debrev sync commands)")


def cmd_peer_set(a, p):
    n = nodemod.load(p)
    n.peer_address = a.address
    nodemod.save(p, n)
    print(f"peer set to {a.address}. Next: 'debrev peer keygen' here, 'debrev peer authorize <key>' on the peer (and vice versa), then 'debrev peer test'")


def cmd_peer_clear(a, p):
    n = nodemod.load(p)
    n.peer_address = None
    nodemod.save(p, n)
    print("peer removed")


def cmd_peer_test(a, p):
    n = nodemod.load(p)
    try:
        s = pr_.peer_status(p, n)
    except (pr_.PeerError, ValueError) as e:
        sys.exit(f"peer {n.peer_address} not usable: {e}")
    print(f"peer {s['name']} ({n.peer_address}): debrev {s['version']}, state format {s['format']}, "
          f"head {(s['head'] or '-')[:8]}, acme issuer: {'yes' if s['acme_issuer'] else 'no'}")
    if s["format"] > st.STATE_FORMAT:
        sys.exit("the peer runs a newer state format; update debrev here first")


def cmd_sync(a, p):
    mode = "theirs" if a.take_theirs else None
    if a.take_mine:
        n = nodemod.load(p)
        if not a.yes:
            sys.exit("--take-mine makes the peer discard its state (it keeps a backup branch). Add --yes to confirm.")
        print("peer told to adopt our state" if pr_.notify(p, n, force=True) else "could not reach the peer")
        return
    if mode and not a.yes:
        sys.exit("--take-theirs discards local changes (kept as a backup branch). Add --yes to confirm.")
    res = pr_.sync(p, mode=mode, retry=a.retry)
    if not a.quiet or not res.ok:
        print(res.message, file=sys.stdout if res.ok else sys.stderr)
    sys.exit(0 if res.ok else 1)


def cmd_certs_renew(a, p):
    if a.names:
        res = cr.renew_selected(p, [n.lower().removeprefix("*.") for n in a.names])
        _finish(res)
    _via_root(["--renew"])
    _finish(cr.renew(p))


def cmd_certs_list(a, p):
    hosts, _ = _load_or_exit(p)
    settings, _ = st.load_settings(p)
    rows = cr.table(p, hosts, settings)
    if not rows:
        print("no hosts use automatic certificates")
    for r in rows:
        exp = f"{r['expires']} ({r['days_left']}d)" if "expires" in r else "-"
        extra = " STAGING" if r.get("staging") else ""
        print(f"{r['name']:34} {r['state']:9} {exp:22} {r['challenge']}{extra}")
        if r.get("needs"):
            print(f"    needs: {r['needs']}")
        if r.get("last_error"):
            print(f"    last error: {r['last_error'][:200]} (next try {r.get('next_try', '?')[:16]})")


def cmd_acme_show(a, p):
    settings, _ = st.load_settings(p)
    print(yaml.safe_dump(settings["acme"], sort_keys=False), end="")


def cmd_acme_set(a, p):
    f = p.state / "settings.yaml"
    doc = yaml.safe_load(f.read_text()) or {}
    acme = doc.setdefault("acme", {})
    if a.email:
        acme["email"] = a.email
    if a.staging:
        acme["server"] = "staging"
    if a.production:
        acme["server"] = "production"
    if a.directory_url:
        acme["server"], acme["directory_url"] = "custom", a.directory_url
    if a.auto is not None:
        acme["auto"] = a.auto
    if a.dns_plugin:
        entry = {"plugin": a.dns_plugin, "credentials": a.dns_credentials or "", "propagation_seconds": a.dns_propagation}
        if a.dns_name:
            acme.setdefault("dns_providers", {})[a.dns_name] = entry
        else:
            acme["dns"] = entry
    old = f.read_text()
    f.write_text(yaml.safe_dump(doc, sort_keys=False))
    _, errs = st.load_settings(p)
    if errs:
        f.write_text(old)
        sys.exit("not saved:\n  " + "\n  ".join(errs))
    st.commit(p, "acme settings", _author())
    print("saved. Next: 'debrev certs issue' (HTTP challenge needs port 80 reachable from the internet)")


def cmd_dns(a, p):
    hosts, _ = _load_or_exit(p)
    names = sorted(dns.hostnames(hosts))
    if not names:
        print("no upstream host names in use (all upstreams are IP addresses)")
        return
    cache = json.loads((p.lib / "dns-cache.json").read_text()) if (p.lib / "dns-cache.json").exists() else {}
    for n in names:
        try:
            live = dns.lookup(n)
        except OSError as e:
            live = f"UNRESOLVED ({e})"
        c_ = cache.get(n, {})
        print(f"{n:30} now: {live:18} cached: {c_.get('ip', '-'):18} since {c_.get('time', '-')}")


def cmd_history(a, p):
    for r in st.log(p, a.n):
        print(f"{r['rev'][:8]}  {r['date'][:19]}  {r['author']:12}  {r['message']}")


def cmd_diff(a, p):
    print(st.diff(p, a.rev), end="")


def cmd_rollback(a, p):
    rows = st.log(p, 2)
    rev = a.rev or (rows[1]["rev"] if len(rows) > 1 else None)
    if not rev:
        sys.exit("nothing to roll back to")
    new = st.restore(p, rev)
    print(f"state restored to {rev[:8]} (new commit {new[:8] if new else 'none'}); run 'debrev apply' to publish")


def cmd_status(a, p):
    try:
        hosts, _, errors, _ = st.load(p)
    except st.StateError as e:
        sys.exit(str(e))
    head = st.head(p)
    applied = json.loads(p.applied.read_text()) if p.applied.exists() else {}
    print(f"debrev {__version__}")
    print(f"hosts:        {len(hosts)} ({sum(1 for h in hosts if h['enabled'])} enabled)")
    print(f"state commit: {head[:8] if head else '-'}{' (uncommitted changes!)' if st.is_dirty(p) else ''}")
    print(f"applied:      {applied.get('commit', '-')[:8]} at {applied.get('time', 'never')}")
    if head and applied.get("commit") and head != applied["commit"]:
        print("              (state is ahead of what nginx is serving; run 'debrev apply')")
    print(f"validation:   {'OK' if not errors else str(len(errors)) + ' error(s)'}")
    try:
        n = nodemod.load(p)
        print(f"node:         {n.name}; acme issuer: {'yes' if n.acme_issuer else 'no'}; peer: {n.peer_address or 'none'}")
        cv = cl_.cluster_settings(p)
        if cv["vip"]:
            lv = cl_.local_view(p)
            print(f"failover:     VIP {cv['vip']}; this node {lv['vrrp'] or 'VRRP not running'}{', DRAINED' if lv['drained'] else ''}{'' if lv['healthy'] else ', UNHEALTHY'}")
        if n.has_peer:
            s = pr_.read_status(p)
            print(f"sync:         {s.get('state', 'never run')}{(' - ' + s['message']) if s.get('message') else ''} (checked {s.get('updated', 'never')})")
    except nodemod.NodeError as e:
        print(f"node:         INVALID {e}")
    if not errors:
        settings, _ = st.load_settings(p)
        rows = cr.table(p, hosts, settings)
        bad = [r["name"] for r in rows if r["state"] != "ok"]
        print(f"certificates: {len(rows) - len(bad)}/{len(rows)} ok" + (f"; attention: {', '.join(bad)}" if bad else ""))


def cmd_export(a, p):
    """Write hosts, access lists and settings to one YAML file (no certificates, keys or tokens)."""
    from . import portable
    _load_or_exit(p)
    text = portable.export_text(p)
    if a.output and a.output != "-":
        Path(a.output).write_text(text)
        print(f"exported to {a.output}")
    else:
        sys.stdout.write(text)


def cmd_import(a, p):
    """Import hosts (and access lists; settings only with --settings) from an export file. Dry run unless --write."""
    from . import portable
    src = Path(a.file)
    try:
        text = src.read_text()
    except OSError as e:
        sys.exit(f"cannot read {src}: {e}")
    doc, errs = portable.parse(text)
    if errs:
        sys.exit(f"{src}: " + "; ".join(errs))
    _load_or_exit(p)
    pl = portable.plan(p, doc, overwrite=a.overwrite, settings=a.settings)
    todo = [i for i in pl["items"] if i["kind"] == "host" and i["action"] in ("new", "replace")]
    bad_names: set[str] = set()
    if todo:
        _, acls, _, _ = st.load(p)
        hs = [normalise_host(dict(yaml.safe_load(pl["writes"][p.state / "hosts" / f"{i['name']}.yaml"])), acls, i["name"])[0]
              for i in todo]
        bad_names = {n for n in dns.hostnames([h for h in hs if h]) if not _resolves(n)}
    for i in pl["items"]:
        tag = {"new": "import ", "replace": "replace", "skip": "skip   ", "invalid": "INVALID"}[i["action"]]
        print(f"{tag} {i['kind']:11} {i['name']:38} {i['note']}")
    n_new = sum(1 for i in pl["items"] if i["action"] in ("new", "replace"))
    print(f"\n{n_new} to write, {pl['problems']} invalid, {sum(1 for i in pl['items'] if i['action'] == 'skip')} skipped"
          + (f", {len(bad_names)} upstream name(s) not resolvable from this server: {', '.join(sorted(bad_names))}" if bad_names else "") + ".")
    if not a.write:
        print("dry run: nothing written. Add --write to save (not live until 'debrev apply').")
        return
    ok, msg = portable.apply(p, pl, _author(), src.name)
    print(msg)
    if not ok:
        sys.exit(1)

    print(f"imported {len(todo)} host(s). Review in the web interface, then apply.")


def _resolves(name: str) -> bool:
    try:
        dns.lookup(name)
        return True
    except Exception:
        return False


def can_sudo() -> bool:
    """True if the current user is allowed to use sudo (group sudo/wheel/admin or a passwordless rule)."""
    import grp
    import pwd
    try:
        me = pwd.getpwuid(os.geteuid()).pw_name
        gids = set(os.getgroups()) | {pwd.getpwnam(me).pw_gid}
        names = {grp.getgrgid(g).gr_name for g in gids}
    except KeyError:
        names = set()
    if names & {"sudo", "wheel", "admin"}:
        return True
    return subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0


NO_SUDO_HELP = ("warning: user '{u}' is not in the sudoers list (not in group 'sudo').\n"
                "  Fix as root:  usermod -aG sudo {u}   (then log out and in again)\n"
                "  or run this command directly as root.")


def cmd_user(a, p):
    import getpass
    from . import auth
    if a.action != "list" and not a.name:
        sys.exit("a user name is required")
    web_dir = p.lib / "web"
    if os.geteuid() != 0 and not os.access(web_dir, os.W_OK | os.X_OK) and not os.environ.get("DEBREV_ROOT"):
        if not can_sudo():
            sys.exit(NO_SUDO_HELP.format(u=os.environ.get("USER") or os.geteuid()))
        print("note: user accounts are owned by the 'debrev' service user; re-running with sudo ...", file=sys.stderr)
        os.execvp("sudo", ["sudo", str(APP_DIR / "bin" / "debrev"), *sys.argv[1:]])
    try:
        if a.action == "list":
            for n, u in sorted(auth.load_users(p).items()):
                print(f"{n:20} {'2FA on' if u.get('totp') else 'password only'}")
            return
        if a.action == "rm":
            auth.remove_user(p, a.name)
        elif a.action == "no2fa":
            auth.set_totp(p, a.name, None)
        else:
            pw = os.environ.get("DEBREV_PASSWORD")
            if pw is None:
                pw = getpass.getpass("Password: ")
                if pw != getpass.getpass("Again: "):
                    sys.exit("passwords differ")
            (auth.add_user if a.action == "add" else auth.set_password)(*((p, a.name, pw)))
        print("done")
    except auth.AuthError as e:
        sys.exit(f"error: {e}")


def cmd_web(a, p):
    from . import web
    web.serve(p)


def build_parser() -> argparse.ArgumentParser:
    ap_ = argparse.ArgumentParser(prog="debrev", description="Reverse proxy manager for Debian")
    ap_.add_argument("--version", action="version", version=__version__)
    sub = ap_.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create the state repository").set_defaults(fn=cmd_init)
    sub.add_parser("status", help="show state and applied versions").set_defaults(fn=cmd_status)
    sub.add_parser("validate", help="validate all state files").set_defaults(fn=cmd_validate)
    r = sub.add_parser("render", help="print or write generated nginx config")
    r.add_argument("--out")
    r.set_defaults(fn=cmd_render)
    a = sub.add_parser("apply", help="publish state to nginx (needs root / sudo)")
    a.add_argument("--check", action="store_true", help="validate and test only, change nothing")
    a.set_defaults(fn=cmd_apply)
    sub.add_parser("dns", help="show upstream host name resolution and cache").set_defaults(fn=cmd_dns)
    acme = sub.add_parser("acme", help="Let's Encrypt settings").add_subparsers(dest="sub", required=True)
    acme.add_parser("show").set_defaults(fn=cmd_acme_show)
    aset = acme.add_parser("set")
    aset.add_argument("--email")
    aset.add_argument("--staging", action="store_true", help="use the Let's Encrypt staging CA (untrusted certs, high limits)")
    aset.add_argument("--production", action="store_true")
    aset.add_argument("--directory-url", help="custom ACME server (private CA, testing)")
    aset.add_argument("--auto", dest="auto", action="store_true", default=None, help="let the timer issue missing certificates")
    aset.add_argument("--no-auto", dest="auto", action="store_false")
    aset.add_argument("--dns-plugin", help="certbot DNS plugin for DNS-01 / wildcards, e.g. cloudflare")
    aset.add_argument("--dns-credentials", help="absolute path of the plugin's credentials file (keep it in /etc/debrev, mode 600)")
    aset.add_argument("--dns-name", help="store this DNS provider under a name (hosts pick it with tls.dns_provider) instead of making it the default")
    aset.add_argument("--dns-propagation", type=int, default=60)
    aset.set_defaults(fn=cmd_acme_set)
    certs = sub.add_parser("certs", help="certificates").add_subparsers(dest="sub", required=True)
    certs.add_parser("list").set_defaults(fn=cmd_certs_list)
    ci = certs.add_parser("issue", help="get missing certificates, then re-apply (needs root / sudo)")
    ci.add_argument("--force", action="store_true", help="ignore the failure backoff")
    ci.set_defaults(fn=cmd_certs_issue)
    cn = certs.add_parser("renew", help="run certbot renew now, or force-renew the named certificates")
    cn.add_argument("names", nargs="*", help="certificate names (the main domain of the host); none = renew what is due")
    cn.set_defaults(fn=cmd_certs_renew)
    certs.add_parser("push", help="send certificates to the peer").set_defaults(fn=cmd_certs_push)
    cu = certs.add_parser("upload", help="install your own certificate for a host (tls.cert: custom)")
    cu.add_argument("domain")
    cu.add_argument("--cert", required=True, help="PEM file: certificate followed by the intermediate chain")
    cu.add_argument("--key", required=True, help="PEM file: unencrypted private key")
    cu.set_defaults(fn=cmd_certs_upload)
    node_ = sub.add_parser("node", help="settings of this server").add_subparsers(dest="sub", required=True)
    node_.add_parser("show").set_defaults(fn=cmd_node_show)
    ns = node_.add_parser("set")
    ns.add_argument("--name")
    ns.add_argument("--issuer", choices=["yes", "no"], help="may this node request new certificates? (follows the virtual IP once the cluster runs)")
    ns.add_argument("--priority", type=int, help="VRRP priority 1-254; the higher one owns the virtual IP when both are healthy")
    ns.add_argument("--interface", help="network interface for the virtual IP (default: the one towards the twin)")
    ns.set_defaults(fn=cmd_node_set)
    peer_ = sub.add_parser("peer", help="the twin server").add_subparsers(dest="sub", required=True)
    peer_.add_parser("keygen", help="create this node's sync key and print it").set_defaults(fn=cmd_peer_keygen)
    pa_ = peer_.add_parser("authorize", help="allow the twin's public key to sync with this node")
    pa_.add_argument("pubkey")
    pa_.set_defaults(fn=cmd_peer_authorize)
    ps_ = peer_.add_parser("set")
    ps_.add_argument("address", help="IP address of the twin")
    ps_.set_defaults(fn=cmd_peer_set)
    peer_.add_parser("clear").set_defaults(fn=cmd_peer_clear)
    peer_.add_parser("test", help="check the connection to the twin").set_defaults(fn=cmd_peer_test)
    tr = sub.add_parser("traffic", help="traffic statistics").add_subparsers(dest="sub", required=True)
    tc = tr.add_parser("collect", help="read new access-log lines into the statistics (a timer runs this every minute)")
    tc.add_argument("--quiet", action="store_true")
    tc.set_defaults(fn=cmd_traffic_collect)
    sec = sub.add_parser("security", help="exposure checklist; 'security set' changes the rate limits")
    sec.set_defaults(fn=cmd_security)
    secs = sec.add_subparsers(dest="sub")
    ss = secs.add_parser("set", help="rate limiting settings")
    ss.add_argument("--rate-limit", dest="rate_limit", type=lambda x: x.lower() in ("on", "yes", "true", "1"), metavar="on|off")
    ss.add_argument("--lan-exempt", dest="lan_exempt", type=lambda x: x.lower() in ("on", "yes", "true", "1"), metavar="on|off")
    ss.add_argument("--rate", type=int, help="requests per second per address")
    ss.add_argument("--burst", type=int)
    ss.add_argument("--connections", type=int, help="simultaneous connections per address")
    ss.set_defaults(fn=cmd_security_set)
    cluster = sub.add_parser("cluster", help="floating IP / failover").add_subparsers(dest="sub", required=True)
    cluster.add_parser("show").set_defaults(fn=cmd_cluster_show)
    cs = cluster.add_parser("set")
    cs.add_argument("--vip", help="the floating IPv4 address both nodes share")
    cs.add_argument("--vrid", type=int, help="VRRP id 1-255 (default 51); unique on your LAN")
    cs.set_defaults(fn=cmd_cluster_set)
    dr = sub.add_parser("drain", help="move the floating IP to the twin so this node can be upgraded")
    dr.add_argument("--force", action="store_true")
    dr.set_defaults(fn=cmd_drain)
    sub.add_parser("restore", help="make this node eligible for the floating IP again").set_defaults(fn=cmd_restore)
    sy = sub.add_parser("sync", help="reconcile state with the twin")
    sy.add_argument("--quiet", action="store_true")
    sy.add_argument("--retry", action="store_true", help="retry a peer state that failed to apply before")
    sy.add_argument("--take-theirs", action="store_true", help="resolve a conflict with the peer's state (backup branch kept)")
    sy.add_argument("--take-mine", action="store_true", help="resolve a conflict with this node's state")
    sy.add_argument("--yes", action="store_true")
    sy.set_defaults(fn=cmd_sync)
    h = sub.add_parser("history", help="show change history")
    h.add_argument("-n", type=int, default=20)
    h.set_defaults(fn=cmd_history)
    d = sub.add_parser("diff", help="show a change (default: latest)")
    d.add_argument("rev", nargs="?")
    d.set_defaults(fn=cmd_diff)
    rb = sub.add_parser("rollback", help="restore state from an earlier commit (default: previous)")
    rb.add_argument("rev", nargs="?")
    rb.set_defaults(fn=cmd_rollback)
    sub.add_parser("migrate-presets", help="one-time upgrade: copy the settings of the removed presets into the hosts").set_defaults(fn=cmd_migrate_presets)

    host = sub.add_parser("host", help="manage proxy hosts").add_subparsers(dest="sub", required=True)
    host.add_parser("list").set_defaults(fn=cmd_host_list)
    s = host.add_parser("show")
    s.add_argument("domain")
    s.set_defaults(fn=cmd_host_show)
    ad = host.add_parser("add")
    ad.add_argument("domain")
    ad.add_argument("upstream", help="e.g. http://10.0.0.5:3000")
    ad.add_argument("--websockets", action="store_true")
    ad.add_argument("--cache", action="store_true")
    ad.add_argument("--no-tls", action="store_true")
    ad.add_argument("--own-cert", action="store_true", help="use your own certificate (add it with 'debrev certs upload')")
    ad.add_argument("--cert-from", metavar="CERT", help="use an installed certificate (e.g. a wildcard one) instead of requesting one; CERT is the owning host's name, see 'debrev certs'")
    ad.add_argument("--challenge", choices=["http", "dns"], help="Let's Encrypt validation method (default http)")
    ad.add_argument("--wildcard", action="store_true", help="also cover *.DOMAIN with one wildcard certificate (DNS-01)")
    ad.add_argument("--access-list")
    ad.set_defaults(fn=cmd_host_add)
    for name, fn in (("rm", cmd_host_rm), ("edit", cmd_host_edit)):
        x = host.add_parser(name)
        x.add_argument("domain")
        x.set_defaults(fn=fn)
    ex = sub.add_parser("export", help="write hosts, access lists and settings to one YAML file (no certificates or keys)")
    ex.add_argument("-o", "--output", help="file to write (default: standard output)")
    ex.set_defaults(fn=cmd_export)
    im = sub.add_parser("import", help="import hosts and access lists from an export file (dry run unless --write)")
    im.add_argument("file")
    im.add_argument("--write", action="store_true", help="save the changes (they are not live until 'debrev apply')")
    im.add_argument("--overwrite", action="store_true", help="replace hosts and access lists that already exist (default: skip them)")
    im.add_argument("--settings", action="store_true", help="also import the settings sections (acme, cluster, security)")
    im.set_defaults(fn=cmd_import)
    us = sub.add_parser("user", help="web interface accounts")
    us.add_argument("action", choices=["add", "passwd", "rm", "list", "no2fa"])
    us.add_argument("name", nargs="?")
    us.set_defaults(fn=cmd_user)
    sub.add_parser("web", help="run the web interface (systemd does this)").set_defaults(fn=cmd_web)
    return ap_


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    p = Paths.from_env()
    try:
        args.fn(args, p)
    except st.StateError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except PermissionError as e:
        who = "root" if os.geteuid() == 0 else os.environ.get("USER", "this user")
        print(f"error: permission denied ({e.filename or e}).\n"
              f"warning: '{who}' is not allowed to do this. debrev data belongs to the 'debrev' user; "
              f"use 'sudo debrev ...' (or 'sudo -u debrev debrev ...').", file=sys.stderr)
        if os.geteuid() != 0 and not can_sudo():
            print(NO_SUDO_HELP.format(u=who), file=sys.stderr)
        return 1
    return 0
