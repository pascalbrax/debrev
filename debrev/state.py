"""The synced state: a plain git repository of YAML files.

state/
  settings.yaml
  hosts/<domain>.yaml
  access_lists/<name>.yaml
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
from pathlib import Path

import yaml

from . import STATE_FORMAT
from .paths import Paths
from .schema import NAME_RE, normalise_host, validate_access_list

SUBDIRS = ("hosts", "access_lists")
DEFAULT_SETTINGS = {"format": STATE_FORMAT}


class _Dumper(yaml.SafeDumper):
    pass


def _str_repr(dumper, data):
    # multi-line text (nginx snippets) as a readable block instead of one escaped line
    if "\n" in data and "\r" not in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper.add_representer(str, _str_repr)


def dump_yaml(data) -> str:
    return yaml.dump(data, Dumper=_Dumper, sort_keys=False, allow_unicode=True)


class StateError(Exception):
    pass


def _git(p: Paths, *args: str, check=True, author: str | None = None) -> str:
    env = dict(os.environ)
    name = author or "debrev"
    env.update(GIT_AUTHOR_NAME=name, GIT_COMMITTER_NAME=name,
               GIT_AUTHOR_EMAIL=f"{name}@{socket.gethostname()}",
               GIT_COMMITTER_EMAIL=f"{name}@{socket.gethostname()}")
    cmd = ["git", "-c", f"safe.directory={p.state}", "-C", str(p.state), *args]
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if check and r.returncode != 0:
        raise StateError(f"git {' '.join(args)} failed: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def init(p: Paths) -> bool:
    """Create the state repo. Returns False if it already exists."""
    if (p.state / ".git").exists():
        return False
    p.state.mkdir(parents=True, exist_ok=True)
    for d in SUBDIRS:
        (p.state / d).mkdir(exist_ok=True)
        (p.state / d / ".gitkeep").touch()
    (p.state / "settings.yaml").write_text(yaml.safe_dump(DEFAULT_SETTINGS))
    subprocess.run(["git", "-C", str(p.state), "init", "-q", "-b", "main"], check=True)
    commit(p, "init state")
    return True


def commit(p: Paths, message: str, author: str | None = None) -> str | None:
    _git(p, "add", "-A")
    if not _git(p, "status", "--porcelain").strip():
        return None
    _git(p, "commit", "-q", "-m", message, author=author)
    return head(p)


def head(p: Paths) -> str | None:
    out = _git(p, "rev-parse", "HEAD", check=False).strip()
    return out or None


def is_dirty(p: Paths) -> bool:
    return bool(_git(p, "status", "--porcelain").strip())


def log(p: Paths, n: int = 20) -> list[dict]:
    out = _git(p, "log", f"-n{n}", "--format=%H%x1f%an%x1f%aI%x1f%s", check=False)
    rows = []
    for line in out.splitlines():
        h, a, d, s = line.split("\x1f")
        rows.append({"rev": h, "author": a, "date": d, "message": s})
    return rows


def diff(p: Paths, rev: str | None = None) -> str:
    if rev is None:
        return _git(p, "show", "--format=%h %an: %s", "HEAD")
    return _git(p, "show", "--format=%h %an: %s", rev)


def restore(p: Paths, rev: str) -> str | None:
    """Make the working tree match `rev` and record it as a new commit."""
    _git(p, "rev-parse", "--verify", f"{rev}^{{commit}}")
    _git(p, "rm", "-r", "-q", "--cached", ".", check=False)
    _git(p, "checkout", rev, "--", ".")
    # drop files that did not exist at `rev`
    tracked = set(_git(p, "ls-tree", "-r", "--name-only", rev).splitlines())
    for f in _git(p, "ls-files", "-o", "--exclude-standard").splitlines():
        if f not in tracked:
            (p.state / f).unlink(missing_ok=True)
    return commit(p, f"rollback to {rev[:8]}")


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys instead of letting the last win."""

    def construct_mapping(self, node, deep=False):
        seen = set()
        for k, _ in node.value:
            key = self.construct_object(k, deep=True)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", k.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep)


def _load_yaml(path: Path):
    try:
        return yaml.load(path.read_text(), Loader=_StrictLoader) or {}
    except yaml.YAMLError as e:
        raise StateError(f"{path.name}: invalid YAML: {e}")


EMAIL_RE = re.compile(r"^[^@\s\"';\\]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~/-]*)?$")
SECURITY_DEFAULTS = {"rate_limit": True, "rate": 30, "burst": 200, "connections": 100, "lan_exempt": True}
SECURITY_LIMITS = {"rate": (1, 1000), "burst": (0, 10000), "connections": (1, 10000)}

ACME_DEFAULTS = {"email": None, "server": "production", "directory_url": None, "auto": False, "dns": None, "dns_providers": {}, "dns_default": None}


def _check_dns(dns, where: str, required: bool = False) -> list[str]:
    errs: list[str] = []
    if dns is None and not required:
        return errs
    if not isinstance(dns, dict) or set(dns) - {"plugin", "credentials", "propagation_seconds"}:
        return [f"settings.yaml: {where} needs plugin, credentials[, propagation_seconds]"]
    if not re.match(r"^[a-z0-9]+$", str(dns.get("plugin", ""))):
        errs.append(f"settings.yaml: {where}.plugin must be lower-case letters/digits (e.g. cloudflare)")
    if not re.match(r"^/[A-Za-z0-9._/-]+$", str(dns.get("credentials", ""))):
        errs.append(f"settings.yaml: {where}.credentials must be an absolute path")
    ps = dns.get("propagation_seconds", 60)
    if not isinstance(ps, int) or isinstance(ps, bool) or not 0 <= ps <= 3600:
        errs.append(f"settings.yaml: {where}.propagation_seconds must be 0-3600")
    return errs


def load_settings(p: Paths) -> tuple[dict, list[str]]:
    """Validated settings with defaults filled in."""
    errs: list[str] = []
    raw = _load_yaml(p.state / "settings.yaml")
    acme = {**ACME_DEFAULTS, **(raw.get("acme") or {})}
    for k in (raw.get("acme") or {}):
        if k not in ACME_DEFAULTS:
            errs.append(f"settings.yaml: unknown acme key '{k}'")
    if acme["email"] is not None and not EMAIL_RE.match(str(acme["email"])):
        errs.append(f"settings.yaml: invalid acme.email {acme['email']!r}")
    if acme["server"] not in ("production", "staging", "custom"):
        errs.append("settings.yaml: acme.server must be production, staging or custom")
    if acme["server"] == "custom" and not (acme["directory_url"] and URL_RE.match(str(acme["directory_url"]))):
        errs.append("settings.yaml: acme.server custom needs an https acme.directory_url")
    if not isinstance(acme["auto"], bool):
        errs.append("settings.yaml: acme.auto must be true or false")
    errs += _check_dns(acme["dns"], "acme.dns")
    provs = acme["dns_providers"]
    if acme["dns_default"] is not None and not (isinstance(provs, dict) and acme["dns_default"] in provs):
        errs.append("settings.yaml: acme.dns_default must name a provider from acme.dns_providers")
    if not isinstance(provs, dict):
        errs.append("settings.yaml: acme.dns_providers must be a mapping name -> {plugin, credentials}")
    else:
        for name, d in provs.items():
            if not NAME_RE.match(str(name)):
                errs.append(f"settings.yaml: invalid DNS provider name {name!r}")
            errs += _check_dns(d, f"acme.dns_providers.{name}", required=True)
    cl = {"vip": None, "vrid": 51, **(raw.get("cluster") or {})}
    for k in (raw.get("cluster") or {}):
        if k not in ("vip", "vrid"):
            errs.append(f"settings.yaml: unknown cluster key '{k}'")
    if cl["vip"] is not None:
        try:
            if ipaddress.ip_address(str(cl["vip"])).version != 4:
                raise ValueError
        except ValueError:
            errs.append(f"settings.yaml: cluster.vip must be an IPv4 address, got {cl['vip']!r}")
    if not isinstance(cl["vrid"], int) or isinstance(cl["vrid"], bool) or not 1 <= cl["vrid"] <= 255:
        errs.append("settings.yaml: cluster.vrid must be 1-255")
    sec = {**SECURITY_DEFAULTS, **(raw.get("security") or {})}
    for k in (raw.get("security") or {}):
        if k not in SECURITY_DEFAULTS:
            errs.append(f"settings.yaml: unknown security key '{k}'")
    for k in ("rate_limit", "lan_exempt"):
        if not isinstance(sec[k], bool):
            errs.append(f"settings.yaml: security.{k} must be true or false")
    for k, (lo, hi) in SECURITY_LIMITS.items():
        if not isinstance(sec[k], int) or isinstance(sec[k], bool) or not lo <= sec[k] <= hi:
            errs.append(f"settings.yaml: security.{k} must be a whole number {lo}-{hi}")
    return {"acme": acme, "cluster": cl, "security": sec}, errs


def load(p: Paths):
    """Load and validate the whole state.

    Returns (hosts, access_lists, errors, warnings). Hosts are normalised
    dicts, each with an extra 'file' key.
    """
    errors: list[str] = []
    warnings: list[str] = []
    if not (p.state / "settings.yaml").exists():
        raise StateError(f"no state at {p.state} (run 'debrev init')")
    settings = _load_yaml(p.state / "settings.yaml")
    if settings.get("format", 0) > STATE_FORMAT:
        raise StateError(f"state format {settings['format']} is newer than this debrev supports ({STATE_FORMAT}); update debrev")

    acls = {}
    for f in sorted((p.state / "access_lists").glob("*.yaml")):
        if not NAME_RE.match(f.stem):
            errors.append(f"access_lists/{f.name}: invalid name")
            continue
        try:
            a, errs = validate_access_list(_load_yaml(f), f"access_lists/{f.name}")
        except StateError as e:
            errors.append(str(e))
            continue
        errors += errs
        if a:
            acls[f.stem] = a

    hosts, seen = [], {}
    for f in sorted((p.state / "hosts").glob("*.yaml")):
        where = f"hosts/{f.name}"
        try:
            raw = _load_yaml(f)
        except StateError as e:
            errors.append(str(e))
            continue
        h, errs = normalise_host(raw, acls, where)
        errors += errs
        if not h:
            continue
        if f.stem != h["domain"]:
            warnings.append(f"{where}: file name does not match domain {h['domain']}")
        h["file"] = f.name
        for name in [h["domain"], *h["aliases"]]:
            if h["enabled"]:
                if name in seen:
                    errors.append(f"{where}: {name} is already served by {seen[name]}")
                seen[name] = f.name
        hosts.append(h)
    settings_, serrs = load_settings(p)
    errors += serrs
    known = set((settings_["acme"].get("dns_providers") or {})) if isinstance(settings_["acme"].get("dns_providers"), dict) else set()
    for h in hosts:
        prov = h["tls"].get("dns_provider")
        if prov and prov not in known:
            errors.append(f"hosts/{h['file']}: tls.dns_provider {prov!r} is not defined in settings (acme.dns_providers)")
    names: dict[str, str] = {}
    for h in hosts:
        if h["enabled"] and h["tls"]["enabled"] and (h["tls"]["cert"] == "auto" or not h["tls"]["cert_path"]):
            cn = h["domain"].removeprefix("*.")
            if cn in names:
                errors.append(f"hosts/{h['file']}: certificate name {cn!r} collides with {names[cn]}")
            names[cn] = h["file"]
    return hosts, acls, errors, warnings


def migrate_presets(p: Paths) -> list[str]:
    """One-time upgrade from the removed presets: copy each preset's settings into the hosts that
    used them (host values win), delete the presets folder, commit. Returns the migrated hosts."""
    from .schema import deep_merge
    pdir = p.state / "presets"
    presets = {f.stem: _load_yaml(f) for f in sorted(pdir.glob("*.yaml"))} if pdir.is_dir() else {}
    done = []
    for f in sorted((p.state / "hosts").glob("*.yaml")):
        raw = _load_yaml(f)
        names = raw.get("preset")
        if names is None:
            continue
        names = [names] if isinstance(names, str) else list(names)
        unknown = [n for n in names if n not in presets]
        if unknown:
            raise StateError(f"{f.name}: unknown preset {', '.join(unknown)}; nothing was changed")
        merged: dict = {}
        for n in names:
            merged = deep_merge(merged, presets[n])
        own = {k: v for k, v in raw.items() if k != "preset"}
        new = deep_merge(merged, own)
        order = [k for k in ("domain", "aliases", "upstream") if k in new]
        new = {k: new[k] for k in order + [k for k in new if k not in order]}
        f.write_text(dump_yaml(new))
        done.append(f.stem)
    if pdir.is_dir():
        shutil.rmtree(pdir)
    if done or not (pdir.is_dir()):
        commit(p, "migrate: presets copied into hosts" if done else "migrate: remove empty presets folder")
    return done
