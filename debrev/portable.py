"""Export the whole configuration to one YAML file and import it again (on this or another server).

The file holds hosts, access lists and settings, exactly as stored in the state repository. It never holds
certificates or private keys (those stay in /var/lib/debrev/certs and /etc/letsencrypt), nor DNS API tokens
(settings only name the credentials *file*), nor web logins, nor this server's own node settings.
Importing only writes files into the state repository and commits them; nothing goes live until 'apply'.
"""
from __future__ import annotations

import time
from pathlib import Path

import yaml

from . import state as st
from .paths import Paths
from .schema import HOST_KEYS, NAME_RE, normalise_host, validate_access_list

EXPORT_FORMAT = 1
MAX_BYTES = 2 * 1024 * 1024
TOP_KEYS = {"debrev_export", "exported", "hosts", "access_lists", "settings"}
SETTINGS_SECTIONS = ("acme", "cluster", "security")


def export_doc(p: Paths) -> dict:
    hosts = [st._load_yaml(f) for f in sorted((p.state / "hosts").glob("*.yaml"))]
    acls = {f.stem: st._load_yaml(f) for f in sorted((p.state / "access_lists").glob("*.yaml"))}
    raw = st._load_yaml(p.state / "settings.yaml")
    return {"debrev_export": EXPORT_FORMAT,
            "exported": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hosts": hosts, "access_lists": acls,
            "settings": {k: raw[k] for k in SETTINGS_SECTIONS if k in raw}}


def export_text(p: Paths) -> str:
    head = ("# debrev configuration export: hosts, access lists and settings.\n"
            "# No certificates, private keys, DNS tokens or logins are included.\n"
            "# Import with:  debrev import FILE [--write] [--overwrite] [--settings]   (or Hosts > Import in the web interface)\n")
    return head + st.dump_yaml(export_doc(p))


def parse(text: str) -> tuple[dict | None, list[str]]:
    """Read an export file (or the older plain '{hosts: [...]}' list)."""
    if len(text.encode()) > MAX_BYTES:
        return None, [f"file is larger than {MAX_BYTES // 1024 // 1024} MB"]
    try:
        doc = yaml.load(text, Loader=st._StrictLoader)
    except yaml.YAMLError as e:
        return None, [f"not valid YAML: {str(e).splitlines()[0]}"]
    if not isinstance(doc, dict):
        return None, ["expected a mapping with a 'hosts:' list"]
    ver = doc.get("debrev_export")
    if ver is not None and (not isinstance(ver, int) or ver > EXPORT_FORMAT):
        return None, [f"export format {ver!r} is newer than this debrev understands; update debrev"]
    if ver is not None:
        extra = set(doc) - TOP_KEYS
        if extra:
            return None, [f"unknown top-level key(s): {', '.join(sorted(map(str, extra)))}"]
    if not any(k in doc for k in ("hosts", "access_lists", "settings")):
        return None, ["nothing to import: expected 'hosts:', 'access_lists:' or 'settings:'"]
    if "hosts" in doc and not isinstance(doc["hosts"], list):
        return None, ["'hosts' must be a list"]
    if "access_lists" in doc and not isinstance(doc["access_lists"], dict):
        return None, ["'access_lists' must be a mapping"]
    if "settings" in doc and not isinstance(doc["settings"], dict):
        return None, ["'settings' must be a mapping"]
    return doc, []


def plan(p: Paths, doc: dict, overwrite: bool = False, settings: bool = False) -> dict:
    """What an import would do. {'items': [{kind, name, action, note}], 'writes': {Path: text}, 'problems': n}."""
    items: list[dict] = []
    writes: dict[Path, str] = {}
    legacy = "debrev_export" not in doc          # older plain host lists may carry keys we do not know

    def item(kind, name, action, note=""):
        items.append({"kind": kind, "name": name, "action": action, "note": note})

    new_acls: dict = {}
    for name, raw in (doc.get("access_lists") or {}).items():
        name = str(name)
        f = p.state / "access_lists" / f"{name}.yaml"
        if not NAME_RE.match(name):
            item("access list", name, "invalid", "invalid name")
            continue
        a, errs = validate_access_list(raw, name)
        if errs:
            item("access list", name, "invalid", "; ".join(errs))
        elif f.exists() and not overwrite:
            item("access list", name, "skip", "already exists")
        else:
            item("access list", name, "replace" if f.exists() else "new")
            writes[f] = st.dump_yaml(raw)
            new_acls[name] = a

    known_acls = {**{f.stem: None for f in (p.state / "access_lists").glob("*.yaml")}, **new_acls}
    seen: set[str] = set()
    for e in doc.get("hosts") or []:
        if not isinstance(e, dict):
            item("host", "?", "invalid", "entry is not a mapping")
            continue
        raw = {k: v for k, v in e.items() if k in HOST_KEYS} if legacy else dict(e)
        dom = str(raw.get("domain", "")).lower()
        h, errs = normalise_host(raw, {k: v or {"allow": [], "deny": []} for k, v in known_acls.items()}, dom or "?")
        f = p.state / "hosts" / f"{dom}.yaml"
        if errs or not h:
            item("host", dom or "?", "invalid", "; ".join(errs))
        elif dom in seen:
            item("host", dom, "invalid", "listed twice in the file")
        elif f.exists() and not overwrite:
            item("host", dom, "skip", "already exists")
        else:
            seen.add(dom)
            item("host", dom, "replace" if f.exists() else "new", f"-> {h['upstream']}")
            writes[f] = st.dump_yaml(raw)

    sets = doc.get("settings")
    if sets and not settings:
        item("settings", ", ".join(map(str, sets)), "skip", "not imported (ask for it explicitly)")
    elif sets:
        bad = [k for k in sets if k not in SETTINGS_SECTIONS]
        if bad:
            item("settings", ", ".join(map(str, bad)), "invalid", "unknown section")
        else:
            cur = st._load_yaml(p.state / "settings.yaml")
            cur.update({k: v for k, v in sets.items()})
            writes[p.state / "settings.yaml"] = st.dump_yaml(cur)
            item("settings", ", ".join(sets), "replace", "these sections are replaced")
    return {"items": items, "writes": writes, "problems": sum(1 for i in items if i["action"] == "invalid")}


def apply(p: Paths, pl: dict, author: str, source: str = "file") -> tuple[bool, str]:
    """Write a plan into the state repository, validate everything, undo on any error, commit."""
    if pl["problems"]:
        return False, "fix the invalid entries first"
    if not pl["writes"]:
        return True, "nothing to import"
    if st.is_dirty(p):
        return False, "there are unsaved changes in the state repository; apply or discard them first"
    before = {f: (f.read_text() if f.exists() else None) for f in pl["writes"]}
    for f, text in pl["writes"].items():
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    _, _, errors, _ = st.load(p)
    if errors:
        for f, old in before.items():
            f.unlink(missing_ok=True) if old is None else f.write_text(old)
        return False, "import rolled back:\n  " + "\n  ".join(errors)
    counts = {k: sum(1 for i in pl["items"] if i["kind"] == k and i["action"] in ("new", "replace"))
              for k in ("host", "access list", "settings")}
    msg = f"import from {source}: {counts['host']} host(s), {counts['access list']} access list(s)" \
          + (", settings" if counts["settings"] else "")
    st.commit(p, msg, author)
    return True, msg + ". Saved but not live yet: run 'debrev apply'."
