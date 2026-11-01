"""debrev web interface (FastAPI). Runs as the unprivileged 'debrev' user; every
privileged step goes through the same sudo-whitelisted helper the CLI uses.

Security model: reachable from private networks only (plus an explicit allow list),
HTTPS with a per-node certificate, argon2 + optional TOTP, signed cookie sessions,
CSRF token on every POST, strict CSP (no inline script/style), login throttling.
"""
from __future__ import annotations

import copy
import secrets
import threading
import time
from datetime import datetime
import difflib
import ipaddress
import json
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeSerializer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.concurrency import run_in_threadpool

from . import __version__, auth, portable, certs as cr, cluster as cl_, node as nodemod, peer as pr_, state as st, sysinfo, traffic as tf
from .paths import APP_DIR, Paths
from .schema import DOMAIN_RE, NAME_RE, normalise_host

WEB_DIR = APP_DIR / "data" / "web"
MAX_YAML = 200_000
COOKIE = "debrev_session"
KINDS = {"access_lists": "Access lists"}


def load_web_config(p: Paths) -> dict:
    cfg = {"listen": "0.0.0.0", "port": 8443, "allow": [],
           "cert": str(p.etc / "web.crt"), "key": str(p.etc / "web.key")}
    try:
        cfg.update(tomllib.loads((p.etc / "web.toml").read_text()).get("web", {}))
    except FileNotFoundError:
        pass
    return cfg


# Python's is_private also covers documentation/test ranges; list the real local ones explicitly.
LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10")]


def client_allowed(host: str, allow: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if any(ip in n for n in LOCAL_NETS):
        return True
    return any(ip in ipaddress.ip_network(a, strict=False) for a in allow)


def create_app(p: Paths | None = None, secure_cookie: bool = True) -> FastAPI:
    p = p or Paths.from_env()
    cfg = load_web_config(p)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    env = Environment(loader=FileSystemLoader(str(p.templates / "web")),
                      autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)
    env.filters["timefmt"] = lambda t: time.strftime("%d.%m. %H:%M:%S", time.localtime(t))
    flash_ser = URLSafeSerializer(auth.secret_key(p), salt="debrev-flash")

    # ---------------------------------------------------------------- plumbing
    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = request.client.host if request.client else ""
        if not client_allowed(host, cfg["allow"]):
            return PlainTextResponse("forbidden: this interface is reachable from the local network only\n", status_code=403)
        resp = await call_next(request)
        resp.headers.update({
            "Content-Security-Policy": "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; "
                                       "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
        })
        if secure_cookie:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    def redirect(url: str, msg: str | None = None, kind: str = "ok") -> RedirectResponse:
        r = RedirectResponse(url, status_code=303)
        if msg:
            r.set_cookie("flash", flash_ser.dumps({"m": msg, "k": kind}), httponly=True, samesite="strict",
                         secure=secure_cookie, max_age=60)
        return r

    def session(request: Request) -> dict:
        s = auth.read_session(p, request.cookies.get(COOKIE))
        if not s:
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        return s

    def pending(s=None) -> dict:
        info = {"dirty": False, "ahead": False}
        try:
            head = st.head(p)
            applied = json.loads(p.applied.read_text()) if p.applied.exists() else {}
            info["ahead"] = bool(head and applied.get("commit") != head)
            info["dirty"] = st.is_dirty(p)
        except (st.StateError, OSError, ValueError):
            pass
        return info

    def page(request: Request, tpl: str, s: dict | None, status: int = 200, **ctx) -> HTMLResponse:
        flash = None
        raw = request.cookies.get("flash")
        if raw:
            try:
                flash = flash_ser.loads(raw)
            except BadSignature:
                flash = None
        try:
            node_name = nodemod.load(p).name
        except nodemod.NodeError:
            node_name = "?"
        html = env.get_template(tpl).render(
            s=s, csrf=s["csrf"] if s else "", flash=flash, node=node_name, version=__version__,
            pending=pending() if s else None, nav=request.url.path, active=active_jobs() if s else [], **ctx)
        r = HTMLResponse(html, status_code=status)
        if raw:
            r.delete_cookie("flash")
        return r

    async def post(request: Request):
        s = session(request)
        form = await request.form()
        if not form.get("csrf") or form.get("csrf") != s["csrf"]:
            raise HTTPException(status_code=403, detail="invalid or missing CSRF token; reload the page")
        return s, form

    def cli(s: dict, *args: str, timeout: int = 300) -> tuple[bool, str]:
        import os
        env_ = dict(os.environ, DEBREV_AUTHOR=s["user"])
        try:
            r = subprocess.run([str(APP_DIR / "bin" / "debrev"), *args], capture_output=True, text=True,
                               timeout=timeout, env=env_)
        except subprocess.TimeoutExpired:
            return False, f"timed out after {timeout}s"
        return r.returncode == 0, (r.stdout + r.stderr).strip() or "(no output)"

    def result(request, s, title, ok, out, back="/"):
        return page(request, "result.html", s, title=title, ok=ok, out=out, back=back)

    def state_load():
        try:
            return st.load(p)
        except st.StateError as e:
            return [], {}, [str(e)], []

    def validation_errors() -> list[str]:
        try:
            return st.load(p)[2]
        except st.StateError as e:
            return [str(e)]

    def write_validated(rel: str, text: str | None, message: str, user: str) -> list[str]:
        """Write (or delete when text is None), validate the whole state, roll back on errors."""
        f = p.state / rel
        old = f.read_text() if f.exists() else None
        if text is None:
            f.unlink(missing_ok=True)
        else:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text)
        errs = validation_errors()
        if errs:
            if old is None:
                f.unlink(missing_ok=True)
            else:
                f.write_text(old)
            return errs
        st.commit(p, message, user)
        return []

    # ---------------------------------------------------------------- static / login
    @app.get("/static/{name}")
    def static(name: str):
        f = {"style.css": ("style.css", "text/css"), "app.js": ("app.js", "text/javascript"),
             "favicon.svg": ("favicon.svg", "image/svg+xml")}.get(name)
        if not f:
            raise HTTPException(404)
        return FileResponse(WEB_DIR / f[0], media_type=f[1], headers={"Cache-Control": "no-cache"})

    @app.get("/favicon.ico")
    def favicon():
        return FileResponse(WEB_DIR / "favicon.svg", media_type="image/svg+xml", headers={"Cache-Control": "max-age=86400"})

    @app.get("/login")
    def login_form(request: Request):
        if auth.read_session(p, request.cookies.get(COOKIE)):
            return RedirectResponse("/", status_code=303)
        return page(request, "login.html", None, no_users=not auth.load_users(p), error=None)

    @app.post("/login")
    async def login(request: Request):
        form = await request.form()
        ip = request.client.host if request.client else "?"
        try:
            user = await run_in_threadpool(auth.authenticate, p, str(form.get("user", "")),
                                           str(form.get("password", "")), str(form.get("code", "")), ip)
        except auth.AuthError as e:
            return page(request, "login.html", None, status=401, no_users=not auth.load_users(p), error=str(e))
        r = RedirectResponse("/", status_code=303)
        r.set_cookie(COOKIE, auth.make_session(p, user), httponly=True, samesite="strict",
                     secure=secure_cookie, max_age=auth.SESSION_SECONDS)
        return r

    @app.post("/logout")
    async def logout(request: Request):
        await post(request)
        r = RedirectResponse("/login", status_code=303)
        r.delete_cookie(COOKIE)
        return r

    # ---------------------------------------------------------------- dashboard
    def gather_status() -> dict:
        d: dict = {"errors": [], "hosts": [], "certs": [], "sync": None, "cluster": None, "applied": {}}
        hosts, _, errors, warnings = state_load()
        d.update(hosts=hosts, errors=errors, warnings=warnings)
        try:
            d["applied"] = json.loads(p.applied.read_text()) if p.applied.exists() else {}
        except (OSError, ValueError):
            pass
        d["head"] = (st.head(p) or "")[:8]
        if not errors:
            settings, _ = st.load_settings(p)
            d["certs"] = cr.table(p, hosts, settings)
        try:
            n = nodemod.load(p)
            d["peer"] = n.peer_address
            d["acme_issuer"] = n.acme_issuer
            cs = cl_.cluster_settings(p)
            if cs["vip"]:
                d["cluster"] = {**cl_.local_view(p), "vip": cs["vip"]}
            if n.has_peer:
                d["sync"] = pr_.read_status(p)
            d["nodes"] = overview(n, cs, d.get("cluster"))
        except nodemod.NodeError as e:
            d["errors"].append(f"node.toml: {e}")
        return d

    def own_ip(n) -> str:
        try:
            if n.has_peer:
                return cl_.iface_info(p, n)["src"]
        except (cl_.ClusterError, OSError, ValueError, KeyError):
            pass
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
                sk.connect(("192.0.2.1", 9))      # no packet is sent; picks the outgoing address
                return sk.getsockname()[0]
        except OSError:
            return "?"

    def overview(n, cs, local) -> list[dict]:
        """One row per server: address, whether this page is served by it, who holds the virtual IP."""
        me = local or cl_.local_view(p)
        rows = [{"name": n.name, "ip": own_ip(n), "here": True, "vrrp": me["vrrp"], "healthy": me["healthy"],
                 "drained": me["drained"], "priority": n.priority}]
        if n.has_peer:
            row = {"name": "twin", "ip": n.peer_address, "here": False, "vrrp": None, "healthy": None,
                   "drained": False, "priority": None, "error": None}
            try:
                t = pr_.peer_status(p, n, timeout=5)["cluster"]
                row.update(name=t["name"], vrrp=t["vrrp"], healthy=t["healthy"], drained=t["drained"], priority=t["priority"])
            except (pr_.PeerError, ValueError, KeyError) as e:
                row["error"] = str(e) or "no answer"
            rows.append(row)
        for r in rows:
            r["master"] = r["vrrp"] == "MASTER"
        return rows

    @app.get("/")
    def dashboard(request: Request, s=Depends(session)):
        return page(request, "dashboard.html", s, d=gather_status())

    @app.post("/apply")
    async def do_apply(request: Request):
        s, form = await post(request)
        check = form.get("mode") == "check"
        ok, out = await run_in_threadpool(cli, s, "apply", *(["--check"] if check else []))
        return result(request, s, "Check only (nothing changed)" if check else "Apply", ok, out)

    # ---------------------------------------------------------------- hosts
    def host_summary(h: dict) -> dict:
        return {"domain": h["domain"], "upstream": h["upstream"], "enabled": h["enabled"],
                "tls": h["tls"]["enabled"], "ws": h["websockets"], "cache": h["cache"]["enabled"],
                "aliases": h["aliases"], "acl": h["access_list"],
                "rl": "off" if not h["rate_limit"] else "custom" if h["rate_limits"] else None}

    @app.get("/hosts")
    def hosts_list(request: Request, s=Depends(session)):
        hosts, _, errors, _ = state_load()
        return page(request, "hosts.html", s, hosts=[host_summary(h) for h in sorted(hosts, key=lambda x: x["domain"])], errors=errors)

    # ---------------------------------------------------------------- export / import
    @app.get("/export")
    def export_file(s=Depends(session)):
        _, _, errors, _ = state_load()
        name = "debrev-export-" + datetime.now().strftime("%Y%m%d-%H%M") + ".yaml"
        return PlainTextResponse(portable.export_text(p), media_type="text/yaml",
                                 headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})

    @app.get("/import")
    def import_form(request: Request, s=Depends(session)):
        return page(request, "import.html", s)

    async def read_bundle(form) -> str:
        up = form.get("file")
        if up is not None and hasattr(up, "read"):
            data = await up.read(portable.MAX_BYTES + 1)
            if data:
                return data.decode("utf-8", "replace")
        return str(form.get("bundle") or "")

    def make_plan(text: str, form):
        doc, errs = portable.parse(text)
        if errs:
            return None, errs
        return portable.plan(p, doc, overwrite=bool(form.get("overwrite")), settings=bool(form.get("settings"))), []

    @app.post("/import/preview")
    async def import_preview(request: Request):
        s, form = await post(request)
        text = await read_bundle(form)
        if not text.strip():
            return page(request, "import.html", s, status=400, error="Choose a file or paste its contents.")
        pl, errs = await run_in_threadpool(make_plan, text, form)
        if errs:
            return page(request, "import.html", s, status=400, error="; ".join(errs))
        writable = [i for i in pl["items"] if i["action"] in ("new", "replace")]
        return page(request, "import_preview.html", s, items=pl["items"], problems=pl["problems"], count=len(writable),
                    bundle=text, overwrite=bool(form.get("overwrite")), settings=bool(form.get("settings")))

    @app.post("/import/apply")
    async def import_apply(request: Request):
        s, form = await post(request)
        text = str(form.get("bundle") or "")
        pl, errs = await run_in_threadpool(make_plan, text, form)       # planned again: the preview is never trusted
        if errs:
            return result(request, s, "Import", False, "; ".join(errs), back="/import")
        ok, msg = await run_in_threadpool(portable.apply, p, pl, s["user"], "web upload")
        return result(request, s, "Import", ok, msg, back="/hosts")

    def raw_host(domain: str) -> tuple[Path, dict]:
        f = p.state / "hosts" / f"{domain}.yaml"
        if not DOMAIN_RE.match(domain) or not f.exists():
            raise HTTPException(404, "no such host")
        return f, st._load_yaml(f)

    def form_ctx(raw: dict | None, new: bool, **extra):
        hosts, acls, _, _ = state_load()
        if raw is not None:
            h, _ = normalise_host(raw, acls, "form")
        else:
            h = None
        provs = sorted((st.load_settings(p)[0]["acme"].get("dns_providers") or {}))
        return dict(new=new, h=h, raw=raw or {}, acls=sorted(acls), providers=provs, **extra)

    @app.get("/hosts/new")
    def host_new_form(request: Request, s=Depends(session)):
        return page(request, "host_edit.html", s, cert=None, dns_ready=bool(cr.dns_for(st.load_settings(p)[0]["acme"], None)),
                    **form_ctx(None, True, yaml_text="", values={}))

    async def maybe_upload(domain: str, form):
        """If the form carries a certificate and key, install them. Returns a Result, or None when nothing was sent."""
        fc, key = str(form.get("fullchain", "")).strip(), str(form.get("privkey", "")).strip()
        if form.get("cert") != "custom" or not (fc or key):
            return None
        if not (fc and key):
            return cr.ap.Result(False, "Both the certificate and the private key are needed. The host itself was saved.")
        return await run_in_threadpool(cr.upload, p, domain.removeprefix("*."), fc + "\n", key + "\n")

    def _get(d, path):
        for k in path:
            d = d[k]
        return d

    def _set_flag(raw: dict, path: tuple, val: bool, acls) -> None:
        """Store `val` only if it differs from the default."""
        for top in ("tls", "cache"):
            if isinstance(raw.get(top), bool):
                raw[top] = {"enabled": raw[top]}
        probe = copy.deepcopy(raw)
        d = probe
        for k in path[:-1]:
            d = d.get(k, {}) if isinstance(d.get(k, {}), dict) else {}
        d.pop(path[-1], None)
        h, _ = normalise_host(probe, acls, "probe")
        base = _get(h, path) if h else None
        d = raw
        for k in path[:-1]:
            d = d.setdefault(k, {})
        if val == base:
            d.pop(path[-1], None)
            if len(path) > 1 and not d:
                raw.pop(path[0], None)
        else:
            d[path[-1]] = val

    def build_raw(form, base: dict, domain: str) -> dict:
        _, acls, _, _ = state_load()
        raw = copy.deepcopy(base)
        raw["domain"] = domain
        raw["upstream"] = str(form.get("upstream", "")).strip()
        al = [a.strip().lower() for a in str(form.get("aliases", "")).replace(",", "\n").splitlines() if a.strip()]
        wild = f"*.{domain}"
        if not domain.startswith("*."):          # checkbox "also all subdomains" = the wildcard alias
            al = [a for a in al if a != wild]
            if form.get("wildcard") == "on":
                al.append(wild)
        if al:
            raw["aliases"] = al
        else:
            raw.pop("aliases", None)
        own = form.get("cert") == "custom"
        _set_flag(raw, ("tls", "cert"), "custom" if own else "auto", acls)
        _set_flag(raw, ("tls", "challenge"), "dns" if form.get("challenge") == "dns" or form.get("wildcard") == "on" else "http", acls)
        prov = str(form.get("dns_provider", "")).strip() or None
        _set_flag(raw, ("tls", "dns_provider"), prov, acls)
        if not own and isinstance(raw.get("tls"), dict):
            raw["tls"].pop("cert_path", None)
            raw["tls"].pop("key_path", None)
        for path, key in ((("websockets",), "websockets"), (("cache", "enabled"), "cache"),
                          (("tls", "enabled"), "tls"), (("tls", "force_https"), "force_https"),
                          (("tls", "hsts"), "hsts"), (("enabled",), "enabled")):
            _set_flag(raw, path, form.get(key) == "on", acls)
        if "adv" in form:                        # advanced block present in the posted form
            if form.get("rate_limit") != "on":
                raw["rate_limit"] = False
            else:
                lim = {}
                for k in ("rate", "burst", "connections"):
                    v = str(form.get(f"rl_{k}", "")).strip()
                    if v:
                        lim[k] = int(v) if v.isdigit() else v
                if lim:
                    raw["rate_limit"] = lim
                else:
                    raw.pop("rate_limit", None)
            _set_flag(raw, ("buffering",), form.get("buffering") == "on", acls)
            _set_flag(raw, ("request_buffering",), form.get("request_buffering") == "on", acls)
            to = {k: str(form.get(f"to_{k}", "")).strip() for k in ("connect", "read", "send")}
            to = {k: v for k, v in to.items() if v}
            if to:
                raw["timeouts"] = to
            else:
                raw.pop("timeouts", None)
            snip = str(form.get("custom_snippet", "")).replace("\r\n", "\n").strip("\n")
            if snip.strip():
                raw["custom_snippet"] = snip + "\n"
            else:
                raw.pop("custom_snippet", None)
        else:
            _set_flag(raw, ("rate_limit",), form.get("rate_limit") == "on", acls)
        for key in ("max_body", "note"):
            v = str(form.get(key, "")).strip()
            if v:
                raw[key] = v
            else:
                raw.pop(key, None)
        acl = str(form.get("access_list", "")).strip()
        if acl:
            raw["access_list"] = acl
        else:
            raw.pop("access_list", None)
        return raw

    @app.post("/hosts/new")
    async def host_new(request: Request):
        s, form = await post(request)
        domain = str(form.get("domain", "")).strip().lower()
        values = {"domain": domain, "upstream": form.get("upstream", ""), "aliases": form.get("aliases", "")}
        if not DOMAIN_RE.match(domain):
            return page(request, "host_edit.html", s, status=400, **form_ctx(None, True, yaml_text="", values=values, errors=[f"invalid domain {domain!r}"]))
        if (p.state / "hosts" / f"{domain}.yaml").exists():
            return page(request, "host_edit.html", s, status=400, **form_ctx(None, True, yaml_text="", values=values, errors=[f"{domain} already exists"]))
        raw = build_raw(form, {}, domain)
        text = st.dump_yaml(raw)
        errs = await run_in_threadpool(write_validated, f"hosts/{domain}.yaml", text, f"host add: {domain} (web)", s["user"])
        if errs:
            return page(request, "host_edit.html", s, status=400, **form_ctx(raw, True, yaml_text=text, values=values, errors=errs))
        up = await maybe_upload(domain, form)
        if up:
            return result(request, s, f"Added {domain}; certificate " + ("installed" if up.ok else "NOT installed"), up.ok, up.message, f"/hosts/{domain}")
        if form.get("cert") == "custom":
            return redirect(f"/hosts/{domain}", f"Added {domain}. Now paste your certificate below.")
        if form.get("then") == "apply":
            ok, out = await run_in_threadpool(cli, s, "apply")
            return result(request, s, f"Added {domain} and applied", ok, out, "/hosts")
        return redirect("/hosts", f"Added {domain}. Not live until you apply.")

    def cert_row(domain: str):
        hosts, _, errors, _ = state_load()
        if errors:
            return None
        settings, _ = st.load_settings(p)
        name = domain.removeprefix("*.")
        return next((r for r in cr.table(p, hosts, settings) if r["name"] == name), None)

    @app.get("/hosts/{domain}")
    def host_form(domain: str, request: Request, s=Depends(session)):
        f, raw = raw_host(domain)
        return page(request, "host_edit.html", s, cert=cert_row(domain),
                    dns_ready=bool(cr.dns_for(st.load_settings(p)[0]["acme"], None)),
                    **form_ctx(raw, False, yaml_text=f.read_text(), values={}))

    @app.post("/hosts/{domain}")
    async def host_save(domain: str, request: Request):
        s, form = await post(request)
        f, base = raw_host(domain)
        action = form.get("action", "save")
        if action == "delete":
            await run_in_threadpool(write_validated, f"hosts/{domain}.yaml", None, f"host remove: {domain} (web)", s["user"])
            return redirect("/hosts", f"Removed {domain}. Not live until you apply.")
        if action == "upload_cert":
            fc, key = str(form.get("fullchain", "")).strip() + "\n", str(form.get("privkey", "")).strip() + "\n"
            res = await run_in_threadpool(cr.upload, p, domain.removeprefix("*."), fc, key)
            return result(request, s, "Certificate upload", res.ok, res.message, f"/hosts/{domain}")
        if action == "yaml":
            text = str(form.get("yaml", "")).replace("\r\n", "\n")
            if len(text) > MAX_YAML:
                raise HTTPException(413)
            try:
                parsed = st.yaml.load(text, Loader=st._StrictLoader)
                if not isinstance(parsed, dict) or str(parsed.get("domain", "")).lower() != domain:
                    raise ValueError("the 'domain' field must stay " + domain)
                errs = await run_in_threadpool(write_validated, f"hosts/{domain}.yaml", text, f"host edit: {domain} (web, yaml)", s["user"])
            except (yaml.YAMLError, ValueError) as e:
                errs = [str(e)]
            if errs:
                return page(request, "host_edit.html", s, status=400, **form_ctx(base, False, yaml_text=text, values={}, errors=errs, tab="yaml"))
            return redirect(f"/hosts/{domain}", "Saved. Not live until you apply.")
        raw = build_raw(form, base, domain)
        text = st.dump_yaml(raw)
        errs = await run_in_threadpool(write_validated, f"hosts/{domain}.yaml", text, f"host edit: {domain} (web)", s["user"])
        if errs:
            return page(request, "host_edit.html", s, status=400, **form_ctx(raw, False, yaml_text=text, values={}, errors=errs))
        up = await maybe_upload(domain, form)
        if up:
            return result(request, s, f"Saved {domain}; certificate " + ("installed" if up.ok else "NOT installed"), up.ok, up.message, f"/hosts/{domain}")
        if form.get("then") == "apply":
            ok, out = await run_in_threadpool(cli, s, "apply")
            return result(request, s, f"Saved {domain} and applied", ok, out, f"/hosts/{domain}")
        return redirect(f"/hosts/{domain}", "Saved. Not live until you apply.")

    # ---------------------------------------------------------------- access lists
    def kind_dir(kind: str) -> Path:
        if kind not in KINDS:
            raise HTTPException(404)
        return p.state / kind

    @app.get("/files/{kind}")
    def files_list(kind: str, request: Request, s=Depends(session)):
        d = kind_dir(kind)
        rows = []
        for f in sorted(d.glob("*.yaml")):
            first = (f.read_text().splitlines() or [""])[0]
            rows.append({"name": f.stem, "info": first.lstrip("# ") if first.startswith("#") else ""})
        return page(request, "files.html", s, kind=kind, title=KINDS[kind], rows=rows)

    @app.get("/files/{kind}/{name}")
    def file_form(kind: str, name: str, request: Request, s=Depends(session)):
        d = kind_dir(kind)
        if name == "_new":
            return page(request, "file_edit.html", s, kind=kind, title=KINDS[kind], name="", new=True, text="")
        if not NAME_RE.match(name) or not (d / f"{name}.yaml").exists():
            raise HTTPException(404)
        return page(request, "file_edit.html", s, kind=kind, title=KINDS[kind], name=name, new=False,
                    text=(d / f"{name}.yaml").read_text())

    @app.post("/files/{kind}/{name}")
    async def file_save(kind: str, name: str, request: Request):
        s, form = await post(request)
        d = kind_dir(kind)
        new = name == "_new"
        if new:
            name = str(form.get("name", "")).strip().lower()
        if not NAME_RE.match(name):
            return page(request, "file_edit.html", s, status=400, kind=kind, title=KINDS[kind], name=name, new=new,
                        text=str(form.get("yaml", "")), errors=["name: lower-case letters, digits, - and _"])
        rel = f"{kind}/{name}.yaml"
        if new and (d / f"{name}.yaml").exists():
            return page(request, "file_edit.html", s, status=400, kind=kind, title=KINDS[kind], name=name, new=True,
                        text=str(form.get("yaml", "")), errors=[f"{name} already exists"])
        if form.get("action") == "delete":
            errs = await run_in_threadpool(write_validated, rel, None, f"{kind} remove: {name} (web)", s["user"])
            if errs:
                return page(request, "file_edit.html", s, status=400, kind=kind, title=KINDS[kind], name=name, new=False,
                            text=(d / f"{name}.yaml").read_text(), errors=["cannot remove (still in use?)"] + errs)
            return redirect(f"/files/{kind}", f"Removed {name}.")
        text = str(form.get("yaml", "")).replace("\r\n", "\n")
        if len(text) > MAX_YAML:
            raise HTTPException(413)
        try:
            st.yaml.load(text, Loader=st._StrictLoader)
            errs = await run_in_threadpool(write_validated, rel, text, f"{kind} edit: {name} (web)", s["user"])
        except yaml.YAMLError as e:
            errs = [str(e)]
        if errs:
            return page(request, "file_edit.html", s, status=400, kind=kind, title=KINDS[kind], name=name, new=new,
                        text=text, errors=errs)
        return redirect(f"/files/{kind}", f"Saved {name}. Not live until you apply.")

    # ---------------------------------------------------------------- background certificate jobs
    jobs: dict[str, dict] = {}
    jobs_lock = threading.Lock()

    def running_job() -> dict | None:
        with jobs_lock:
            return next((j for j in jobs.values() if j["state"] == "running"), None)

    def job_view(j: dict) -> dict:
        with jobs_lock:
            done = sum(1 for i in j["items"].values() if i["state"] in ("ok", "fail"))
            return {"id": j["id"], "state": j["state"], "total": max(j["total"], len(j["items"])), "done": done, "phase": j["phase"],
                    "title": j["title"],
                    "items": [{"name": n, **i} for n, i in j["items"].items()], "now": time.time(),
                    "started": j["started"], "ok": j["ok"], "log": "\n".join(j["log"][-80:])}

    def run_job(j: dict, user: str) -> None:
        import os
        env_ = dict(os.environ, DEBREV_AUTHOR=user)
        try:
            env_["DEBREV_PROGRESS"] = "1"
            proc = subprocess.Popen([str(APP_DIR / "bin" / "debrev"), *j["cmd"]], env=env_,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                line = line.rstrip("\n")
                with jobs_lock:
                    parts = line.split(" ", 4)
                    if parts[0] == "@@" and len(parts) >= 3 and parts[1] == "total" and parts[2].isdigit():
                        j["total"] = int(parts[2])
                    elif parts[0] == "@@" and len(parts) >= 3 and parts[1] in ("start", "done"):
                        it = j["items"].setdefault(parts[2], {"state": "pending", "message": "", "since": None})
                        if parts[1] == "start":
                            it.update(state="running", since=time.time())
                        elif parts[1] == "done" and len(parts) >= 4:
                            it.update(state="ok" if parts[3] == "ok" else "fail", message=parts[4] if len(parts) > 4 else "")
                    elif parts[0] == "@@" and len(parts) >= 2 and parts[1] == "applying":
                        j["phase"] = "Applying the new certificates"
                    elif line and not line.startswith("@@"):
                        j["log"].append(line)
            rc = proc.wait()
        except OSError as e:
            rc = 1
            j["log"].append(str(e))
        with jobs_lock:
            for it in j["items"].values():
                if it["state"] in ("pending", "running"):
                    it.update(state="fail", message=it["message"] or "did not finish")
            j["state"], j["ok"], j["phase"] = "finished", rc == 0, "Finished"

    def active_jobs() -> list[dict]:
        with jobs_lock:
            return [{"id": j["id"], "title": j["title"],
                     "done": sum(1 for i in j["items"].values() if i["state"] in ("ok", "fail")),
                     "total": max(j["total"], len(j["items"]))} for j in jobs.values() if j["state"] == "running"]

    @app.get("/jobs/active")
    def jobs_active(s=Depends(session)):
        return JSONResponse({"running": active_jobs()})

    @app.post("/certs/job")
    async def job_start(request: Request):
        s, form = await post(request)
        action = str(form.get("action", "selected"))
        names = [str(x) for x in form.getlist("name")][:100]
        cmds = {"selected": (["certs", "renew", *names], "Renewing selected certificates"),
                "issue": (["certs", "issue"], "Requesting missing certificates"),
                "force": (["certs", "issue", "--force"], "Retrying failed certificates"),
                "renew": (["certs", "renew"], "Renewing certificates that are due")}
        if action not in cmds:
            return JSONResponse({"error": "unknown action"}, status_code=400)
        if action == "selected" and not names:
            return JSONResponse({"error": "Tick at least one certificate first."}, status_code=400)
        if running_job():
            return JSONResponse({"error": "Another certificate job is still running."}, status_code=409)
        cmd, title = cmds[action]
        j = {"id": secrets.token_urlsafe(8), "state": "running", "phase": "Starting", "started": time.time(), "ok": None,
             "log": [], "cmd": cmd, "title": title, "total": len(names) if action == "selected" else 0,
             "items": {n: {"state": "pending", "message": "", "since": None} for n in names} if action == "selected" else {}}
        with jobs_lock:
            for old in [k for k, v in jobs.items() if v["state"] != "running"][:-5]:
                jobs.pop(old, None)                      # keep only the last few finished jobs
            jobs[j["id"]] = j
        threading.Thread(target=run_job, args=(j, s["user"]), daemon=True).start()
        return JSONResponse({"id": j["id"]})

    @app.get("/certs/job/{jid}")
    def job_status(jid: str, s=Depends(session)):
        j = jobs.get(jid)
        if not j:
            raise HTTPException(404)
        return JSONResponse(job_view(j))

    # ---------------------------------------------------------------- certificates
    @app.get("/certs")
    def certs_page(request: Request, s=Depends(session)):
        hosts, _, errors, _ = state_load()
        settings, _ = st.load_settings(p)
        rows = [] if errors else cr.table(p, hosts, settings)
        rj = running_job()
        return page(request, "certs.html", s, rows=rows, acme=settings["acme"], errors=errors, job=rj["id"] if rj else "")

    @app.post("/certs")
    async def certs_action(request: Request):
        s, form = await post(request)
        action = form.get("action")
        args = {"issue": ["certs", "issue"], "force": ["certs", "issue", "--force"], "renew": ["certs", "renew"]}.get(action)
        if action == "selected":
            names = [str(x) for x in form.getlist("name")]
            if not names:
                return redirect("/certs", "Tick at least one certificate first.", "err")
            args = ["certs", "renew", *names]
        if not args:
            raise HTTPException(400)
        ok, out = await run_in_threadpool(cli, s, *args, timeout=1800)
        return result(request, s, "Certificates", ok, out, "/certs")

    # ---------------------------------------------------------------- history
    def colour(diff_text: str) -> list[tuple[str, str]]:
        out = []
        for line in diff_text.splitlines():
            cls = ("add" if line.startswith("+") and not line.startswith("+++") else
                   "del" if line.startswith("-") and not line.startswith("---") else
                   "hunk" if line.startswith("@@") else "")
            out.append((cls, line))
        return out

    @app.get("/history")
    def history(request: Request, s=Depends(session)):
        applied = ""
        try:
            applied = json.loads(p.applied.read_text()).get("commit", "")
        except (OSError, ValueError):
            pass
        return page(request, "history.html", s, rows=st.log(p, 60), applied=applied)

    @app.get("/history/{rev}")
    def history_rev(rev: str, request: Request, s=Depends(session)):
        if not all(c in "0123456789abcdef" for c in rev) or not 4 <= len(rev) <= 40:
            raise HTTPException(404)
        try:
            text = st.diff(p, rev)
        except st.StateError:
            raise HTTPException(404)
        return page(request, "diff.html", s, rev=rev, lines=colour(text))

    @app.post("/history/{rev}/rollback")
    async def rollback(rev: str, request: Request):
        s, form = await post(request)
        if not all(c in "0123456789abcdef" for c in rev) or not 4 <= len(rev) <= 40:
            raise HTTPException(404)
        try:
            new = await run_in_threadpool(st.restore, p, rev)
        except st.StateError as e:
            return redirect("/history", str(e), "err")
        errs = validation_errors()
        if errs:
            return redirect("/history", "Restored state does not validate: " + "; ".join(errs[:3]), "err")
        return redirect("/history", f"State restored to {rev[:8]}. Not live until you apply.")

    # ---------------------------------------------------------------- cluster
    @app.get("/cluster")
    def cluster_page(request: Request, s=Depends(session)):
        cs = cl_.cluster_settings(p)
        d: dict = {"vip": cs["vip"], "vrid": cs["vrid"], "me": None, "twin": None, "twin_error": None, "vip_owner": None}
        try:
            n = nodemod.load(p)
            d["me"] = cl_.local_view(p)
            d["me"]["acme_issuer"] = n.acme_issuer
            if n.has_peer:
                d["peer"] = n.peer_address
                try:
                    d["twin"] = pr_.peer_status(p, n)["cluster"]
                except (pr_.PeerError, ValueError, KeyError) as e:
                    d["twin_error"] = str(e)
            if cs["vip"]:
                d["vip_owner"] = cl_.probe_vip(cs["vip"])
            d["sync"] = pr_.read_status(p) if n.has_peer else None
        except nodemod.NodeError as e:
            d["twin_error"] = str(e)
        return page(request, "cluster.html", s, d=d)

    @app.post("/cluster")
    async def cluster_action(request: Request):
        s, form = await post(request)
        args = {"drain": ["drain"], "restore": ["restore"], "sync": ["sync"]}.get(form.get("action"))
        if not args:
            raise HTTPException(400)
        ok, out = await run_in_threadpool(cli, s, *args, timeout=180)
        return result(request, s, args[0].capitalize(), ok, out, "/cluster")

    # ---------------------------------------------------------------- settings (ACME)
    def plugin_installed(plugin: str) -> bool:
        import importlib.util
        try:
            return importlib.util.find_spec(f"certbot_dns_{plugin}") is not None
        except (ImportError, ValueError):
            return False

    def provider_rows(acme: dict) -> list[dict]:
        """One row per DNS provider. The old single 'dns' entry is shown as a provider named after its plugin."""
        provs = dict(acme.get("dns_providers") or {})
        default = acme.get("dns_default")
        legacy = acme.get("dns")
        if legacy:
            name = legacy["plugin"] if legacy["plugin"] not in provs else "default"
            provs = {name: legacy, **provs}
            default = default or name
        published = cr.creds_published(p)
        hosts = state_load()[0]
        rows = []
        for name, d in provs.items():
            used = [h["domain"] for h in hosts if h["enabled"] and h["tls"]["enabled"] and h["tls"]["cert"] == "auto"
                    and (h["tls"]["challenge"] == "dns" or h["domain"].startswith("*."))
                    and (h["tls"].get("dns_provider") == name or (not h["tls"].get("dns_provider") and name == default))]
            fp = published.get(d.get("credentials"))
            rows.append({"name": name, "plugin": d.get("plugin", ""), "credentials": d.get("credentials", ""),
                         "wait": d.get("propagation_seconds", 60), "default": name == default or len(provs) == 1,
                         "installed": plugin_installed(d.get("plugin", "")), "file": bool(fp),
                         "file_time": datetime.fromtimestamp(fp["mtime"]).strftime("%Y-%m-%d %H:%M") if fp else None,
                         "used": used})
        return rows

    def settings_page_ctx(acme=None, rows=None, security=None):
        settings, _ = st.load_settings(p)
        acme = acme or settings["acme"]
        return dict(acme=acme, cluster=settings["cluster"], security=security or settings["security"], providers=rows if rows is not None else provider_rows(settings["acme"]))

    @app.get("/settings")
    def settings_page(request: Request, s=Depends(session)):
        return page(request, "settings.html", s, **settings_page_ctx())

    @app.post("/settings")
    async def settings_save(request: Request):
        s, form = await post(request)
        f = p.state / "settings.yaml"
        raw = st._load_yaml(f)
        acme = dict(raw.get("acme") or {})
        email = str(form.get("email", "")).strip()
        acme["email"] = email or None
        acme["server"] = str(form.get("server", "production"))
        url = str(form.get("directory_url", "")).strip()
        if url:
            acme["directory_url"] = url
        else:
            acme.pop("directory_url", None)
        acme["auto"] = form.get("auto") == "on"
        names, plugins = form.getlist("p_name"), form.getlist("p_plugin")
        creds, waits = form.getlist("p_credentials"), form.getlist("p_wait")
        removed = set(form.getlist("p_remove"))
        default_idx = str(form.get("p_default", ""))
        provs, rows, default_name = {}, [], None
        errors = []
        for i in range(len(names)):
            name, plugin, cred = names[i].strip().lower(), plugins[i].strip().lower(), creds[i].strip()
            if not (name or plugin or cred) or str(i) in removed:
                continue
            name = name or plugin
            try:
                wait = int(waits[i].strip() or "60")
            except ValueError:
                wait = -1
            if name in provs:
                errors.append(f"two providers are named {name!r}")
            provs[name] = {"plugin": plugin, "credentials": cred, "propagation_seconds": wait}
            rows.append({"name": name, "plugin": plugin, "credentials": cred, "wait": waits[i], "default": str(i) == default_idx,
                         "installed": plugin_installed(plugin), "file": False, "file_time": None, "used": []})
            if str(i) == default_idx:
                default_name = name
        acme.pop("dns", None)
        if provs:
            acme["dns_providers"] = provs
            acme["dns_default"] = default_name or next(iter(provs))
        else:
            acme.pop("dns_providers", None)
            acme.pop("dns_default", None)
        raw["acme"] = acme
        sec = dict(raw.get("security") or {})
        if "rate" in form:                       # forms without the security card leave it alone
            sec.update(rate_limit=form.get("rate_limit") == "on", lan_exempt=form.get("lan_exempt") == "on")
            for k in ("rate", "burst", "connections"):
                try:
                    sec[k] = int(str(form.get(k, "")).strip())
                except ValueError:
                    errors.append(f"security: {k} must be a whole number")
        if sec:
            raw["security"] = sec
        errs = errors or await run_in_threadpool(write_validated, "settings.yaml", st.dump_yaml(raw),
                                                 "settings: acme (web)", s["user"])
        if errs:
            return page(request, "settings.html", s, status=400, errors=errs,
                        **settings_page_ctx({**st.load_settings(p)[0]["acme"], **{k: v for k, v in acme.items() if k not in ("dns_providers", "dns_default", "dns")}}, rows,
                                            {**st.SECURITY_DEFAULTS, **sec}))
        return redirect("/settings", "Saved. Settings sync to the twin automatically.")

    # ---------------------------------------------------------------- health
    def health_data(rng: str, only_errors: bool):
        st_ = tf.status(p)
        if not st_["last"] or time.time() - st_["last"] > 20:
            tf.collect(p)
            st_ = tf.status(p)
        hosts = st.load(p)[0]
        _, _, step = tf._since(rng)
        tot, rows = tf.totals(p, rng), tf.hosts_table(p, rng)
        ips, lim = tf.ips_table(p, rng), tf.limited(p, rng)
        ups = tf.probe_upstreams(p, hosts)
        sysi = sysinfo.snapshot()
        series = tf.series(p, rng)
        days = (time.time() - min((r["t"] for r in series if r["n"]), default=time.time())) / 86400
        import shutil as _sh
        sug = tf.suggestions(hosts, rows, ips, lim, ups, tot, bool(_sh.which("fail2ban-client")), days)
        return dict(rng=rng, only=only_errors, sysi=sysi, uptime=sysinfo.human_uptime(sysi["uptime"]), st=st_, tot=tot, rows=rows, ips=ips, ups=ups, sug=sug,
                    req=tf.chart(series, step, "requests"), byt=tf.chart(series, step, "bytes"), series=series, step=step,
                    recent=tf.recent(p, 100, only_errors), classes=tf.CLASSES, labels=tf.LABELS, hb=tf.human_bytes,
                    lim=sorted(lim, key=lambda x: -x["hits"])[:10], now=time.time())

    @app.get("/health")
    async def health_page(request: Request, s=Depends(session)):
        rng = request.query_params.get("range", "24h")
        rng = rng if rng in tf.RANGES else "24h"
        d = await run_in_threadpool(health_data, rng, request.query_params.get("only") == "errors")
        return page(request, "health.html", s, **d)

    # ---------------------------------------------------------------- security
    @app.get("/security")
    async def security_page(request: Request, s=Depends(session)):
        from . import security as sc
        checks = await run_in_threadpool(sc.audit, p)
        return page(request, "security.html", s, checks=checks, verdict=sc.verdict(checks))

    # ---------------------------------------------------------------- account
    @app.get("/account")
    def account(request: Request, s=Depends(session)):
        return page(request, "account.html", s, **totp_ctx(s))

    def totp_ctx(s, secret=None, errors=None):
        ser = URLSafeSerializer(auth.secret_key(p), salt="debrev-totp")
        enabled = s["totp"]
        sec = None if enabled else (secret or auth.new_totp_secret())
        node_name = nodemod.load(p).name
        return dict(totp_enabled=enabled, secret=sec, uri=auth.totp_uri(sec, s["user"], node_name) if sec else None,
                    token=ser.dumps(sec) if sec else None, errors=errors or [])

    @app.post("/account")
    async def account_post(request: Request):
        s, form = await post(request)
        action = form.get("action")
        users = auth.load_users(p)
        me = users.get(s["user"])
        if not me:
            raise HTTPException(403)
        # every change needs the current password
        try:
            auth._ph.verify(me["hash"], str(form.get("current", "")))
        except Exception:
            return page(request, "account.html", s, status=400, **totp_ctx(s, errors=["current password is wrong"]))
        try:
            if action == "password":
                new = str(form.get("new", ""))
                if new != str(form.get("new2", "")):
                    raise auth.AuthError("the two new passwords differ")
                await run_in_threadpool(auth.set_password, p, s["user"], new)
                user = auth.load_users(p)[s["user"]]
                r = redirect("/account", "Password changed. Other sessions were signed out.")
                r.set_cookie(COOKIE, auth.make_session(p, {"name": s["user"], **user}), httponly=True, samesite="strict",
                             secure=secure_cookie, max_age=auth.SESSION_SECONDS)
                return r
            if action == "totp_on":
                ser = URLSafeSerializer(auth.secret_key(p), salt="debrev-totp")
                try:
                    sec = ser.loads(str(form.get("token", "")))
                except BadSignature:
                    raise auth.AuthError("form expired; reload the page")
                if not auth.verify_totp(sec, str(form.get("code", "")).strip()):
                    raise auth.AuthError("that code is wrong; check the clock on your phone and try again")
                auth.set_totp(p, s["user"], sec)
                r = redirect("/account", "Two-factor login enabled.")
                r.set_cookie(COOKIE, auth.make_session(p, {"name": s["user"], **auth.load_users(p)[s["user"]]}),
                             httponly=True, samesite="strict", secure=secure_cookie, max_age=auth.SESSION_SECONDS)
                return r
            if action == "totp_off":
                auth.set_totp(p, s["user"], None)
                r = redirect("/account", "Two-factor login disabled.")
                r.set_cookie(COOKIE, auth.make_session(p, {"name": s["user"], **auth.load_users(p)[s["user"]]}),
                             httponly=True, samesite="strict", secure=secure_cookie, max_age=auth.SESSION_SECONDS)
                return r
        except auth.AuthError as e:
            return page(request, "account.html", s, status=400, **totp_ctx(s, errors=[str(e)]))
        raise HTTPException(400)

    return app


def serve(p: Paths) -> None:
    import uvicorn
    cfg = load_web_config(p)
    if not (Path(cfg["cert"]).exists() and Path(cfg["key"]).exists()):
        sys.exit(f"missing TLS certificate {cfg['cert']} / {cfg['key']} (install.sh creates a self-signed one)")
    uvicorn.run(create_app(p), host=cfg["listen"], port=int(cfg["port"]), ssl_certfile=cfg["cert"],
                ssl_keyfile=cfg["key"], log_level="warning", server_header=False, proxy_headers=False)
