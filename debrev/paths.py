"""Filesystem layout. Every path is overridable so tests and dev runs
can work under a scratch root (DEBREV_ROOT) without touching /etc."""
from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent


@dataclass
class Paths:
    etc: Path = Path("/etc/debrev")
    lib: Path = Path("/var/lib/debrev")
    cache: Path = Path("/var/cache/debrev")
    letsencrypt: Path = Path("/etc/letsencrypt")
    nginx_conf: Path = Path("/etc/nginx/nginx.conf")
    nginx_cmd: tuple = ("nginx",)
    certbot_cmd: tuple = ("certbot",)
    keepalived_conf: Path = Path("/etc/keepalived/keepalived.conf")
    keepalived_cmd: tuple = ("systemctl", "enable", "--now", "keepalived")
    keepalived_reload: tuple = ("systemctl", "reload", "keepalived")
    apply_cmd: tuple = ("sudo", "-n", str(APP_DIR / "bin" / "debrev-apply"))
    peer_ssh: tuple | None = None   # test hook: replaces the ssh command prefix
    openssl_cmd: tuple = ("openssl",)
    reload_cmd: tuple = ("systemctl", "reload-or-restart", "nginx")
    health_check: bool = True
    health_port: int = 80
    keep_releases: int = 10
    access_log: Path = Path("/var/log/nginx/debrev.log")

    @property
    def node_file(self) -> Path:
        return self.etc / "node.toml"

    @property
    def ssh_dir(self) -> Path:
        return self.lib / ".ssh"

    @property
    def ssh_key(self) -> Path:
        return self.ssh_dir / "id_ed25519"

    @property
    def certs_dir(self) -> Path:
        """Certificates nginx actually serves (root-only). Filled from certbot or from the peer."""
        return self.lib / "certs"

    @property
    def drain_file(self) -> Path:
        return self.lib / "drain-weight"

    @property
    def vrrp_state(self) -> Path:
        return self.lib / "vrrp-state.json"

    @property
    def sync_status(self) -> Path:
        return self.lib / "sync-status.json"

    @property
    def sync_lock(self) -> Path:
        return self.lib / "sync.lock"

    @property
    def state(self) -> Path:
        return self.lib / "state"

    @property
    def releases(self) -> Path:
        return self.lib / "releases"

    @property
    def live(self) -> Path:
        return self.lib / "live"

    @property
    def cert_status(self) -> Path:
        return self.lib / "cert-status.json"

    @property
    def acme(self) -> Path:
        return self.lib / "acme"

    @property
    def lock(self) -> Path:
        return self.lib / "apply.lock"

    @property
    def traffic_db(self) -> Path:
        return self.lib / "traffic.db"

    @property
    def applied(self) -> Path:
        return self.lib / "applied.json"

    @property
    def templates(self) -> Path:
        return APP_DIR / "templates"

    @classmethod
    def from_env(cls) -> "Paths":
        p = cls()
        root = os.environ.get("DEBREV_ROOT")
        if root:
            r = Path(root)
            p.etc, p.lib = r / "etc/debrev", r / "var/lib/debrev"
            p.cache, p.letsencrypt = r / "var/cache/debrev", r / "etc/letsencrypt"
            p.nginx_conf = r / "etc/nginx/nginx.conf"
            p.access_log = r / "var/log/nginx/debrev.log"
            p.reload_cmd = ("true",)
            p.keepalived_conf = r / "etc/keepalived/keepalived.conf"
            p.keepalived_cmd = p.keepalived_reload = ("true",)
            p.health_check = False
        if os.environ.get("DEBREV_NGINX"):
            p.nginx_cmd = tuple(shlex.split(os.environ["DEBREV_NGINX"]))
        if os.environ.get("DEBREV_PEER_SSH"):
            p.peer_ssh = tuple(shlex.split(os.environ["DEBREV_PEER_SSH"]))
        if os.environ.get("DEBREV_APPLY"):
            p.apply_cmd = tuple(shlex.split(os.environ["DEBREV_APPLY"]))
        if os.environ.get("DEBREV_CERTBOT"):
            p.certbot_cmd = tuple(shlex.split(os.environ["DEBREV_CERTBOT"]))
        if os.environ.get("DEBREV_RELOAD"):
            p.reload_cmd = tuple(shlex.split(os.environ["DEBREV_RELOAD"]))
        return p
