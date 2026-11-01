"""Settings of THIS server only (/etc/debrev/node.toml). Never synced."""
from __future__ import annotations

import ipaddress
import re
import socket
import tomllib
from dataclasses import dataclass

from .paths import Paths


class NodeError(Exception):
    pass


@dataclass
class Node:
    name: str
    acme_issuer: bool = True
    peer_address: str | None = None
    priority: int = 100
    interface: str | None = None

    @property
    def has_peer(self) -> bool:
        return bool(self.peer_address)


def validate(name: str, issuer, peer, priority=100, interface=None) -> None:
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", name or ""):
        raise NodeError(f"invalid node name {name!r}")
    if not isinstance(issuer, bool):
        raise NodeError("acme_issuer must be true or false")
    if not isinstance(priority, int) or isinstance(priority, bool) or not 1 <= priority <= 254:
        raise NodeError("priority must be 1-254")
    if interface is not None and not re.match(r"^[A-Za-z0-9_.:-]{1,15}$", str(interface)):
        raise NodeError(f"invalid interface name {interface!r}")
    if peer:
        try:
            ipaddress.ip_address(peer)
        except ValueError:
            raise NodeError(f"peer address must be an IP address, got {peer!r}")


def load(p: Paths) -> Node:
    try:
        raw = tomllib.loads(p.node_file.read_text())
    except FileNotFoundError:
        return Node(name=socket.gethostname())
    except tomllib.TOMLDecodeError as e:
        raise NodeError(f"{p.node_file}: {e}")
    node = raw.get("node", {})
    peer = (raw.get("peer") or {}).get("address") or None
    n = Node(name=node.get("name", socket.gethostname()), acme_issuer=node.get("acme_issuer", True),
             peer_address=peer, priority=node.get("priority", 100), interface=node.get("interface"))
    validate(n.name, n.acme_issuer, n.peer_address, n.priority, n.interface)
    return n


def save(p: Paths, n: Node) -> None:
    validate(n.name, n.acme_issuer, n.peer_address, n.priority, n.interface)
    lines = ["# Settings for THIS server only. Never synced to the twin.", "[node]",
             f'name = "{n.name}"', f"acme_issuer = {'true' if n.acme_issuer else 'false'}", f"priority = {n.priority}"]
    if n.interface:
        lines.append(f'interface = "{n.interface}"')
    if n.peer_address:
        lines += ["", "[peer]", f'address = "{n.peer_address}"']
    text = "\n".join(lines) + "\n"
    p.node_file.parent.mkdir(parents=True, exist_ok=True)
    # write in place: keeps the file's owner/group (the debrev user may edit it)
    with open(p.node_file, "w") as f:
        f.write(text)
