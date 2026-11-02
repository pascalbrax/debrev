"""Talking to the twin server.

Transport is plain SSH using a dedicated key. On the receiving side that key
is locked (authorized_keys) to the forced command `bin/debrev-sync-serve`,
which understands only the handful of requests below:

  git-upload-pack   serve our state repository read-only (the peer fetches)
  notify            "please run a sync now" (detached, returns at once)
  notify-force      same, but adopt our state (peer takes our side of a conflict)
  status            small JSON: head commit, state format, issuer flag
  cert-list         non-secret list of certificates we hold (name -> expiry)
  cert-import       replace/accept certificates (root helper validates them)
  drain, restore    take this server out of / back into service (the twin asks
                    for it: "Take over traffic" / "Hand back" in the web UI)

State always moves by the *receiver* fetching and fast-forwarding, never by
pushing into a working tree. Diverged histories are never merged silently.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import STATE_FORMAT, __version__, node as nodemod, state as st
from .paths import APP_DIR, Paths

KEY_RE = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/=]{40,100}( [^\n\"]{0,80})?$")


class PeerError(Exception):
    pass


@dataclass
class SyncResult:
    ok: bool
    state: str       # in-sync | updated | notified | unreachable | diverged | unrelated | error | no-peer
    message: str


# ---------------------------------------------------------------- keys / auth

def ensure_key(p: Paths) -> str:
    """Create this node's sync key if missing; return the public key line."""
    p.ssh_dir.mkdir(parents=True, exist_ok=True)
    p.ssh_dir.chmod(0o700)
    if not p.ssh_key.exists():
        r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                            f"debrev-sync@{nodemod.load(p).name}", "-f", str(p.ssh_key)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise PeerError(f"ssh-keygen failed: {r.stderr.strip()}")
    return (p.ssh_key.with_suffix(".pub")).read_text().strip()


def authorize(p: Paths, pubkey: str, from_ip: str | None = None) -> None:
    """Allow `pubkey` (the twin's key) to run ONLY the sync forced command here."""
    pubkey = pubkey.strip()
    if not KEY_RE.match(pubkey):
        raise PeerError("not a valid ssh-ed25519 public key line")
    p.ssh_dir.mkdir(parents=True, exist_ok=True)
    p.ssh_dir.chmod(0o700)
    opts = f'command="{APP_DIR}/bin/debrev-sync-serve",restrict'
    if from_ip:
        opts = f'from="{from_ip}",' + opts
    line = f"{opts} {pubkey}"
    ak = p.ssh_dir / "authorized_keys"
    keep = []
    if ak.exists():
        keyblob = pubkey.split()[1]
        keep = [l for l in ak.read_text().splitlines() if keyblob not in l]
    ak.write_text("\n".join(keep + [line]) + "\n")
    ak.chmod(0o600)


# ------------------------------------------------------------------ transport

def _ssh_opts(p: Paths) -> list[str]:
    return ["-i", str(p.ssh_key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={p.ssh_dir / 'known_hosts'}",
            "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3"]


def remote(p: Paths, n: nodemod.Node, command: str, stdin: bytes | None = None, timeout: int = 60):
    """Run one whitelisted request on the peer. Returns CompletedProcess."""
    if not n.has_peer:
        raise PeerError("no peer configured (debrev peer set <ip>)")
    prefix = list(p.peer_ssh) if p.peer_ssh else ["ssh", *_ssh_opts(p), f"debrev@{n.peer_address}"]
    try:
        return subprocess.run([*prefix, command], input=stdin, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise PeerError(f"peer did not answer within {timeout}s")


def _git_env(p: Paths) -> dict:
    env = dict(os.environ, HOME=str(p.lib), GIT_TERMINAL_PROMPT="0")
    env["GIT_SSH_COMMAND"] = " ".join(shlex.quote(x) for x in ["ssh", *_ssh_opts(p)])
    return env


def _git(p: Paths, *args: str, check=True, timeout=60) -> str:
    r = subprocess.run(["git", "-c", f"safe.directory={p.state}", "-C", str(p.state), *args],
                       capture_output=True, text=True, env=_git_env(p), timeout=timeout)
    if check and r.returncode != 0:
        raise PeerError(f"git {args[0]} failed: {(r.stderr or r.stdout).strip()[-300:]}")
    return r.stdout.strip()


def peer_url(p: Paths, n: nodemod.Node) -> str:
    return os.environ.get("DEBREV_PEER_GIT_URL") or f"ssh://debrev@{n.peer_address}/state"


def peer_status(p: Paths, n: nodemod.Node, timeout: int = 15) -> dict:
    r = remote(p, n, "status", timeout=timeout)
    if r.returncode != 0:
        raise PeerError((r.stderr or b"").decode(errors="replace").strip()[-200:] or f"ssh exit {r.returncode}")
    return json.loads(r.stdout)


def ask_twin(p: Paths, n: nodemod.Node, what: str, timeout: int = 120) -> str:
    """Ask the twin to 'drain' or 'restore' itself. Returns its output; raises PeerError on refusal."""
    if what not in ("drain", "restore"):
        raise ValueError(what)
    r = remote(p, n, what, timeout=timeout)
    text = ((r.stdout or b"").decode(errors="replace") + (r.stderr or b"").decode(errors="replace")).strip()
    if r.returncode != 0:
        raise PeerError(text[-300:] or f"ssh exit {r.returncode}")
    return text


def notify(p: Paths, n: nodemod.Node, force: bool = False) -> bool:
    try:
        r = remote(p, n, "notify-force" if force else "notify", timeout=15)
        return r.returncode == 0
    except PeerError:
        return False


# ------------------------------------------------------------------- the sync

def _write_status(p: Paths, **kw) -> None:
    cur = {}
    try:
        cur = json.loads(p.sync_status.read_text())
    except (OSError, ValueError):
        pass
    cur.update(kw, updated=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    p.sync_status.write_text(json.dumps(cur, indent=1, sort_keys=True) + "\n")


def read_status(p: Paths) -> dict:
    try:
        return json.loads(p.sync_status.read_text())
    except (OSError, ValueError):
        return {}


def relation(p: Paths, local: str, theirs: str) -> str:
    if local == theirs:
        return "equal"
    r = subprocess.run(["git", "-c", f"safe.directory={p.state}", "-C", str(p.state), "merge-base", local, theirs],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return "unrelated"
    base = r.stdout.strip()
    if base == local:
        return "behind"          # peer is ahead of us -> we fast-forward
    if base == theirs:
        return "ahead"           # we are ahead -> peer should pull
    return "diverged"


def _apply_locally(p: Paths) -> tuple[bool, str]:
    r = subprocess.run(list(p.apply_cmd), capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def _backup(p: Paths, why: str) -> str:
    name = "backup/" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + why
    _git(p, "branch", name, "HEAD")
    return name


def sync(p: Paths, mode: str | None = None, retry: bool = False) -> SyncResult:
    """Reconcile state with the peer. mode: None | 'theirs' (adopt peer's state, keeping a backup branch)."""
    n = nodemod.load(p)
    if not n.has_peer:
        return SyncResult(True, "no-peer", "no peer configured")
    p.lib.mkdir(parents=True, exist_ok=True)
    with open(p.sync_lock, "w") as lk:
        try:
            fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return SyncResult(True, "busy", "another sync is running")
        return _sync_locked(p, n, mode, retry)


def _sync_locked(p: Paths, n: nodemod.Node, mode, retry) -> SyncResult:
    try:
        if st.is_dirty(p):
            _write_status(p, state="error", message="uncommitted local changes; commit or discard them")
            return SyncResult(False, "error", "state has uncommitted changes; commit them first")
        _git(p, "fetch", "-q", peer_url(p, n), "+refs/heads/main:refs/peer/main", timeout=60)
    except (PeerError, subprocess.TimeoutExpired) as e:
        msg = str(e)
        _write_status(p, state="unreachable", message=msg)
        return SyncResult(False, "unreachable", f"cannot reach peer {n.peer_address}: {msg}")
    local, theirs = st.head(p), _git(p, "rev-parse", "refs/peer/main")
    rel = relation(p, local, theirs)
    base = dict(local=local[:8], peer=theirs[:8])

    if rel == "equal":
        _write_status(p, state="in-sync", message="", failed_sha=None, **base)
        return SyncResult(True, "in-sync", f"in sync at {local[:8]}")
    if rel == "ahead":
        ok = notify(p, n)
        _write_status(p, state="ahead", message="" if ok else "peer not notified (will pull on its next run)", **base)
        return SyncResult(True, "notified", f"we are ahead ({local[:8]} > {theirs[:8]}); peer {'notified' if ok else 'will catch up on its own'}")
    if rel in ("diverged", "unrelated"):
        if mode != "theirs":
            msg = (f"state diverged: local {local[:8]}, peer {theirs[:8]}" if rel == "diverged"
                   else "peer has an unrelated history (different first commit)")
            _write_status(p, state=rel, message=msg + "; resolve with 'debrev sync --take-theirs' here or 'debrev sync --take-mine'", **base)
            return SyncResult(False, rel, msg)
        backup = _backup(p, "before-take-theirs")
        return _fast_forward(p, local, theirs, base, hard=True, note=f" (previous state kept as branch {backup})")

    # behind: take the peer's newer state
    st_prev = read_status(p)
    if not retry and st_prev.get("failed_sha") == theirs:
        return SyncResult(False, "error", f"peer state {theirs[:8]} failed to apply earlier: {st_prev.get('message', '')[:200]} (use --retry)")
    return _fast_forward(p, local, theirs, base)


def _fast_forward(p: Paths, local: str, theirs: str, base: dict, hard=False, note="") -> SyncResult:
    try:
        if hard:
            _git(p, "reset", "-q", "--hard", theirs)
        else:
            _git(p, "merge", "-q", "--ff-only", theirs)
    except PeerError as e:
        _write_status(p, state="error", message=str(e), **base)
        return SyncResult(False, "error", str(e))
    ok, out = _apply_locally(p)
    if not ok:
        _git(p, "reset", "-q", "--hard", local)
        _write_status(p, state="error", failed_sha=theirs, message=f"peer config does not apply here: {out[-400:]}", **base)
        return SyncResult(False, "error", f"peer's config {theirs[:8]} does not apply on this node; kept {local[:8]}.\n{out[-400:]}")
    _write_status(p, state="in-sync", message="", failed_sha=None, local=theirs[:8], peer=theirs[:8])
    return SyncResult(True, "updated", f"updated {local[:8]} -> {theirs[:8]} and applied{note}")


# ------------------------------------------------------------- server side

def serve(p: Paths, original: str, stdin=None) -> int:
    """Handle one request from the peer (called by bin/debrev-sync-serve)."""
    try:
        argv = shlex.split(original)
    except ValueError:
        argv = []
    if not argv:
        print("debrev: interactive logins are not allowed", file=sys.stderr)
        return 2
    cmd = argv[0]
    out = sys.stdout
    if cmd in ("git-upload-pack", "git-receive-pack") or argv[:2] == ["git", "upload-pack"]:
        if cmd == "git-receive-pack":
            print("debrev: pushing is not allowed; the receiver fetches", file=sys.stderr)
            return 2
        os.execvp("git", ["git", "upload-pack", "--strict", str(p.state / ".git")])
    if cmd == "status" and len(argv) == 1:
        from . import cluster
        n = nodemod.load(p)
        json.dump({"name": n.name, "head": st.head(p), "format": STATE_FORMAT, "version": __version__,
                   "acme_issuer": n.acme_issuer, "sync": read_status(p).get("state"),
                   "cluster": cluster.local_view(p)}, out)
        out.write("\n")
        return 0
    if cmd in ("notify", "notify-force") and len(argv) == 1:
        args = [str(APP_DIR / "bin" / "debrev"), "sync", "--quiet"] + (["--take-theirs", "--yes"] if cmd == "notify-force" else [])
        subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True, env=dict(os.environ, HOME=str(p.lib)))
        print("accepted")
        return 0
    if cmd == "cert-list" and len(argv) == 1:
        try:
            data = json.loads((p.lib / "certs.json").read_text())
        except (OSError, ValueError):
            data = {}
        json.dump({k: (v if k == "_credentials" else
                       {"expires": v.get("expires"), "sans": v.get("sans"), "fp": v.get("fp"), "installed": v.get("installed")}) for k, v in data.items()}, out)
        out.write("\n")
        return 0
    if cmd == "cert-import" and len(argv) == 1:
        payload = (stdin if stdin is not None else sys.stdin.buffer).read()
        if len(payload) > 20_000_000:
            print("payload too large", file=sys.stderr)
            return 2
        r = subprocess.run([*p.apply_cmd, "--cert-import"], input=payload, capture_output=True)
        sys.stdout.buffer.write(r.stdout)
        sys.stderr.buffer.write(r.stderr)
        return r.returncode
    if cmd in ("drain", "restore") and len(argv) == 1:
        # Run the ordinary CLI command; drain still checks that *its* twin (the caller) is healthy.
        r = subprocess.run([str(APP_DIR / "bin" / "debrev"), cmd], capture_output=True, text=True,
                           env=dict(os.environ, HOME=str(p.lib)), timeout=120)
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        return r.returncode
    print(f"debrev: request not allowed: {cmd}", file=sys.stderr)
    return 2
