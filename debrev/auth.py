"""Web UI accounts: argon2 password hashes, optional TOTP, signed sessions,
login throttling. Per-node data in <lib>/web/ (never synced, never in git)."""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .paths import Paths

USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
MIN_PASSWORD = 10
SESSION_SECONDS = 12 * 3600
_ph = PasswordHasher()
_DUMMY = _ph.hash("debrev-dummy-password")
_lock = threading.Lock()


class AuthError(Exception):
    pass


def _dir(p: Paths) -> Path:
    d = p.lib / "web"
    if not d.exists():
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)
    return d


def _write_private(path: Path, text: str) -> None:
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    tmp.replace(path)
    _match_owner(path)


def _match_owner(path: Path) -> None:
    """When root creates files, hand them to the owner of the data dir (the debrev service user)."""
    if os.geteuid() == 0:
        ref = path.parent.parent.stat()
        os.chown(path, ref.st_uid, ref.st_gid)
        os.chown(path.parent, ref.st_uid, ref.st_gid)


def load_users(p: Paths) -> dict:
    try:
        return json.loads((_dir(p) / "users.json").read_text())
    except (OSError, ValueError):
        return {}


def _save_users(p: Paths, users: dict) -> None:
    _write_private(_dir(p) / "users.json", json.dumps(users, indent=1, sort_keys=True) + "\n")


def secret_key(p: Paths) -> str:
    f = _dir(p) / "secret.key"
    if not f.exists():
        _write_private(f, secrets.token_urlsafe(48))
    return f.read_text().strip()


def check_password_policy(pw: str) -> None:
    if len(pw) < MIN_PASSWORD:
        raise AuthError(f"password must be at least {MIN_PASSWORD} characters")
    if len(pw) > 256:
        raise AuthError("password is too long")


def add_user(p: Paths, name: str, password: str) -> None:
    name = name.lower()
    if not USER_RE.match(name):
        raise AuthError("user names: lower-case letters, digits, . _ - (max 32)")
    check_password_policy(password)
    with _lock:
        users = load_users(p)
        if name in users:
            raise AuthError(f"user {name} already exists")
        users[name] = {"hash": _ph.hash(password), "ver": 1, "totp": None}
        _save_users(p, users)


def set_password(p: Paths, name: str, password: str) -> None:
    check_password_policy(password)
    with _lock:
        users = load_users(p)
        if name not in users:
            raise AuthError(f"no such user: {name}")
        users[name]["hash"] = _ph.hash(password)
        users[name]["ver"] += 1      # invalidates every existing session
        _save_users(p, users)


def remove_user(p: Paths, name: str) -> None:
    with _lock:
        users = load_users(p)
        if name not in users:
            raise AuthError(f"no such user: {name}")
        del users[name]
        _save_users(p, users)


def set_totp(p: Paths, name: str, secret: str | None) -> None:
    with _lock:
        users = load_users(p)
        if name not in users:
            raise AuthError(f"no such user: {name}")
        users[name]["totp"] = secret
        users[name]["ver"] += 1
        _save_users(p, users)


def verify_totp(secret: str, code: str) -> bool:
    import pyotp
    return bool(re.fullmatch(r"\d{6}", code or "")) and pyotp.TOTP(secret).verify(code, valid_window=1)


def new_totp_secret() -> str:
    import pyotp
    return pyotp.random_base32()


def totp_uri(secret: str, user: str, node: str) -> str:
    import pyotp
    return pyotp.TOTP(secret).provisioning_uri(name=f"{user}@{node}", issuer_name="debrev")


# ---- throttling (in memory; restarting the service clears it) -------------

_fails: dict[str, list[float]] = {}
WINDOW, MAX_FAILS, LOCK_SECONDS = 600, 5, 300


def _key_list(*keys):
    return [k for k in keys if k]


def locked(ip: str, user: str | None = None) -> int:
    """Seconds still locked out (0 = not locked)."""
    now = time.time()
    worst = 0
    with _lock:
        for k in _key_list(f"ip:{ip}", f"user:{user}" if user else None):
            recent = [t for t in _fails.get(k, []) if now - t < WINDOW]
            _fails[k] = recent
            if len(recent) >= MAX_FAILS:
                worst = max(worst, int(recent[-1] + LOCK_SECONDS - now))
    return max(worst, 0)


def record_fail(ip: str, user: str | None) -> None:
    now = time.time()
    with _lock:
        for k in _key_list(f"ip:{ip}", f"user:{user}" if user else None):
            _fails.setdefault(k, []).append(now)
        if len(_fails) > 5000:       # bound memory under a spray attack
            for k in [k for k, v in _fails.items() if not v or now - v[-1] > WINDOW]:
                _fails.pop(k, None)


def record_ok(ip: str, user: str) -> None:
    with _lock:
        _fails.pop(f"ip:{ip}", None)
        _fails.pop(f"user:{user}", None)


def authenticate(p: Paths, name: str, password: str, code: str, ip: str) -> dict:
    """Returns the user record or raises AuthError. Same message for every failure."""
    name = (name or "").lower()
    wait = locked(ip, name)
    if wait:
        raise AuthError(f"too many failed attempts; try again in {wait // 60 + 1} min")
    user = load_users(p).get(name)
    ok = False
    try:
        _ph.verify(user["hash"] if user else _DUMMY, password or "")
        ok = user is not None
    except (VerificationError, InvalidHash):
        ok = False
    if ok and user.get("totp"):
        ok = verify_totp(user["totp"], (code or "").strip())
    if not ok:
        record_fail(ip, name)
        raise AuthError("wrong user name, password or code")
    record_ok(ip, name)
    return {"name": name, **user}


# ---- sessions ----------------------------------------------------------------

def _ser(p: Paths) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key(p), salt="debrev-session")


def make_session(p: Paths, user: dict) -> str:
    return _ser(p).dumps({"u": user["name"], "v": user["ver"], "c": secrets.token_urlsafe(24)})


def read_session(p: Paths, token: str | None) -> dict | None:
    if not token:
        return None
    try:
        data = _ser(p).loads(token, max_age=SESSION_SECONDS)
    except BadSignature:
        return None
    u = load_users(p).get(data.get("u"))
    if not u or u["ver"] != data.get("v"):
        return None
    return {"user": data["u"], "csrf": data["c"], "totp": bool(u.get("totp"))}
