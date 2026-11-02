# debrev: Design

## Goals
1. Let's Encrypt certificates with auto-renewal.
2. Twin-server config sync (set peer IP in config) so one node can be upgraded while the other carries traffic.
3. Versioned configs across both servers.
4. User-friendly web interface.
5. Easy updates: all tools from stock Debian apt (`apt update && apt upgrade`). The project itself is not a .deb.
6. Per-host custom config: websockets, caching, raw nginx snippets.

## Engine: nginx + certbot
Chosen over Caddy: nginx text config diffs well in git, the ACME fallback to the peer is simple, and Caddy's cert storage is awkward to share. Debian's caddy also lacks DNS modules and layer4.

## Debian packages
```
apt install nginx libnginx-mod-stream certbot python3-certbot-nginx \
            python3-certbot-dns-cloudflare keepalived git rsync \
            python3-fastapi python3-uvicorn python3-jinja2 python3-yaml python3-argon2
```
No pip, no venv. Keep the list in `requirements.apt`.

## Directory layout
| Path | Purpose | Synced? |
|---|---|---|
| `/opt/debrev` | app code (git clone) | no |
| `/etc/debrev/node.toml` | this node's IP, keepalived priority, peer address | no |
| `/var/lib/debrev/state` | git working repo: hosts/, access_lists/, settings.yaml (YAML, one file per host) | yes (git) |
| `/var/lib/debrev/acme` | ACME webroot | no |
| `/var/lib/debrev/releases`, `live` | rendered nginx config releases; `live` symlink is swapped atomically | no |
| `/etc/letsencrypt` | certs and keys | rsync, not git |

## Code map (`debrev/`)
| Module | Purpose |
|---|---|
| `schema.py`, `state.py` | host/settings schema and validation; the git state repository (commit, restore, load) |
| `render.py`, `apply.py` | state to nginx config; the apply pipeline with rollback |
| `certs.py`, `dns.py` | Let's Encrypt via certbot (HTTP-01, DNS-01), shared and uploaded certificates; upstream name cache |
| `peer.py`, `cluster.py`, `node.py` | twin sync over SSH, keepalived/VIP and drain, node-local settings |
| `portable.py` | configuration export and import (one YAML file) |
| `traffic.py`, `sysinfo.py`, `security.py`, `fail2ban.py` | Health page statistics, server load, exposure checklist, banned addresses |
| `web.py`, `auth.py`, `cli.py` | web interface (FastAPI), logins and 2FA, command line |

## Apply pipeline
render to staging → `nginx -t` → atomic swap → reload → health check → automatic rollback on failure. Every UI save is a git commit.

## Certificates with two nodes
Option A: only the VIP holder renews; a deploy hook rsyncs to the peer, which validates and reloads.
Option B: both renew; nginx forwards unmatched challenges to the peer:
```nginx
location /.well-known/acme-challenge/ {
    root /var/lib/debrev/acme;
    try_files $uri @peer;
}
location @peer { proxy_pass http://PEER_IP; }
```
DNS-01 for wildcards. Private keys never go into git.

## Sync
Git push over SSH or mTLS API, fast-forward only. Diverged history shows a "resolve" banner. One writer at a time. A format-version field lets nodes run different app versions during upgrades.

## Failover
keepalived VRRP floating IP (same L2). Cloud: provider floating-IP API in a notify script. Fallback: low-TTL DNS. The Drain wizard lowers priority, confirms the peer is serving, then marks the node safe to upgrade.

## Adding the second server (join script)
A single idempotent `install.sh` has two modes: `--init` (first node) and `--join <peer-ip>` (twin). Join uses a one-time token generated on the existing node to authorize the new node's SSH key/mTLS cert, then clones the state repo, copies certs, writes the node-local `node.toml` (BACKUP keepalived priority), applies the config, and runs the self-check. It must work on a clean Debian install with only apt dependencies, and `--dry-run` prints the plan first.

## How the twin sync works (as built)
See ROADMAP.md "Phase 3 notes". Short version: SSH key locked to a forced command; receiver fetches and fast-forwards; no silent merges; only the `acme_issuer` node asks Let's Encrypt, certificates travel to the peer and are validated there; nginx forwards unknown ACME tokens to the twin; `/etc/debrev/node.toml` is per node and never synced.

## Failover (as built)
See ROADMAP.md "Phase 4 notes": unicast VRRP, health via nginx, drain as a keepalived track file, notify script follows the VIP with the certificate-issuer role.

## Upgrade routine
1. Drain node A. 2. `apt update && apt full-upgrade` (+ `git pull` for the app), reboot if needed. 3. Self-check. 4. Restore. 5. Repeat on B.
Stagger unattended-upgrades between nodes so they never restart together.

## Per-host customization
Three layers:
1. **Toggles** stored as YAML keys: websockets, cache (enabled, ttl, static_only, bypass_cookies), max_body, timeouts, http2, headers, access_list, custom_locations.
2. **Recipes**: ready-made settings for common apps live in `docs/RECIPES.md`; every host carries its own settings (presets were removed: shared bundles were confusing).
3. **Custom snippet**: textarea inserted inside `server {}`. Validated with `nginx -t` on save, blocklist for dangerous directives (`include`, `load_module`, scripting modules, arbitrary `access_log`/`root`/`alias`), admin-only. The blocklist is a mistake guard, not a security boundary.

Details:
- WebSockets: `proxy_http_version 1.1`, `Upgrade` and `Connection $connection_upgrade`, with one global `map $http_upgrade $connection_upgrade`.
- Caching: global `proxy_cache_path` zone with size limit; per host `proxy_cache`, `proxy_cache_valid`, `proxy_cache_bypass`, `proxy_no_cache`; `X-Cache-Status` header; purge button clears that host's cache dir. Cache is per node and not synced.

## Web UI
FastAPI + Jinja2, no Node toolchain, strict CSP (no inline scripts or styles). Bind to LAN/VPN on a separate port (8443). Argon2 password hashes, optional TOTP, audit trail via git. App runs as unprivileged `debrev` user with a sudoers entry for the single apply script.

## Effort
MVP of all goals ≈ 4–5 weeks; polished v1 ≈ 11–13 weeks. See ROADMAP.md.
