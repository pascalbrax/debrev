# debrev: Roadmap

Name: **debrev** (reverse proxy manager for Debian). No Docker. Every runtime dependency comes from stock Debian apt. The app itself is installed via git clone + `install.sh`, not as a .deb.

Estimates are for one developer. MVP ≈ 4–5 weeks, polished v1 ≈ 11–13 weeks.

## Phase 1: Core engine, CLI only (~1.5 wk): DONE 2026-11-01
- Repo layout: `/opt/debrev` (code), `/etc/debrev` (node-local config), `/var/lib/debrev` (synced state git repo).
- Host schema (YAML, one file per host) incl. toggles: websockets, cache, max_body, timeouts, headers, access_list, custom_locations, custom snippet.
- Jinja2 renderer to nginx config.
- Safe apply script: render to staging → `nginx -t` → atomic swap → reload → health check → auto rollback.
- Each change = a git commit.
- Unprivileged `debrev` user + sudoers entry for the apply script only.

## Phase 2: Let's Encrypt (~1 wk): DONE 2026-11-01 (peer ACME fallback moves to phase 3)
- certbot integration (HTTP-01 webroot, DNS-01 via python3-certbot-dns-* for wildcards).
- Auto-renew via certbot's systemd timer; deploy hook reloads nginx.
- ACME challenge fallback to peer (`try_files $uri @peer`) so either node can renew.
- Cert status (expiry, last renewal, issuing node) exposed to CLI/API.

## Phase 3: Twin-node sync (~2 wk): DONE 2026-11-01
- Peer IP in `/etc/debrev/node.toml`; node-specific settings never synced.
- Git push over SSH (or mTLS API); fast-forward only; diverged history raises a "resolve" state.
- One writer at a time (VIP holder or lock).
- Cert sync: deploy hook rsyncs `/etc/letsencrypt` to the peer, which validates and reloads. Private keys stay out of git.
- Sync-format version number so nodes on different app versions coexist.
- Cache directories are per node, not synced.

## Phase 4: Failover and drain (~1 wk): DONE 2026-11-01
- keepalived/VRRP floating IP (same L2 network). Cloud hosts: floating-IP API from a notify script. Fallback: low-TTL DNS.
- Health-check script triggers automatic failover.
- Drain/Restore workflow: lower priority → confirm peer is serving → mark node safe to upgrade → restore.
- Post-upgrade self-check: `nginx -t`, certbot works, peer reachable, config versions match.

## Phase 5: Web UI (~3–4 wk): DONE 2026-11-01 (see "Phase 5 notes")
- FastAPI + Jinja2 + htmx; no Node toolchain.
- Pages: hosts (with Details / SSL / Advanced / Custom / Preview tabs), redirects, certificates, access lists, history/diff/rollback, cluster status, drain wizard, upgradable-packages view.
- Auth: argon2 password hashes, sessions, TOTP later. Bind to LAN/VPN on a separate port (e.g. 8443). Audit log via git.
- (Removed later, see RECIPES.md) Presets (named bundles: "WebSocket app", "Static site with caching", "Large uploads", …).
- Custom snippet editor with live `nginx -t` validation, blocked-directive list, admin-only permission.
- Cache purge button; rendered-config preview.

## Phase 6: Install and update (~0.5 wk) - DONE (the UI "Update app" button was left out on purpose: a web service should not replace its own code)
- `requirements.apt` + `install.sh` (idempotent): apt install, create user, systemd unit, sudoers, `node.toml`.
- Update: `git pull && ./install.sh`, or an "Update app" button in the UI.
- Test that every Python import maps to a Debian package (`dpkg -S`).
- Stagger `unattended-upgrades` between nodes.

### Phase 6b: Second-server join script - DONE as `install.sh --join` (tested by re-joining the live twin; fresh-VM test belongs to phase 7)
- `install.sh --join <peer-ip>` (or `debrev join <peer-ip>`) turns a fresh Debian box into the twin of an existing node.
- Steps: apt install deps → create user/dirs/systemd → exchange SSH keys (or mTLS certs) with the peer using a one-time join token shown in the first node's UI/CLI → write the local `node.toml` (own IP, peer IP, keepalived priority lower than the peer) → clone the state repo from the peer → rsync `/etc/letsencrypt` → render + `nginx -t` + apply → configure keepalived (BACKUP) → run the self-check and report.
- Idempotent and safe to re-run; refuses to overwrite an existing state repo without `--force`.
- Also supports `--init` for the first node, and `--dry-run` to print the plan.
- Test in two-node CI: fresh VM joins an existing node and ends with identical config versions and valid certs.

## Phase 7: Hardening and tests (~1.5 wk)
- DONE: rate/connection limiting, slow-client timeouts, hidden version, exposure checklist (`debrev security`, web page), optional fail2ban jail.
- Two-node integration tests (VMs/containers for CI only, not in production).
- Run against Debian stable and testing; render-and-`nginx -t` test for every option combination.
- Fail-safe tests: bad config, sync divergence, peer down, cert renewal failure.

## Next version (postponed on purpose)
- Alerts by email or webhook: certificate issue/renewal failed, backend down, sync broken, failover happened. (Until then the Health page, Certificates page and `debrev security` show these.)
- Failover form in Settings (virtual IP, VRRP id, node priority); DNS-01 via CNAME delegation for providers without a certbot plugin (FreeDNS, Hostpoint).

## Later / optional
- TOTP/2FA, multiple users and roles, stream (TCP/UDP) proxying via libnginx-mod-stream, Prometheus metrics, notifications on cert/sync failure, import from Nginx Proxy Manager.

## Phase 1 notes (as built)
- Code: `debrev/` (schema, state, render, apply, cli), `templates/`, `data/presets/`, `bin/`, `install.sh --init`, `requirements.apt`, 44 pytest tests.
- Apply = validate -> render release dir -> isolated `nginx -t` (generated files only) -> atomic `live` symlink swap -> full `nginx -t` -> reload -> health probe through nginx (token in the ACME webroot) -> auto rollback at every failing step.
- Open items for later phases: runtime DNS resolution for upstreams (nginx refuses to load if an upstream hostname does not resolve); redirect hosts and TCP/UDP stream proxies; ACME peer fallback location (phase 2/3); `install.sh --join` (phase 6b).

## Phase 1.1 (2026-11-01): upstream name caching + default-deny
- Upstream hostnames are resolved by debrev via the system resolver (search domain, /etc/hosts), cached in `/var/lib/debrev/dns-cache.json`, and pinned as IPs in the nginx config. A systemd timer (`debrev-dns.timer`, every 2 min) re-applies only when an address changes. Unresolvable names fall back to the cached IP; with no cache the host is skipped and other hosts are unaffected. `debrev dns` shows the state.
- Catch-all default servers: unknown Host headers and bare-IP requests get `444`; unknown TLS SNI is rejected. The stock nginx welcome site is disabled by the installer.
- Fixed: release directory name collision when two applies ran in the same second.

## Internet exposure checklist (do NOT open ports 80/443 before this is all green)
1. Phase 2 done: HTTPS certificates issued and auto-renewing, HTTP->HTTPS redirect active.
2. Port 80 must be reachable from the internet for Let's Encrypt HTTP-01 (or use DNS-01 and keep 80 closed).
3. Every proxied app is one you are happy to expose; use access lists for the rest.
4. Rate limiting / basic abuse protection (planned in phase 7).
5. Admin UI (phase 5) stays LAN/VPN-only, never forwarded.

## Pending: migrate from Nginx Proxy Manager
21 NPM proxy hosts (26 domain names) are saved in `/root/debrev-private/npm-proxy-hosts.yaml` (kept outside the repo on purpose), validated against the debrev schema. Not applied yet. To do: check per-host advanced settings in NPM (websockets, cache, HSTS, custom config), make sure upstream names resolve from this host, issue certificates (needs Phase 2), then `debrev host add` / import and switch DNS or port-forwarding. Needs a one-shot importer (`debrev import-npm`) or a script.

## Phase 2 notes (as built)
- `debrev acme set/show`, `debrev certs list|issue|renew`; root-side modes of `bin/debrev-apply`: `--certs`, `--certs-force`, `--certs-auto`, `--renew`, `--cert-info` (fixed whitelist, also in sudoers).
- One cert per host, named after the main domain (wildcard prefix removed), SANs = domain + aliases. HTTP-01 via the shared webroot (already served by every host's port-80 block); DNS-01 through any `python3-certbot-dns-*` plugin (wildcards use it automatically); staging/production/custom ACME server.
- Flow: apply plain HTTP -> certbot -> re-apply, so HTTPS starts on the next reload. Renewal = Debian's `certbot.timer`; deploy hook `/etc/letsencrypt/renewal-hooks/deploy/debrev-reload` tests and reloads nginx. `debrev-certs.timer` (30 min) issues missing certs only when `acme.auto: true`.
- Failures back off 1h, 2h, 4h ... 24h per host (rate-limit protection); `certs issue --force` overrides. Changed host names re-issue with `--expand`; a staging cert is replaced when production is configured.
- Private keys stay root-only: root publishes `/var/lib/debrev/certs.json` (expiry, SANs, issuer; no secrets) for the CLI/UI.
- Tested for real with Pebble (ACME test server from Debian apt), certbot and nginx: issuance, alias expansion, failure + backoff, forced renewal picked up by the deploy hook. 64 unit tests.
- Not testable here: real Let's Encrypt (port 80 is LAN-only), real DNS providers.

## Phase 3 notes (as built)
- Transport: SSH with a per-node ed25519 key owned by the `debrev` user. On the receiving side the key is locked in `authorized_keys` to `from=<peer ip>,restrict,command=bin/debrev-sync-serve`, which answers only: `git-upload-pack` (read-only), `status`, `notify`, `notify-force`, `cert-list`, `cert-import`. Shells, `id`, `cat`, `git-receive-pack` are refused (verified on the real pair).
- State: the receiver fetches and fast-forwards (no pushes into working trees), then applies; if the peer's config does not apply it reverts and will not retry that commit until `--retry`. Diverged or unrelated histories are never merged: status shows `diverged`, resolve with `debrev sync --take-theirs --yes` (backup branch kept) or `--take-mine --yes`. `debrev apply` notifies the peer; `debrev-sync.timer` (1 min) is the backstop.
- Certificates: only the node with `acme_issuer = true` talks to Let's Encrypt. nginx reads certificates from `/var/lib/debrev/certs/<name>` (root-only, atomic symlink swap), filled from certbot or from the peer. The issuer pushes certificates the peer lacks/has older; the peer validates (known host, exact names, key matches, not expired, newer) and re-applies.
- ACME fallback: every port-80 block does `try_files $uri @debrev_acme_peer` (one hop, loop-guarded) so validation succeeds whichever node receives the traffic. Verified: Pebble validated against debrev2, the request was handed to debrev, the certificate was issued there and appeared on debrev2.
- Node-local file `/etc/debrev/node.toml` (never synced): name, `acme_issuer`, `[peer] address`.
- Commands: `debrev peer keygen|authorize|set|clear|test`, `debrev node show|set`, `debrev sync`, `debrev certs push`.
- Manual join today (what `install.sh --join` will automate in phase 6b): install on the new box, `peer set`, `peer keygen`, exchange keys with `peer authorize`, `sync --take-theirs --yes`.
- Known gap: the first-contact SSH host key is accepted on first use (accept-new). The join token in 6b should pin it.
- Not live-tested: renewal pushing through the hook on a timer (hook entry point and push logic are covered by unit tests and the issuance run); peer reboot mid-sync.

## Phase 4 notes (as built)
- keepalived (VRRP, unicast between the two nodes, no multicast needed). Cluster-wide settings are synced (`settings.yaml: cluster: {vip, vrid}`, set with `debrev cluster set --vip 192.168.1.230`); node-local ones live in `node.toml` (`priority`, optional `interface`). Each node renders its own `/etc/keepalived/keepalived.conf` during every apply and starts/reloads keepalived when it changes.
- Priorities: primary 150, secondary 100. Failed health check = -60, drain = -100, so either always drops a node below its twin. A drained node still takes the IP if the twin is dead. The preferred node takes the IP back when healthy (preempt).
- Health = nginx answers `/.debrev-health` locally (private networks only; the reply names the node, which is also how `drain`/`cluster show` see who serves the VIP). Checked every 1s, 2 failures = fail, 2 successes = healthy.
- `debrev drain` refuses unless the twin is reachable, healthy and not drained (`--force` overrides), then waits until the VIP is really served by the twin. `debrev restore` waits for health. The drained state is a file keepalived tracks, so it survives reboots (verified).
- keepalived notify script records the VRRP state and makes the VIP holder the `acme_issuer`. Because a replicated certificate has no certbot lineage on the new master, `certs` now requests a fresh certificate when a replicated one is within 30 days of expiry (independent of `acme.auto`, which only gates brand-new certificates). Either node pushes newer certificates to the other.
- systemd drop-in for keepalived: `Restart=always` and `ExecStopPost` removes the VIP, so a SIGKILLed keepalived cannot leave a duplicate address behind.
- Measured on the real pair (probe every 0.2s from the twin): drain + restore 0 failed of 201 requests; nginx crash 23 failed (~4.6s, then back automatically); keepalived SIGKILL 1 failed of 106 (~1s); debrev2 full drain -> apt full-upgrade -> reboot -> restore worked and stayed drained across the reboot.
- Notes: no VRRP authentication (removed in VRRPv3; the LAN is trusted). Point port forwarding / DNS at the VIP, not at a node. A home router may only offer devices it has seen; browse the VIP once or add it manually.

## Phase 5 notes (as built)
- FastAPI + Jinja2, server-rendered, **no htmx and no JavaScript framework** (a 20-line `app.js` for confirm prompts and the host filter). Strict CSP: no inline script or style.
- Runs as `debrev-web.service` (user `debrev`, port 8443, HTTPS with a per-node self-signed certificate made by install.sh). Config in `/etc/debrev/web.toml` (listen, port, allow). Not synced.
- **Network guard:** only RFC1918/loopback/link-local/ULA clients are served; others get 403. Add VPN ranges to `allow`. It is not proxied by nginx, so ports 80/443 exposure does not expose it, but never port-forward 8443.
- Accounts are per node (`debrev user add|passwd|rm|list|no2fa`, files in `/var/lib/debrev/web`, 0700): argon2id, min 10 chars, optional TOTP (enabled on the Account page; needs password), signed 12 h cookie sessions (HttpOnly, SameSite=Strict, Secure), password/2FA change signs out other sessions, CSRF token on every POST, lockout after 5 failures (per IP and per user, 5 min), identical error text for unknown user / wrong password / wrong code.
- Pages: dashboard, hosts (form + filter, advanced YAML editor, delete), access lists (YAML editor, validated), certificates (request / renew / retry), history (diff view, restore), cluster (both nodes, drain / restore / sync), settings (ACME email, staging/production, auto), account.
- Every save validates the whole state and rolls the file back on error; commits carry the signed-in user as author (`... (web)`). Saving does not go live: a yellow "Apply now" bar shows while the saved version is ahead of the live one. "Save & apply" does both. Privileged work goes through the same CLI/sudo helper, so UI and CLI behave identically.
- Form toggles are only written to the host file when they differ from the defaults.
- Not done: cache purge button, rendered-config preview, redirect hosts, upgradable-packages view, QR code for TOTP (secret/URI shown as text), shared accounts across the twin (create the user on both nodes).

## DNS credentials sync (added after Phase 5)
- The file named in `acme.dns.credentials` (must be under /etc/letsencrypt or /etc/debrev) is copied to the twin over the existing root-only SSH channel together with the certificates (`cert-import`). The twin only writes the exact path named in its own synced settings, max 4 KB, 0600 root, atomic.
- Conflict rule: identical content = nothing; otherwise the newer file (mtime) wins and is installed on the other node. The twin reads a non-secret fingerprint (sha256, mtime) from certs.json, refreshed at the start of every `--cert-push` (every minute via debrev-sync).
- Not synced: anything outside that path (e.g. other secrets).

## Custom certificates, favicon, per-host HTTP-01/DNS-01 (added after Phase 5)
- `tls.cert: custom` without `cert_path`/`key_path` = uploaded certificate. Upload: `debrev certs upload` or the host page. Validated by the root helper (`debrev-apply --cert-upload`, new sudoers entry; re-run `install.sh` after updating): PEM, unencrypted key, key matches, not expired, names cover the domain and all aliases. Stored in `/var/lib/debrev/certs/<name>` like Let's Encrypt certificates.
- Sync of uploaded certificates differs from Let's Encrypt ones: not "longer expiry wins" but "more recently installed copy wins" (an upload with an earlier expiry must replace an older one and must not be reverted by the twin). Fingerprint (sha256) and install time are published in certs.json and exchanged by `cert-list`. A race exists right after adding a host: the twin may refuse the certificate until it has synced the host (one minute); the timer retries.
- The host form has Certificate source (Let's Encrypt / own) and Validation (HTTP-01 / DNS-01). Settings has the DNS provider (plugin, credentials file, wait seconds).
- Favicon = the logo (`/static/favicon.svg`, also served at `/favicon.ico`).
- certbot DNS plugins are selected with `--authenticator dns-<name>` (the `--dns-<name>` flag is ambiguous for Infomaniak).
- Renewal of a Let's Encrypt (staging) certificate through certbot + deploy hook was tested live: new serial served by both servers within seconds.

## Several DNS providers (added later)
- `acme.dns` stays the default provider; `acme.dns_providers: {name: {plugin, credentials, propagation_seconds}}` adds named ones; a host selects one with `tls.dns_provider` (validated against the settings). All listed credential files are synced to the twin (certs.json `_credentials` is now a map path -> fingerprint; the payload carries a list; older single-file payloads are still accepted).
- Not solved: providers without a certbot plugin (FreeDNS/afraid.org, Hostpoint). certbot plugins do not follow `_acme-challenge` CNAME delegation, so a CNAME to an Infomaniak zone does NOT work with the current engine. Options: HTTP-01 for those hosts, or a debrev-supplied manual auth hook that writes the TXT record into the delegated zone through a supported provider's API (not built).

## Settings/certificate UI rework (added later)
- Settings: DNS providers as cards, stored as `acme.dns_providers` + `acme.dns_default` (the old single `acme.dns` still works and is shown as a provider; saving migrates it). Status comes from the root-published `_credentials` fingerprints and `importlib` for the plugin.
- Certificates page: checkboxes + "Renew selected" -> `debrev certs renew NAME...` -> root helper `--certs-select` (JSON names on stdin; only names of enabled Let's Encrypt hosts accepted; forces renewal, ignores backoff). New sudoers entry: re-run `install.sh` after updating.
- Own certificates: the certificate/key boxes are part of the host form (shown when "My own certificate" is selected); a new host with that choice opens its page to add the certificate; the Certificates page has an "Edit certificate" button for them.
- Root hardening: `--cert-push` (every minute) chmods DNS token files named in the settings to 0600 (a hand-created 644 cloudflare.ini was found and fixed).

## Certificate progress bar (added later)
- "Renew selected" runs as a background job in the web service (`POST /certs/job`, `GET /certs/job/<id>`, one job at a time, last 5 kept in memory). The CLI/helper print machine-readable lines (`@@ total N`, `@@ start NAME`, `@@ done NAME ok|fail MSG`, `@@ applying`) which the job parses; the page polls every 2 s and shows a progress bar, per-certificate status with elapsed time, and the log. A page reload during a job picks it up again. Without JavaScript the button still works as a normal (blocking) form post. Other buttons (Request missing, Renew due, Retry failed) are still plain posts.
- The progress is per certificate (a DNS-01 certificate takes about 1-2 minutes; the time inside one certificate cannot be split further).

## Progress bar for every certificate action (added later)
- Request missing / Renew due / Retry failed / Renew selected all run as background jobs with the progress panel. Pressing the old plain-form buttons used to leave the page spinning for the whole run (11 DNS-01 certificates take 20+ minutes) with no feedback.
- `debrev-apply --certs|--certs-force` now print `@@ total/start/done/applying` lines; `debrev certs issue|renew NAME` (CLI) hides them unless `DEBREV_PROGRESS=1`, which only the web service sets. "Renew due" (certbot renew) has no per-certificate lines, so its bar is indeterminate.
- Do not restart `debrev-web` while a job runs: its children (including certbot) are part of the service and are stopped with it.
- Top-bar job indicator: a red spinner pill ("Requesting missing certificates 3/11") appears in the menu bar on every page while a background job runs (server-rendered, then refreshed by `GET /jobs/active` every 3-8 s); it links to the Certificates page.
