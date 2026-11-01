#!/bin/bash
# debrev installer. Idempotent: safe to re-run for updates.
#
#   sudo ./install.sh --init            set up this server as the first node
#   sudo ./install.sh --join <peer-ip>  set up this server as the twin of a running node
#   sudo ./install.sh --update          after 'git pull': refresh services, sudoers and config (same as --init)
#   sudo ./install.sh --fail2ban        optional: ban addresses that keep hitting the rate limit
#   options: --dry-run             print what would be done
#            --peer-user NAME      join: account on the peer to log in with (default root; needs sudo rights if not root)
#            --priority N          join: keepalived priority of this server (default: below the peer)
#            --yes                 join: do not ask before re-pairing a peer that already has another twin
set -euo pipefail

APP_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ETC=/etc/debrev
LIB=/var/lib/debrev
CACHE=/var/cache/debrev
SVC_USER=debrev
MODE="" DRY=0 PEER="" PEER_USER=root PRIO="" YES=0

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --init|--update) MODE=init ;;
    --fail2ban) MODE=fail2ban ;;
    --join) MODE=join; PEER="${2:-}"; shift || true ;;
    --peer-user) PEER_USER="${2:-}"; shift || true ;;
    --priority) PRIO="${2:-}"; shift || true ;;
    --yes) YES=1 ;;
    --dry-run) DRY=1 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
  shift || true
done
[ -n "$MODE" ] || usage 2
if [ "$MODE" = join ]; then
  [[ "$PEER" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "--join needs the twin's IPv4 address, e.g. --join 192.168.1.10" >&2; exit 2; }
  [[ "$PEER_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "invalid --peer-user" >&2; exit 2; }
  [ -z "$PRIO" ] || [[ "$PRIO" =~ ^[0-9]+$ ]] || { echo "--priority must be a number" >&2; exit 2; }
fi

step() { echo "==> $*"; }
run() { if [ "$DRY" = 1 ]; then echo "    [dry-run] $*"; else "$@"; fi; }
write() { # write <mode> <path> ; content on stdin
  local mode="$1" path="$2" content; content="$(cat)"
  if [ "$DRY" = 1 ]; then echo "    [dry-run] write $path"; return; fi
  printf '%s\n' "$content" > "$path"; chmod "$mode" "$path"
}

[ "$(id -u)" = 0 ] || [ "$DRY" = 1 ] || { echo "run as root (sudo)" >&2; exit 1; }
grep -qi '^ID=debian\|^ID_LIKE=.*debian' /etc/os-release || { echo "this installer targets Debian" >&2; exit 1; }
case "$APP_DIR" in
  /opt/*) ;;
  *) echo "warning: $APP_DIR is not under /opt; the '$SVC_USER' user may not be able to read it" >&2 ;;
esac

# keepalived runs the health check and notify scripts as root and, with enable_script_security, silently
# disables them if the script or any directory above it is owned by, or writable by, somebody else.
# The result would be a server that never fails over when nginx dies, so refuse to continue.
check_script_security() {
  local bad="" d
  d=$(readlink -f "$APP_DIR")
  while [ "$d" != "/" ]; do
    [ "$(stat -c %u "$d")" = 0 ] && [ -z "$(find "$d" -maxdepth 0 -perm /022)" ] || bad="$bad $d"
    d=$(dirname "$d")
  done
  bad="$bad $(find "$APP_DIR/bin" \( ! -user root -o -perm /022 \) 2>/dev/null | tr '\n' ' ')"
  bad=$(echo $bad)
  [ -z "$bad" ] && return 0
  cat >&2 <<MSG
error: keepalived would refuse to run debrev's health check, so this server would never fail over.
These must be owned by root and not writable by group/others:
  $bad
Install from a root-owned directory such as /opt/debrev:
  sudo git clone https://github.com/pascalbrax/debrev.git /opt/debrev && cd /opt/debrev && sudo ./install.sh --init
or fix the current one:  sudo chown -R root:root $APP_DIR && sudo chmod -R go-w $APP_DIR
MSG
  return 1
}
[ "$DRY" = 1 ] || check_script_security || exit 1

if [ "$MODE" = fail2ban ]; then
  step "Installing fail2ban (Debian package) with a jail for debrev's rate limit"
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban
  write 0644 /etc/fail2ban/jail.d/debrev.local <<'JAIL'
# Managed by debrev (install.sh --fail2ban). nginx logs "limiting requests" when a client address
# goes over the rate limit; an address that does it 30 times in a minute is banned for an hour.
[nginx-limit-req]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
backend  = auto
maxretry = 30
findtime = 60
bantime  = 1h
ignoreip = 127.0.0.0/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7
JAIL
  if [ "$DRY" = 0 ]; then systemctl enable --now fail2ban >/dev/null && systemctl restart fail2ban; fi
  echo "Done. Check with:  sudo fail2ban-client status nginx-limit-req"
  exit 0
fi

step "Installing Debian packages from requirements.apt"
mapfile -t PKGS < <(sed 's/#.*//' "$APP_DIR/requirements.apt" | awk 'NF{print $1}')
run apt-get update -qq
run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${PKGS[@]}"

step "Creating service user and directories"
if ! id "$SVC_USER" >/dev/null 2>&1; then
  run adduser --system --group --home "$LIB" --no-create-home --shell /bin/sh "$SVC_USER"
fi
# the sync key is locked to a forced command (see 'debrev peer authorize'); sshd runs it through the login shell
if [ "$(getent passwd "$SVC_USER" | cut -d: -f7)" != /bin/sh ]; then run usermod -s /bin/sh "$SVC_USER"; fi
run install -d -m 0750 -o root -g "$SVC_USER" "$ETC"
run install -d -m 0755 -o "$SVC_USER" -g "$SVC_USER" "$LIB"
run install -d -m 0755 -o "$SVC_USER" -g "$SVC_USER" "$LIB/acme"
run install -d -m 0755 -o www-data -g www-data "$CACHE"

step "Installing the 'debrev' command"
run ln -sf "$APP_DIR/bin/debrev" /usr/local/bin/debrev
run chmod 0755 "$APP_DIR/bin/debrev" "$APP_DIR/bin/debrev-apply"

step "Writing node settings ($ETC/node.toml)"
if [ ! -e "$ETC/node.toml" ]; then
  write 0660 "$ETC/node.toml" <<TOML
# Settings for THIS server only. Never synced to the twin.
[node]
name = "$(hostname -s)"
acme_issuer = true
# [peer]            # 'debrev peer set <ip>' (twin server)
# address = ""
TOML
  [ "$DRY" = 1 ] || { chgrp "$SVC_USER" "$ETC/node.toml"; chmod 0660 "$ETC/node.toml"; }
else
  echo "    keeping existing $ETC/node.toml"
  [ "$DRY" = 1 ] || { chgrp "$SVC_USER" "$ETC/node.toml"; chmod 0660 "$ETC/node.toml"; }
fi

step "Hooking debrev into nginx"
write 0644 /etc/nginx/conf.d/debrev.conf <<'NGX'
# Managed by debrev. The 'live' link always points at the last applied release.
include /var/lib/debrev/live/*.conf;
NGX

step "Allowing '$SVC_USER' to run the apply helper via sudo"
write 0440 /etc/sudoers.d/debrev <<SUDO
$SVC_USER ALL=(root) NOPASSWD: $APP_DIR/bin/debrev-apply, $APP_DIR/bin/debrev-apply --check, $APP_DIR/bin/debrev-apply --certs, $APP_DIR/bin/debrev-apply --certs-force, $APP_DIR/bin/debrev-apply --renew, $APP_DIR/bin/debrev-apply --cert-publish, $APP_DIR/bin/debrev-apply --cert-push, $APP_DIR/bin/debrev-apply --cert-import, $APP_DIR/bin/debrev-apply --cert-upload, $APP_DIR/bin/debrev-apply --certs-select
SUDO
[ "$DRY" = 1 ] || visudo -cf /etc/sudoers.d/debrev >/dev/null

step "Disabling the stock nginx welcome site (debrev answers unknown hosts itself)"
if [ -L /etc/nginx/sites-enabled/default ]; then run rm -f /etc/nginx/sites-enabled/default; fi

step "Installing the DNS refresh timer (re-resolves upstream names every 2 minutes)"
write 0644 /etc/systemd/system/debrev-dns.service <<UNIT
[Unit]
Description=debrev: re-resolve upstream host names and re-apply if they changed
[Service]
Type=oneshot
ExecStart=$APP_DIR/bin/debrev-apply --refresh-dns
UNIT
write 0644 /etc/systemd/system/debrev-dns.timer <<'UNIT'
[Unit]
Description=debrev upstream DNS refresh
[Timer]
OnBootSec=1min
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
UNIT
if [ "$DRY" = 0 ]; then systemctl daemon-reload && systemctl enable --now debrev-dns.timer >/dev/null; fi

step "Traffic statistics timer (reads nginx's JSON access log every minute for the Health page)"
write 0644 /etc/systemd/system/debrev-traffic.service <<UNIT
[Unit]
Description=debrev: count new requests from the nginx access log
[Service]
Type=oneshot
User=$SVC_USER
SupplementaryGroups=adm
ExecStart=$APP_DIR/bin/debrev traffic collect --quiet
UNIT
write 0644 /etc/systemd/system/debrev-traffic.timer <<'UNIT'
[Unit]
Description=debrev traffic statistics
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
UNIT
if [ "$DRY" = 0 ]; then systemctl daemon-reload && systemctl enable --now debrev-traffic.timer >/dev/null; fi

step "Let's Encrypt: reload nginx after every renewal; timer for automatic issuing"
run install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
write 0755 /etc/letsencrypt/renewal-hooks/deploy/debrev-reload <<HOOK
#!/bin/sh
# Installed by debrev.
# publishes the renewed certificate to the directory nginx reads, reloads nginx, sends it to the twin
$APP_DIR/bin/debrev-apply --cert-publish
HOOK
write 0644 /etc/systemd/system/debrev-certs.service <<UNIT
[Unit]
Description=debrev: issue missing Let's Encrypt certificates (only when acme.auto is on)
[Service]
Type=oneshot
ExecStart=$APP_DIR/bin/debrev-apply --certs-auto
UNIT
write 0644 /etc/systemd/system/debrev-certs.timer <<'UNIT'
[Unit]
Description=debrev certificate issuing
[Timer]
OnBootSec=5min
OnUnitActiveSec=30min
[Install]
WantedBy=timers.target
UNIT
if [ "$DRY" = 0 ]; then systemctl daemon-reload && systemctl enable --now debrev-certs.timer >/dev/null; fi

step "Twin sync timer (every minute; does nothing until a peer is configured)"
write 0644 /etc/systemd/system/debrev-sync.service <<UNIT
[Unit]
Description=debrev: sync state and certificates with the twin server
[Service]
Type=oneshot
ExecStart=-/usr/sbin/runuser -u $SVC_USER -- $APP_DIR/bin/debrev sync --quiet
ExecStart=-$APP_DIR/bin/debrev-apply --cert-push
UNIT
write 0644 /etc/systemd/system/debrev-sync.timer <<'UNIT'
[Unit]
Description=debrev twin sync
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
UNIT
if [ "$DRY" = 0 ]; then systemctl daemon-reload && systemctl enable --now debrev-sync.timer >/dev/null; fi
run install -d -m 0700 -o root -g root "$LIB/certs"
run install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$LIB/.ssh"

step "Web interface (HTTPS on port 8443, local networks only)"
if [ ! -e "$ETC/web.toml" ]; then
  write 0644 "$ETC/web.toml" <<'TOML'
# debrev web interface. Reachable from private/local networks only; add VPN ranges to 'allow'.
[web]
listen = "0.0.0.0"
port = 8443
allow = []
TOML
fi
if [ ! -e "$ETC/web.key" ]; then
  if [ "$DRY" = 1 ]; then echo "    [dry-run] create self-signed certificate $ETC/web.crt"; else
    H="$(hostname -s)"
    SAN="DNS:$H,DNS:$(hostname -f 2>/dev/null || echo "$H"),DNS:localhost,IP:127.0.0.1"
    for ip in $(hostname -I 2>/dev/null); do SAN="$SAN,IP:$ip"; done
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=$H" -addext "subjectAltName=$SAN" -keyout "$ETC/web.key" -out "$ETC/web.crt" 2>/dev/null
    chown "$SVC_USER:$SVC_USER" "$ETC/web.key" "$ETC/web.crt"; chmod 0600 "$ETC/web.key"; chmod 0644 "$ETC/web.crt"
  fi
fi
run install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$LIB/web"
write 0644 /etc/systemd/system/debrev-web.service <<UNIT
[Unit]
Description=debrev web interface
After=network-online.target
Wants=network-online.target
[Service]
User=$SVC_USER
Group=$SVC_USER
SupplementaryGroups=adm
ExecStart=$APP_DIR/bin/debrev web
Restart=on-failure
RestartSec=3
# NoNewPrivileges must stay off: the UI calls the sudo-whitelisted apply helper
PrivateTmp=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
[Install]
WantedBy=multi-user.target
UNIT
if [ "$DRY" = 0 ]; then systemctl daemon-reload && systemctl enable debrev-web.service >/dev/null && systemctl restart debrev-web.service; fi

step "keepalived: restart quickly after a crash and never leave the virtual IP behind"
run install -d -m 0755 /etc/systemd/system/keepalived.service.d
write 0644 /etc/systemd/system/keepalived.service.d/debrev.conf <<UNIT
[Service]
Restart=always
RestartSec=1
ExecStopPost=-$APP_DIR/bin/debrev-vip-cleanup
UNIT
if [ "$DRY" = 0 ]; then systemctl daemon-reload; fi

step "Creating the state repository"
if [ "$DRY" = 1 ]; then echo "    [dry-run] debrev init (as $SVC_USER)"; else
  runuser -u "$SVC_USER" -- "$APP_DIR/bin/debrev" init
fi

step "Initial apply"
if [ "$DRY" = 1 ]; then echo "    [dry-run] debrev-apply"; else
  "$APP_DIR/bin/debrev-apply"
fi

join_twin() {
  step "Joining the twin at $PEER"
  local me key peerinfo peerkey peerprio
  me="$(ip -4 route get "$PEER" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") {print $(i+1); exit}}')"
  if [ "$DRY" = 1 ]; then
    echo "    [dry-run] set peer $PEER, create this node's sync key, log in to $PEER_USER@$PEER once to authorize it there,"
    echo "    [dry-run] authorize the peer's key here, adopt the peer's configuration (backup branch kept), apply"
    return
  fi
  [ -n "$me" ] || { echo "cannot find which local address reaches $PEER (is it reachable?)" >&2; exit 1; }
  echo "    this server's address towards the twin: $me"
  ping -c1 -W2 "$PEER" >/dev/null 2>&1 || echo "    warning: $PEER does not answer ping (continuing)"
  local SSH="${DEBREV_SSH:-ssh}"   # test hook
  local D="runuser -u $SVC_USER -- $APP_DIR/bin/debrev"
  $D peer set "$PEER" >/dev/null
  $D node set --issuer no >/dev/null
  key="$($D peer keygen)"

  # One interactive login to the twin (ssh asks for the password if you have no key there).
  local remote
  remote='D=/usr/local/bin/debrev; if [ "$(id -u)" = 0 ]; then R="runuser -u debrev --"; else R="sudo -n -u debrev"; fi
echo "PRIORITY $($R $D node show | sed -n "s/^priority: *//p")"
echo "CURRENT-PEER $($R $D node show | sed -n "s/^peer: *//p")"'
  echo "    logging in to $PEER_USER@$PEER ..."
  peerinfo="$($SSH -o StrictHostKeyChecking=accept-new "$PEER_USER@$PEER" "$remote")" || {
    cat >&2 <<MSG

Could not log in to $PEER_USER@$PEER. Either use --peer-user with an account that works, or do the
pairing by hand: on the twin run

    sudo -u $SVC_USER debrev peer set $me
    sudo -u $SVC_USER debrev peer authorize '$key'
    sudo -u $SVC_USER debrev peer keygen        # prints the twin's key

then here:   sudo -u $SVC_USER debrev peer authorize '<that key>'  and  sudo -u $SVC_USER debrev sync --take-theirs --yes
MSG
    exit 1; }
  local cur
  cur="$(printf '%s\n' "$peerinfo" | sed -n 's/^CURRENT-PEER *//p')"
  peerprio="$(printf '%s\n' "$peerinfo" | sed -n 's/^PRIORITY *//p')"
  if [ -n "$cur" ] && [ "$cur" != "-" ] && [ "$cur" != "$me" ] && [ "$YES" = 0 ]; then
    echo "    $PEER is currently paired with $cur. Joining replaces that twin."
    read -r -p "    continue? [y/N] " ans; [ "$ans" = y ] || [ "$ans" = Y ] || { echo "aborted"; exit 1; }
  fi
  peerkey="$($SSH "$PEER_USER@$PEER" "D=/usr/local/bin/debrev; if [ \"\$(id -u)\" = 0 ]; then R='runuser -u debrev --'; else R='sudo -n -u debrev'; fi; \$R \$D peer set $me >/dev/null && \$R \$D peer authorize '$key' >/dev/null && \$R \$D peer keygen")"
  [[ "$peerkey" == ssh-ed25519\ * ]] || { echo "unexpected answer from the twin: $peerkey" >&2; exit 1; }
  $D peer authorize "$peerkey" >/dev/null
  if [ -z "$PRIO" ]; then
    if [ "${peerprio:-100}" -gt 100 ]; then PRIO=100; else PRIO=$(( ${peerprio:-100} > 10 ? ${peerprio:-100} - 10 : 1 )); fi
  fi
  $D node set --priority "$PRIO" >/dev/null
  echo "    keepalived priority of this server: $PRIO (twin: ${peerprio:-?})"
  # automatic upgrades: the twin runs 12 hours after the first node so both are never upgrading at once
  install -d -m 0755 /etc/systemd/system/apt-daily-upgrade.timer.d
  printf '[Timer]\nOnCalendar=\nOnCalendar=*-*-* 18:00\nRandomizedDelaySec=30m\n' > /etc/systemd/system/apt-daily-upgrade.timer.d/debrev.conf
  systemctl daemon-reload
  $D peer test
  $D sync --take-theirs --yes
  "$APP_DIR/bin/debrev-apply"
  # ask the twin to send its certificates now instead of within the minute
  $SSH "$PEER_USER@$PEER" 'H=$(dirname "$(readlink -f /usr/local/bin/debrev)")/debrev-apply; if [ "$(id -u)" = 0 ]; then "$H" --cert-push; else sudo -n "$H" --cert-push; fi' >/dev/null 2>&1 || true
  echo "    paired. Certificates and later changes arrive by themselves (sync runs every minute)."
}
if [ "$MODE" = join ]; then join_twin; fi

echo
if [ "$MODE" = join ]; then
  echo "Done. This server is now the twin of $PEER; hosts and certificates come from there."
  echo "Check:  sudo -u $SVC_USER debrev status   and   sudo -u $SVC_USER debrev cluster show"
  echo "Web interface: https://$(hostname -s):8443  -  logins are per server:  sudo debrev user add NAME"
  exit 0
fi
echo "Done. Try:  sudo -u $SVC_USER debrev host add app.example.com http://127.0.0.1:3000 --websockets"
echo "            sudo -u $SVC_USER debrev apply"
echo "Web interface: https://$(hostname -s):8443  (self-signed certificate; local networks only)"
echo "  create your login first:  sudo debrev user add NAME"
