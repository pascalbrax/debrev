# Administration access without root SSH

debrev itself never needs root SSH: the twin sync uses the `debrev` service account with its own restricted key.
Root SSH is only convenient for two things: **joining a new twin** and **pushing code to a server**. Both work with
a normal admin account (`admin` below) once it has the few sudo rights listed here. Replace names and addresses.

## 1. Letting `install.sh --join` log in as an admin account
`sudo ./install.sh --join <peer-ip> --peer-user admin` logs in to the running node as `admin` and runs the debrev
commands through sudo. On the **running node** create `/etc/sudoers.d/debrev-admin` (mode 0440, check with `visudo -cf`):

```
admin ALL=(debrev) NOPASSWD: /usr/local/bin/debrev
admin ALL=(root)   NOPASSWD: /opt/debrev/bin/debrev-apply --cert-push
```

`ssh` asks for admin's password (or uses a key if you set one up). Without these two lines the join stops with
"sudo: a password is required" and prints the manual commands instead.

## 2. A deploy key for pushing code to a server (optional)
Needed only if somebody (or an assistant) pushes code from another machine. Anything that can deploy code can run code
as root on that server, so treat this key like a root key: restrict it to one source address and remove it when done.

On the **target server**, as root:

```
# a) allow the key, only from the deploying machine
install -d -m 0700 -o admin -g admin /home/admin/.ssh
echo 'from="DEPLOYER-IP" ssh-ed25519 AAAA...key... comment' >> /home/admin/.ssh/authorized_keys
chown admin:admin /home/admin/.ssh/authorized_keys && chmod 600 /home/admin/.ssh/authorized_keys

# b) an upload folder and one fixed script that installs what was uploaded
install -d -m 0755 -o admin -g admin /home/admin/incoming
cat > /usr/local/sbin/debrev-deploy <<'EOF'
#!/bin/sh
set -eu
rsync -a --delete --chown=root:root --exclude .git --exclude __pycache__ --exclude tests --exclude '*.pyc' /home/admin/incoming/ /opt/debrev/
chmod -R go+rX,go-w /opt/debrev     # keepalived ignores scripts that anyone but root owns or can write
cd /opt/debrev && ./install.sh --update
EOF
chmod 0755 /usr/local/sbin/debrev-deploy

# c) admin may run only that script as root
echo 'admin ALL=(root) NOPASSWD: /usr/local/sbin/debrev-deploy' > /etc/sudoers.d/debrev-deploy
chmod 0440 /etc/sudoers.d/debrev-deploy && visudo -cf /etc/sudoers.d/debrev-deploy
```

From the deploying machine: `rsync -a --delete --exclude .git ./ admin@TARGET:incoming/ && ssh admin@TARGET sudo /usr/local/sbin/debrev-deploy`.

To remove the access again: delete the key line from `/home/admin/.ssh/authorized_keys` and the file
`/etc/sudoers.d/debrev-deploy`.

## 3. Turning root password login off
In `/etc/ssh/sshd_config` (or a file in `sshd_config.d/`): `PermitRootLogin no`, then `systemctl restart ssh`
(or reboot). `debrev security` and the Security page tell you if it is still on.
