# hardening

Baseline hardening for Debian/Ubuntu. Every component has a switch and a tag.

| Component | Tag | Default | What it does |
|---|---|---|---|
| SSH | `ssh` | on | Drop-in `10-hardening.conf`: no root login, no passwords, `MaxAuthTries 3`, no forwarding. Validated with `sshd -t` before it is written. |
| sysctl | `sysctl` | on | Network and kernel hardening in `/etc/sysctl.d/90-hardening.conf`. Does **not** touch `ip_forward` (Docker/k3d need it). |
| fail2ban | `fail2ban` | on | `sshd` jail (journal backend). |
| updates | `updates` | on | `unattended-upgrades`, periodic. No automatic reboots. |
| auditd | `auditd` | on | Watches on identity files, sudoers and sshd config. |
| firewall | `firewall` | **off** | ufw: SSH (rate-limited) first, extra ports from `hardening_firewall_allowed_ports`, default deny incoming. Opt-in because a wrong rule locks you out. |

## Safety

- **Lockout protection:** the role refuses to disable password or root login unless `hardening_ssh_admin_user`
  is not root and has a non-empty `authorized_keys`.
- **Safe target:** `playbooks/harden.yml` runs on the empty group `hardening_targets`; nothing happens
  until you pass `-e target=<host>`.
- **Fail-closed on OS:** anything that is not Debian-family is rejected.

## Usage

```bash
cd ansible
# dry run first
ansible-playbook playbooks/harden.yml -e target=myhost -K --check --diff
# apply, only SSH and sysctl
ansible-playbook playbooks/harden.yml -e target=myhost -K --tags ssh,sysctl
# in a container / CI: do not touch services or the running kernel
ansible-playbook playbooks/harden.yml -e target=myhost \
  -e hardening_manage_services=false -e hardening_sysctl_apply=false
```

Variables and defaults: `defaults/main.yml`.

## What is verified

Verified: `ansible-lint` (production profile); a real run on Ubuntu 24.04 (services and runtime sysctl
disabled); second run reports `changed=0`; `sshd -T` shows the effective values; lockout protection
refuses `root` as the admin user; `--tags` and firewall `--check` work.

Not verified yet: Debian 12 and Ubuntu 22.04; services actually running (fail2ban, auditd);
runtime `sysctl --system`; a real `ufw enable`. Molecule tests are the next step.
