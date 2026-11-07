# 🛡️ Ansible Security Monitor

> A DevSecOps lab built in the open: **Ansible automation with tested roles**, a **CI security pipeline**, and an **AI agent that reviews pull requests**.

[![Ansible Lint](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/ansible-lint.yml/badge.svg?branch=master)](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/ansible-lint.yml)
[![Molecule](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/molecule.yml/badge.svg?branch=master)](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/molecule.yml)
[![KICS](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/kics.yml/badge.svg?branch=master)](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/kics.yml)
[![AI Security Gatekeeper](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/ai-gatekeeper.yml/badge.svg?branch=master)](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/ai-gatekeeper.yml)
[![Unit Tests](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/unit-tests.yml/badge.svg?branch=master)](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/unit-tests.yml)

Built and documented publicly by [Bekbolat](https://www.linkedin.com/in/bekbolatzhumabekov/) — IT engineer (11+ years) moving into DevSecOps.

---

## What is in here

| Part | What it is | Where |
|---|---|---|
| **Ansible automation** | Read-only audit, health report, and a **tested `hardening` role** for Debian/Ubuntu | [`ansible/`](ansible/) |
| **CI security pipeline** | Trivy, KICS, Conftest/OPA, OPA Gatekeeper, Falco on k3d, AI triage, correlation engine | [`.github/workflows/`](.github/workflows/) |
| **AI Security Agent** | LLM agent that reviews a pull request by choosing tools (git diff, KICS, Trivy) | [`security-agent/`](security-agent/) |
| **Kubernetes & IaC** | Helm chart, RBAC, network policy, Gatekeeper constraints, Terraform | [`k8s/`](k8s/), [`terraform/`](terraform/) |
| **Observability** | Prometheus, Pushgateway, Grafana dashboard as code | [`monitoring/`](monitoring/) |

---

## 🔧 Ansible

```
ansible/
├── ansible.cfg
├── inventory/hosts.yml          # `hardening_targets` is empty on purpose
├── playbooks/
│   ├── security_audit.yml       # read-only audit with real metrics
│   ├── telegram_report.yml      # health report, status computed from thresholds
│   └── harden.yml               # applies the hardening role (needs -e target=<host>)
└── roles/hardening/
    ├── defaults/ tasks/ templates/ handlers/ meta/
    └── molecule/default/        # converge, idempotence, verify
```

### The `hardening` role

Debian/Ubuntu baseline. Every component has a switch and a tag.

| Component | Tag | Default | What it does |
|---|---|---|---|
| SSH | `ssh` | on | Drop-in config: no root login, no passwords, `MaxAuthTries 3`, no forwarding. Validated with `sshd -t` before it is written. |
| sysctl | `sysctl` | on | Network and kernel hardening. Does **not** touch `ip_forward` (Docker, k3d and Kubernetes need it). |
| fail2ban | `fail2ban` | on | `sshd` jail. |
| Unattended upgrades | `updates` | on | Automatic security updates, no automatic reboots. |
| auditd | `auditd` | on | Watches on identity files, sudoers and sshd config. |
| Firewall (ufw) | `firewall` | **off** | SSH (rate-limited) first, extra ports from a variable, default deny. Opt-in because a wrong rule locks you out. |

### Design decisions

- **Lockout protection.** The role refuses to disable password or root login unless the admin user is not `root` and has a non-empty `authorized_keys`.
- **Effective-config check.** `sshd` uses the *first* value it sees, so another file in `sshd_config.d/` can silently cancel the hardening. After writing the drop-in the role reads `sshd -T` and fails if the effective values differ from the requested ones.
- **Safe by default.** `harden.yml` runs on an empty group; nothing happens until you pass `-e target=<host>`. Anything that is not Debian-family is rejected.
- **Evidence-based reports.** The audit computes disk and memory from real facts, and the Telegram status comes from thresholds. No hard-coded "success" messages.

### What the CI proves

- `ansible-lint` runs in the **production profile with no warn-list and no `|| true`**. A deliberately broken PR turned the check red.
- **Molecule** (Docker, systemd) runs on **Ubuntu 22.04 and 24.04**: converge, **idempotence** (a second run changes nothing), and verify — effective `sshd -T` values, sysctl, fail2ban config and running state, unattended upgrades, and a negative test that lockout protection refuses a keyless admin.
- Third-party actions are pinned (Trivy action to a commit), tool versions are pinned in `ansible/requirements-dev.txt`.

Not covered by the container tests: auditd (needs the kernel audit socket), runtime `sysctl --system`, a real `ufw enable`, Debian 12.

### Try it

```bash
cd ansible
python3 -m venv ~/ansible-venv && . ~/ansible-venv/bin/activate
pip install -r requirements-dev.txt

ansible-lint                                   # strict
ansible-playbook playbooks/security_audit.yml  # read-only audit, writes ~/system_health.log

# hardening: dry run first
ansible-playbook playbooks/harden.yml -e target=myhost -K --check --diff

# role tests (needs Docker)
cd roles/hardening && molecule test
```

See [`ansible/roles/hardening/README.md`](ansible/roles/hardening/README.md) for variables and details.

---

## 🤖 AI Security Agent

An agent that gets a pull request number and **decides which checks to run**: it reads the diff via the GitHub API, runs KICS and Trivy in Docker on the PR branch, and returns a verdict with severity levels (`APPROVE` / `REQUEST CHANGES` / `NEEDS MANUAL CHECK`).

It is built to not make things up: it reports only what the tools returned, states a scanner failure explicitly, and never approves when a scanner failed.

Details, tools and roadmap: [`security-agent/README.md`](security-agent/README.md) (in Russian).

---

## 🏗️ CI security pipeline

```
Developer Push / PR
        │
        ▼
┌─────────────────────────────────────────────────────┐
│                  GitHub Actions CI                  │
│                                                     │
│  Trivy          KICS           Conftest             │
│  (containers    (Ansible,      (Policy as           │
│   + IaC)        Helm, K8s,     Code)                │
│                 Dockerfile)                         │
│                      │                              │
│           ┌──────────▼──────────┐                   │
│           │  AI Security Gate   │                   │
│           │  Prioritized triage │                   │
│           └──────────┬──────────┘                   │
└──────────────────────┼──────────────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
   Telegram Alert  Prometheus   Grafana
   (on failure)    Pushgateway  Dashboard
                       │
                  OPA Gatekeeper
                  (K8s admission control)
```

The `AI Security Gatekeeper` workflow also creates a k3d cluster, installs OPA Gatekeeper (and checks that it blocks a bad deployment), deploys the workload, installs **Falco** next to it, runs controlled runtime scenarios and feeds the alerts to the correlation engine.

### Correlation engine

[`ai_correlation_engine.py`](ai_correlation_engine.py) classifies every signal using only what was observed, and does **not** claim to prove exploitation:

| Level | Meaning |
|---|---|
| 🟢 Static only | A scanner flagged a MITRE technique; Falco saw nothing in that family. |
| 🟡 Runtime detected | Falco saw activity no static scanner flagged. |
| 🔵 Detection coverage confirmed | A static finding and a Falco alert share a technique family: the weakness class is visible to the runtime layer. |
| 🔴 Potential exploitation path | Same, and the Falco alert is itself CRITICAL/ERROR. "Potential", not "confirmed". |

---

## 🚀 Quick start (pipeline and monitoring)

```bash
git clone https://github.com/bekbolat2700-collab/ansible-security-monitor.git
cd ansible-security-monitor

# secrets live in a local, gitignored .env — see .env.example
cp .env.example .env   # then edit it

docker-compose up -d prometheus pushgateway grafana   # Grafana: http://localhost:3000

# KICS
docker run --rm -v "$(pwd)":/path checkmarx/kics:latest scan -p /path \
  --exclude-paths /path/k8s/gatekeeper --fail-on HIGH

# Trivy
trivy fs . --severity HIGH,CRITICAL
```

The Grafana admin password comes from `GF_SECURITY_ADMIN_PASSWORD` in your local `.env`; nothing is hard-coded in the repository.

### Grafana dashboard

The pipeline exports metrics to Prometheus after every scan; the dashboard is stored as code in `monitoring/grafana/dashboards/` and loads on startup: pipeline status, findings by severity and by scanner, risk score, last scan, trend.

---

## 🧰 Tech stack

| Layer | Tool |
|---|---|
| Automation | Ansible, Molecule, ansible-lint |
| Containers & orchestration | Docker, Kubernetes (k3d), Helm |
| Scanning | Trivy, KICS |
| Policy as Code | Conftest + OPA (CI), OPA Gatekeeper (cluster) |
| Runtime detection | Falco |
| Secrets | HashiCorp Vault |
| AI | Groq (LLM tool calling) |
| CI/CD | GitHub Actions |
| Metrics | Prometheus, Pushgateway, Grafana |
| Alerts | Telegram Bot |

---

## 📖 LinkedIn series

| Part | Topic |
|---|---|
| 1–11 | [Full series on LinkedIn](https://www.linkedin.com/in/bekbolatzhumabekov/) |
| 12 | KICS multi-IaC scanning + supply chain attack discovery |
| 13 | Fixing HIGH findings + unified security report |
| 14 | Contextual AI triage: from counts to prioritized findings |
| 15 | Policy as Code with Conftest |
| 16 | Final architecture, lessons learned, Grafana dashboard |

---

## 👤 Author

**Bekbolat** — DevSecOps engineer from Astana 🇰🇿

- LinkedIn: [@bekbolatzhumabekov](https://www.linkedin.com/in/bekbolatzhumabekov/)
- GitHub: [@bekbolat2700-collab](https://github.com/bekbolat2700-collab)

> *"Security is a workflow, not a collection of tools."*
