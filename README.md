# 🛡️ Ansible Security Monitor

> A production-grade DevSecOps pipeline built from scratch — documented as a 16-part LinkedIn series.

![Ansible Lint & Security Scan](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/ansible-lint.yml/badge.svg)
![AI Security Gatekeeper](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/ai-security-gatekeeper.yml/badge.svg)
![KICS Security Scan](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/kics.yml/badge.svg)

---

## 🔍 What is this?

A real-world DevSecOps pipeline that automates security auditing across infrastructure code, containers, and Kubernetes — with AI-powered triage, Policy as Code enforcement, and a unified Grafana security dashboard.

Built and documented publicly as a LinkedIn series by [@bekbolatzhumabekov](https://www.linkedin.com/in/bekbolatzhumabekov/) 🥷🏻

---

## 🧰 Tech Stack

| Layer | Tool |
|-------|------|
| IaC & Automation | Ansible |
| Containerization | Docker |
| Orchestration | Kubernetes + Helm Charts |
| Container & IaC Scanning | Trivy (replaces tfsec) |
| Multi-IaC Scanning | KICS |
| Policy as Code | Conftest + OPA Gatekeeper |
| Secrets Management | HashiCorp Vault |
| AI Analysis | Groq / Llama 3 |
| CI/CD | GitHub Actions |
| Monitoring & Dashboard | Prometheus + Grafana |
| Alerts | Telegram Bot |

---

## 🔒 Security Coverage

| Tool | What It Scans |
|------|--------------|
| Trivy | Container images, dependencies (CVEs) + IaC misconfigurations |
| KICS | Ansible, Helm, Dockerfile, Kubernetes manifests |
| Conftest | Policy as Code — blocks non-compliant deployments in CI |
| OPA Gatekeeper | Kubernetes admission control — enforces policies in cluster |
| Vault | Secrets management — no hardcoded credentials |
| Ansible Lint | Playbook quality & security rules |

---

## 📊 Security Dashboard

The pipeline exports structured metrics to Prometheus after every scan. Grafana provides a unified view:

- **Pipeline Status** — PASSED / FAILED
- **Critical, HIGH, MEDIUM findings** — by scanner
- **Risk Score** — calculated from finding severity
- **Last Scan** — timestamp of most recent run
- **Security Trend** — findings over time

Run locally:
```bash
docker-compose up -d prometheus pushgateway grafana
# Open http://localhost:3000 (admin / devsecops)
```

---

## ⚡ GitHub Actions Workflows

### 1. Ansible Lint & Security Scan
Runs on every push. Lints all Ansible playbooks against security rules.

### 2. AI Security Gatekeeper
Full pipeline: Trivy → Trivy Config → KICS → Conftest → OPA Gatekeeper → AI triage → Grafana metrics → Telegram alert.

### 3. KICS Security Scan
Standalone KICS scan via Docker image. Fails on HIGH findings.

First scan results on this repo:
```
HIGH: 2 | MEDIUM: 19 | LOW: 22 | TOTAL: 46
After fixes:
HIGH: 0 | MEDIUM: 10 | LOW: 14 | TOTAL: 25
```

---

## 🤖 AI Security Triage

Instead of summarizing finding counts, the AI receives actual findings — source, severity, file path, and description — and returns a prioritized list explaining the real-world risk behind each one.

Example output:
```
1. Shared Service Account (deployment.yaml)
   — privilege escalation and unauthorized access risk
2. Container Running With Low UID (deployment.yaml)
   — conflicts with host's user table, elevated privileges
3. Container Capabilities Unrestricted
   — reduces attack surface if dropped
```

---

## 📖 LinkedIn Series (16 Parts)

| Part | Topic |
|------|-------|
| Part 1-11 | [Full series on LinkedIn](https://www.linkedin.com/in/bekbolatzhumabekov/) |
| Part 12 | KICS Multi-IaC scanning + supply chain attack discovery |
| Part 13 | Fixing HIGH findings + Unified Security Report |
| Part 14 | Contextual AI triage — from counts to prioritized findings |
| Part 15 | Policy as Code with Conftest — detective vs preventive control |
| Part 16 | Final architecture + Lessons Learned |

---

## 🚀 Quick Start

```bash
git clone https://github.com/bekbolat2700-collab/ansible-security-monitor.git
cd ansible-security-monitor

# Run KICS scan
docker run --rm \
  -v $(pwd):/path \
  checkmarx/kics:latest scan \
  -p /path \
  --report-formats json,sarif \
  -o /path/kics-results \
  --exclude-paths /path/k8s/gatekeeper \
  --fail-on HIGH

# Run Trivy scan
trivy fs . --severity HIGH,CRITICAL

# Run Policy as Code check
conftest test --policy policy/ k8s/deployment/deployment.yaml

# Start monitoring stack
docker-compose up -d prometheus pushgateway grafana
```

---

## 👤 Author

**Bekbolat** — DevSecOps Engineer from Astana 🇰🇿

- LinkedIn: [@bekbolatzhumabekov](https://www.linkedin.com/in/bekbolatzhumabekov/)
- GitHub: [@bekbolat2700-collab](https://github.com/bekbolat2700-collab)

> *"Security is a workflow, not a collection of tools."*
