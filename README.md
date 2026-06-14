# 🛡️ Ansible Security Monitor

> A production-grade DevSecOps pipeline built from scratch — documented as a 12-part LinkedIn series.

![Ansible Lint & Security Scan](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/ansible-lint.yml/badge.svg)
![AI Security Gatekeeper](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/ai-security-gatekeeper.yml/badge.svg)
![KICS Security Scan](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/kics.yml/badge.svg)

## 🔍 What is this?

A real-world DevSecOps pipeline that automates security auditing across infrastructure code, containers, and Kubernetes — with AI-powered analysis and instant Telegram alerts.

Built and documented publicly as a LinkedIn series by [@bekbolat2700](https://www.linkedin.com/in/bekbolatzhumabekov/) 🥷🏻

## 🧰 Tech Stack

| Layer | Tool |
|-------|------|
| IaC & Automation | Ansible |
| Containerization | Docker |
| Orchestration | Kubernetes + Helm Charts |
| Container Scanning | Trivy |
| Terraform Scanning | tfsec |
| Multi-IaC Scanning | KICS |
| Secrets Management | HashiCorp Vault |
| AI Analysis | Groq / Llama 3 |
| CI/CD | GitHub Actions |
| Monitoring | Netdata |
| Alerts | Telegram Bot |

## 🔒 Security Coverage

| Tool | What It Scans |
|------|--------------|
| Trivy | Container images & dependencies (CVEs) |
| tfsec | Terraform misconfigurations |
| KICS | Terraform + Ansible + Helm + Dockerfile + K8s |
| Vault | Secrets — no hardcoded credentials |
| Ansible Lint | Playbook quality & security rules |

## ⚡ GitHub Actions Workflows

### 1. Ansible Lint & Security Scan
Runs on every push. Lints all Ansible playbooks against security rules.

### 2. AI Security Gatekeeper
Uses Groq/Llama 3 to analyze scan results and make intelligent pass/fail decisions.

### 3. KICS Security Scan
Scans all IaC files for misconfigurations via Docker image.
First scan results: HIGH: 2 | MEDIUM: 19 | LOW: 22 | TOTAL: 46

## 📖 LinkedIn Series

| Part | Topic |
|------|-------|
| Part 1-11 | [Full series on LinkedIn](https://www.linkedin.com/in/bekbolatzhumabekov/) |
| Part 12 | KICS Multi-IaC scanning + supply chain attack |

## 🚀 Quick Start

\`\`\`bash
git clone https://github.com/bekbolat2700-collab/ansible-security-monitor.git
cd ansible-security-monitor

docker run --rm \
  -v $(pwd):/path \
  checkmarx/kics:latest scan \
  -p /path \
  --report-formats json,sarif \
  -o /path/kics-results \
  --fail-on HIGH
\`\`\`

## 👤 Author

**Bekbolat** — DevSecOps Engineer from Astana 🇰🇿

- LinkedIn: [@bekbolatzhumabekov](https://www.linkedin.com/in/bekbolatzhumabekov/)
- GitHub: [@bekbolat2700-collab](https://github.com/bekbolat2700-collab)

> *"Security isn't one tool. It's a coverage map."*
