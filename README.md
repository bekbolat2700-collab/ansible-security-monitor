# 🛡️ Ansible Security Monitor

> A production-grade DevSecOps pipeline built from scratch — documented as a 16-part LinkedIn series.

![Ansible Lint & Security Scan](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/ansible-lint.yml/badge.svg)
![AI Security Gatekeeper](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/ai-security-gatekeeper.yml/badge.svg)
![KICS Security Scan](https://github.com/bekbolat2700-collab/ansible-security-monitor/actions/workflows/kics.yml/badge.svg)

---

## 🔍 What is this?

A real-world DevSecOps pipeline that automates security auditing across infrastructure code, containers, and Kubernetes — with AI-powered triage, Policy as Code enforcement, and a unified Grafana security dashboard.

Built and documented publicly as a 16-part LinkedIn series by [@bekbolatzhumabekov](https://www.linkedin.com/in/bekbolatzhumabekov/) 🥷🏻

---

## 🏗️ Architecture

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
│           │  (Groq / Llama 3)   │                   │
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
                  (K8s admission
                   control)
```

---

## 🚀 Quick Start

### Prerequisites
- Docker + Docker Compose
- Git

### 1. Clone the repository
```bash
git clone https://github.com/bekbolat2700-collab/ansible-security-monitor.git
cd ansible-security-monitor
```

### 2. Start the monitoring stack
```bash
docker-compose up -d prometheus pushgateway grafana
```

### 3. Run KICS security scan
```bash
docker run --rm \
  -v $(pwd):/path \
  checkmarx/kics:latest scan \
  -p /path \
  --report-formats json,sarif \
  -o /path/kics-results \
  --exclude-paths /path/k8s/gatekeeper \
  --fail-on HIGH
```

### 4. Run Trivy scan
```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Scan containers and IaC
trivy fs . --severity HIGH,CRITICAL --format json -o trivy-report.json
trivy config . --format json -o tfsec-output.txt --skip-dirs k8s/gatekeeper
```

### 5. Run Policy as Code check
```bash
# Install Conftest
wget https://github.com/open-policy-agent/conftest/releases/download/v0.56.0/conftest_0.56.0_Linux_x86_64.tar.gz
tar xzf conftest_0.56.0_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin

# Test policies
helm template k8s/helm/security-monitor > rendered-helm.yaml
conftest test --policy policy/ k8s/deployment/deployment.yaml rendered-helm.yaml
```

### 6. Generate unified security report
```bash
pip install requests python-dotenv

export GROQ_API_KEY=your_groq_api_key
export TELEGRAM_BOT_TOKEN=your_bot_token
export TELEGRAM_CHAT_ID=your_chat_id

python3 ai_security_advisor.py
```

### 7. Open Grafana Dashboard
```
http://localhost:3000
Login: admin
Password: devsecops
```

---

## 📊 Grafana Security Dashboard

The pipeline exports structured metrics to Prometheus after every scan. Grafana provides a real-time unified view:

| Panel | Description |
|-------|-------------|
| **Pipeline Status** | ✅ PASSED / ❌ FAILED |
| **Critical Findings** | Total CRITICAL severity issues |
| **HIGH Findings** | Total HIGH severity issues |
| **MEDIUM Findings** | Total MEDIUM severity issues |
| **Findings by Scanner** | Breakdown by Trivy / KICS / Trivy Config |
| **Risk Score** | 0-100% calculated from finding severity |
| **Last Scan** | Timestamp of most recent pipeline run |
| **Security Trend** | HIGH and MEDIUM findings over time |

Dashboard is stored as code in `monitoring/grafana/dashboards/` and loads automatically on startup.

---

## 🧰 Tech Stack

| Layer | Tool |
|-------|------|
| IaC & Automation | Ansible |
| Containerization | Docker |
| Orchestration | Kubernetes + Helm Charts |
| Container & IaC Scanning | Trivy |
| Multi-IaC Scanning | KICS |
| Policy as Code (CI) | Conftest + OPA |
| Policy as Code (K8s) | OPA Gatekeeper |
| Secrets Management | HashiCorp Vault |
| AI Analysis | Groq / Llama 3 |
| CI/CD | GitHub Actions |
| Metrics | Prometheus + Pushgateway |
| Dashboard | Grafana |
| Alerts | Telegram Bot |

---

## 🔒 Security Coverage

| Tool | What It Covers |
|------|---------------|
| Trivy | Container images, dependencies (CVEs), IaC misconfigurations |
| KICS | Ansible, Helm, Dockerfile, Kubernetes manifests |
| Conftest | Pre-deployment policy enforcement in CI |
| OPA Gatekeeper | Live Kubernetes admission control |
| Vault | Secrets — no hardcoded credentials in pipeline |
| Ansible Lint | Playbook quality and security rules |

---

## 🤖 AI Security Triage

The AI Security Gatekeeper receives actual findings — not just counts — and returns a prioritized list with real-world risk explanation:

```
🤖 AI Prioritized Findings:
1. Shared Service Account (deployment.yaml)
   — privilege escalation and unauthorized access risk. Fix first.
2. Container Running With Low UID (deployment.yaml)
   — conflicts with host user table, elevated privileges.
3. Container Capabilities Unrestricted
   — reduces attack surface if dropped.
```

This is closer to how a SOC analyst triages alerts — not "here are 46 findings" but "here's what's exploitable right now, and why."

---

## ⚡ GitHub Actions Workflows

### 1. Ansible Lint & Security Scan
Lints all Ansible playbooks on every push.

### 2. AI Security Gatekeeper
Full pipeline: Trivy → Trivy Config → KICS → Conftest → OPA Gatekeeper → AI triage → Prometheus metrics → Telegram alert.

### 3. KICS Security Scan
Standalone KICS scan. Fails on HIGH findings.

**First scan results on this repo:**
```
HIGH: 2 | MEDIUM: 19 | LOW: 22 | TOTAL: 46
```
**After remediation:**
```
HIGH: 0 | MEDIUM: 10 | LOW: 14 | TOTAL: 25
```

---

## 📖 LinkedIn Series (16 Parts)

| Part | Topic |
|------|-------|
| Part 1-11 | [Full series on LinkedIn](https://www.linkedin.com/in/bekbolatzhumabekov/) |
| Part 12 | KICS Multi-IaC scanning + supply chain attack discovery |
| Part 13 | Fixing HIGH findings + Unified Security Report |
| Part 14 | Contextual AI triage — from counts to prioritized findings |
| Part 15 | Policy as Code with Conftest |
| Part 16 | Final architecture + Lessons Learned + Grafana dashboard |

---

## 👤 Author

**Bekbolat** — DevSecOps Engineer from Astana 🇰🇿

- LinkedIn: [@bekbolatzhumabekov](https://www.linkedin.com/in/bekbolatzhumabekov/)
- GitHub: [@bekbolat2700-collab](https://github.com/bekbolat2700-collab)

> *"Security is a workflow, not a collection of tools."*
