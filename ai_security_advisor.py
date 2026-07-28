import os
import json
import time
import requests
import requests as req

def get_vault_secrets():
    vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    vault_token = os.getenv("VAULT_TOKEN", "root")
    try:
        url = f"{vault_addr}/v1/secret/data/security-monitor"
        headers = {"X-Vault-Token": vault_token}
        response = req.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()["data"]["data"]
            print("✅ Secrets loaded from Vault!")
            return data
        else:
            print("⚠️ Vault unavailable, falling back to env vars")
            return None
    except Exception as e:
        print(f"⚠️ Vault error: {e}, falling back to env vars")
        return None

vault_secrets = get_vault_secrets()
if vault_secrets:
    GROQ_API_KEY = vault_secrets.get("groq_api_key")
    TELEGRAM_BOT_TOKEN = vault_secrets.get("telegram_token")
    TELEGRAM_CHAT_ID = vault_secrets.get("telegram_chat_id")
else:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except:
        pass
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

PUSHGATEWAY_URL = os.getenv("PUSHGATEWAY_URL", "http://localhost:9091")
SEVERITY_WEIGHT = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def parse_trivy_report(path="trivy-report.json"):
    high, critical = 0, 0
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "")
                if sev == "HIGH":
                    high += 1
                elif sev == "CRITICAL":
                    critical += 1
                if sev in ("HIGH", "CRITICAL"):
                    findings.append({
                        "source": "Trivy",
                        "severity": sev,
                        "title": vuln.get("VulnerabilityID", "Unknown CVE"),
                        "detail": vuln.get("Title", vuln.get("PkgName", ""))[:120],
                        "file": result.get("Target", "")
                    })
    except Exception as e:
        print(f"⚠️ Trivy parse error: {e}")
    return high, critical, findings

def parse_kics_report(path="kics-results/results.json"):
    high, medium, low = 0, 0, 0
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
        for query in data.get("queries", []):
            sev = query.get("severity", "").upper()
            files = query.get("files", [])
            count = len(files)
            if sev == "HIGH":
                high += count
            elif sev == "MEDIUM":
                medium += count
            elif sev == "LOW":
                low += count
            if sev in ("HIGH", "MEDIUM"):
                for file_info in files[:3]:
                    findings.append({
                        "source": "KICS",
                        "severity": sev,
                        "title": query.get("query_name", "Unknown finding"),
                        "detail": query.get("description", "")[:160],
                        "file": file_info.get("file_name", "")
                    })
    except Exception as e:
        print(f"⚠️ KICS parse error: {e}")
    return high, medium, low, findings

def parse_tfsec_output():
    high, medium = 0, 0
    findings = []
    try:
        with open("tfsec-output.txt") as f:
            data = json.load(f)
        for result in data.get("Results", []):
            for misconfig in result.get("Misconfigurations", []):
                sev = misconfig.get("Severity", "").upper()
                if sev == "HIGH":
                    high += 1
                    findings.append({
                        "source": "trivy-config",
                        "severity": "HIGH",
                        "title": misconfig.get("Title", "Unknown")[:120],
                        "detail": misconfig.get("Description", "")[:160],
                        "file": result.get("Target", "")
                    })
                elif sev == "MEDIUM":
                    medium += 1
                    findings.append({
                        "source": "trivy-config",
                        "severity": "MEDIUM",
                        "title": misconfig.get("Title", "Unknown")[:120],
                        "detail": misconfig.get("Description", "")[:160],
                        "file": result.get("Target", "")
                    })
    except Exception as e:
        print(f"⚠️ Trivy config parse error: {e}")
    return high, medium, findings

def push_metrics_to_prometheus(trivy_high, trivy_critical, tfsec_high, tfsec_medium,
                                kics_high, kics_medium, kics_low, total_high, total_medium, status):
    try:
        status_value = 0 if "PASSED" in status else 1
        metrics = (
            "# HELP security_findings_total Total findings by scanner and severity\n"
            "# TYPE security_findings_total gauge\n"
            f'security_findings_total{{scanner="trivy",severity="critical"}} {trivy_critical}\n'
            f'security_findings_total{{scanner="trivy",severity="high"}} {trivy_high}\n'
            f'security_findings_total{{scanner="trivy_config",severity="high"}} {tfsec_high}\n'
            f'security_findings_total{{scanner="trivy_config",severity="medium"}} {tfsec_medium}\n'
            f'security_findings_total{{scanner="kics",severity="high"}} {kics_high}\n'
            f'security_findings_total{{scanner="kics",severity="medium"}} {kics_medium}\n'
            f'security_findings_total{{scanner="kics",severity="low"}} {kics_low}\n'
            "# HELP security_pipeline_status Pipeline status 0=passed 1=failed\n"
            "# TYPE security_pipeline_status gauge\n"
            f"security_pipeline_status {status_value}\n"
            "# HELP security_total_high Total HIGH and CRITICAL findings\n"
            "# TYPE security_total_high gauge\n"
            f"security_total_high {total_high}\n"
            "# HELP security_total_medium Total MEDIUM findings\n"
            "# TYPE security_total_medium gauge\n"
            f"security_total_medium {total_medium}\n"
            "# HELP security_critical_total Total CRITICAL findings\n"
            "# TYPE security_critical_total gauge\n"
            f"security_critical_total {trivy_critical}\n"
            "# HELP security_last_scan_timestamp Unix timestamp of last scan\n"
            "# TYPE security_last_scan_timestamp gauge\n"
            f"security_last_scan_timestamp {int(time.time())}\n"
            "# HELP security_risk_score Overall risk score 0-100\n"
            "# TYPE security_risk_score gauge\n"
            f"security_risk_score {min(100, trivy_critical * 20 + total_high * 10 + total_medium * 3)}\n"
        )
        response = requests.post(
            f"{PUSHGATEWAY_URL}/metrics/job/devsecops_pipeline",
            data=metrics,
            headers={"Content-Type": "text/plain"}
        )
        print(f"Prometheus metrics pushed: {response.status_code}")
    except Exception as e:
        print(f"⚠️ Prometheus push error: {e}")

def build_findings_context(findings, max_items=10):
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_WEIGHT.get(f["severity"], 0),
        reverse=True
    )[:max_items]
    lines = []
    for i, f in enumerate(sorted_findings, 1):
        loc = f" ({f['file']})" if f.get("file") else ""
        detail = f" — {f['detail']}" if f.get("detail") else ""
        lines.append(f"{i}. [{f['source']}][{f['severity']}] {f['title']}{loc}{detail}")
    return "\n".join(lines)

def ask_groq_prioritized(findings_context, summary_counts):
    if not GROQ_API_KEY:
        return "AI advice unavailable — no API key."
    if not findings_context.strip():
        return "No actionable findings to prioritize."
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a DevSecOps security advisor. You receive a list of real "
                    "security findings from a CI/CD pipeline (Trivy, tfsec, KICS). "
                    "Pick the 3 most important findings to fix first, in priority order. "
                    "For each, give a one-line reason referencing the actual risk. "
                    "Format as a numbered list. Be specific and concise — max 4 sentences total."
                )
            },
            {
                "role": "user",
                "content": f"Scan summary:\n{summary_counts}\n\nFindings:\n{findings_context}\n\nWhat should be fixed first, and why?"
            }
        ]
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI advice error: {e}"

def send_telegram(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    r = requests.post(url, json=payload)
    print("Telegram response:", r.status_code)

def main():
    trivy_high, trivy_critical, trivy_findings = parse_trivy_report()
    kics_high, kics_medium, kics_low, kics_findings = parse_kics_report()
    tfsec_high, tfsec_medium, tfsec_findings = parse_tfsec_output()

    total_high = trivy_high + trivy_critical + kics_high + tfsec_high
    total_medium = kics_medium + tfsec_medium

    status = "❌ FAILED" if total_high > 0 else "✅ PASSED"

    summary_counts = (
        f"Trivy: CRITICAL {trivy_critical}, HIGH {trivy_high} | "
        f"Trivy Config: HIGH {tfsec_high}, MEDIUM {tfsec_medium} | "
        f"KICS: HIGH {kics_high}, MEDIUM {kics_medium}, LOW {kics_low}"
    )

    summary = (
        f"*🛡️ Unified Security Report*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔍 *Trivy*\n"
        f"  CRITICAL: {trivy_critical} | HIGH: {trivy_high}\n\n"
        f"🔍 *Trivy Config*\n"
        f"  HIGH: {tfsec_high} | MEDIUM: {tfsec_medium}\n\n"
        f"🔍 *KICS*\n"
        f"  HIGH: {kics_high} | MEDIUM: {kics_medium} | LOW: {kics_low}\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🚨 *Total HIGH+CRITICAL: {total_high}*\n"
        f"⚠️ *Total MEDIUM: {total_medium}*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"*Status: {status}*\n"
    )

    all_findings = trivy_findings + kics_findings + tfsec_findings

    if all_findings:
        findings_context = build_findings_context(all_findings)
        ai_advice = ask_groq_prioritized(findings_context, summary_counts)
        summary += f"\n🤖 *AI Prioritized Findings:*\n{ai_advice}"
    elif total_high > 0 or total_medium > 0:
        summary += "\n🤖 *AI Advice:* Findings detected but details unavailable."

    print(summary)
    send_telegram(summary)
    push_metrics_to_prometheus(
        trivy_high, trivy_critical, tfsec_high, tfsec_medium,
        kics_high, kics_medium, kics_low, total_high, total_medium, status
    )

    if total_high > 0:
        exit(1)

if __name__ == "__main__":
    main()
