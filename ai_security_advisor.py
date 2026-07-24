import os
import json
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

def parse_trivy_report(path="trivy-report.json"):
    high, critical = 0, 0
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
    except Exception as e:
        print(f"⚠️ Trivy parse error: {e}")
    return high, critical

def parse_kics_report(path="kics-results/results.json"):
    high, medium, low = 0, 0, 0
    try:
        with open(path) as f:
            data = json.load(f)
        for query in data.get("queries", []):
            sev = query.get("severity", "").upper()
            count = len(query.get("files", []))
            if sev == "HIGH":
                high += count
            elif sev == "MEDIUM":
                medium += count
            elif sev == "LOW":
                low += count
    except Exception as e:
        print(f"⚠️ KICS parse error: {e}")
    return high, medium, low

def parse_tfsec_output():
    high, medium = 0, 0
    tfsec_output = os.getenv("TFSEC_OUTPUT", "")
    for line in tfsec_output.splitlines():
        if "HIGH" in line:
            high += 1
        elif "MEDIUM" in line:
            medium += 1
    return high, medium

def ask_groq(summary_text):
    if not GROQ_API_KEY:
        return "AI advice unavailable — no API key."
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
                "content": "You are a DevSecOps expert. Give short, actionable fix priority for these findings. Max 3 sentences."
            },
            {
                "role": "user",
                "content": f"Security scan results:\n{summary_text}\nWhat should be fixed first?"
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
    trivy_high, trivy_critical = parse_trivy_report()
    kics_high, kics_medium, kics_low = parse_kics_report()
    tfsec_high, tfsec_medium = parse_tfsec_output()

    total_high = trivy_high + trivy_critical + kics_high + tfsec_high
    total_medium = kics_medium + tfsec_medium

    status = "❌ FAILED" if total_high > 0 else "✅ PASSED"

    summary = (
        f"*🛡️ Unified Security Report*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔍 *Trivy*\n"
        f"  CRITICAL: {trivy_critical} | HIGH: {trivy_high}\n\n"
        f"🔍 *tfsec*\n"
        f"  HIGH: {tfsec_high} | MEDIUM: {tfsec_medium}\n\n"
        f"🔍 *KICS*\n"
        f"  HIGH: {kics_high} | MEDIUM: {kics_medium} | LOW: {kics_low}\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🚨 *Total HIGH+CRITICAL: {total_high}*\n"
        f"⚠️ *Total MEDIUM: {total_medium}*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"*Status: {status}*\n"
    )

    if total_high > 0 or total_medium > 0:
        ai_advice = ask_groq(summary)
        summary += f"\n🤖 *AI Advice:*\n{ai_advice}"

    print(summary)
    send_telegram(summary)

    if total_high > 0:
        exit(1)

if __name__ == "__main__":
    main()
