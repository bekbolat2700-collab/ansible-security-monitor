import os
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

# Load secrets
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

def ask_groq(vulnerability_text):
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
                "content": "You are a DevSecOps expert. Give short, actionable fix instructions for security vulnerabilities. Max 3 sentences."
            },
            {
                "role": "user",
                "content": f"Critical vulnerability found:\n{vulnerability_text}\nHow to fix it quickly?"
            }
        ]
    }
    response = requests.post(url, headers=headers, json=payload)
    return response.json()["choices"][0]["message"]["content"]

def send_telegram(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    r = requests.post(url, json=payload)
    print("Telegram response:", r.json())

def main(trivy_output):
    if "HIGH" in trivy_output or "CRITICAL" in trivy_output:
        ai_advice = ask_groq(trivy_output)
        message = f"🚨 *Security Alert*\n\n*AI Advice:*\n{ai_advice}"
        send_telegram(message)
        print("Alert sent to Telegram!")
    else:
        print("No critical vulnerabilities found.")

if __name__ == "__main__":
    # Тест
    test_output = "CRITICAL CVE-2023-1234 openssl 3.0.1 - Buffer overflow vulnerability"
    main(test_output)
