import os
import requests
from dotenv import load_dotenv

load_dotenv()

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
    requests.post(url, json=payload)

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
