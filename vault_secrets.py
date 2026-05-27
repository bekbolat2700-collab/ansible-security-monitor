import os
import requests

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "root")

def get_secrets():
    url = f"{VAULT_ADDR}/v1/secret/data/security-monitor"
    headers = {"X-Vault-Token": VAULT_TOKEN}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()["data"]["data"]
        print("✅ Secrets loaded from Vault!")
        print(f"GROQ_API_KEY: {data['groq_api_key'][:10]}...")
        print(f"TELEGRAM_TOKEN: {data['telegram_token'][:10]}...")
        print(f"TELEGRAM_CHAT_ID: {data['telegram_chat_id']}")
        return data
    else:
        print(f"❌ Error: {response.status_code}")
        return None

if __name__ == "__main__":
    get_secrets()
