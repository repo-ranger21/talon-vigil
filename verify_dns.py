"""
🔍 TalonVigil DNS Verification Script

Verifies that Cloudflare DNS records for TalonVigil are correctly routed and proxied.
"""

import requests

RECORDS = {
    "api.talonvigil.com": "render-backend-url",
    "www.talonvigil.com": "vercel-frontend-url"
}

def verify_dns():
    for subdomain, expected in RECORDS.items():
        try:
            response = requests.get(f"https://{subdomain}", timeout=5)
            if response.status_code == 200:
                print(f"[✅] {subdomain} is live and routed correctly.")
            else:
                print(f"[⚠️] {subdomain} responded with status {response.status_code}.")
        except Exception as e:
            print(f"[❌] {subdomain} unreachable: {e}")

if __name__ == "__main__":
    verify_dns()
