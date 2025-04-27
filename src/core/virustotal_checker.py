import requests
import json
import os

class VirusTotalChecker:
    def __init__(self):
        self.api_key = self.load_api_key()
        self.base_url = "https://www.virustotal.com/api/v3"

    def load_api_key(self):
        settings_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config", "settings.json"))
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                settings = json.load(f)
                return settings.get("VIRUSTOTAL_API_KEY", "")
        except Exception as e:
            print(f"[!] API anahtarı yüklenirken hata oluştu: {e}")
            return ""

    def check_file(self, sha256_hash):
        headers = {
            "x-apikey": self.api_key
        }
        url = f"{self.base_url}/files/{sha256_hash}"

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"[!] VirusTotal isteği başarısız: {response.status_code}")
            return {}
