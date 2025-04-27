import hashlib
import requests
from rich.console import Console

console = Console()

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  

class SHAChecker:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}
        self.base_url = "https://www.virustotal.com/api/v3/files/"

    @staticmethod
    def calculate_sha256(file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            console.print("[red][Hata][/red] Dosya bulunamadı.")
            return None

    def query_virustotal(self, sha256_hash):
        url = self.base_url + sha256_hash
        response = requests.get(url, headers=self.headers)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            console.print("[yellow]Hash VirusTotal'da bulunamadı.[/yellow]")
            return None
        else:
            console.print(f"[red]API Hatası: {response.status_code}[/red]")
            return None

if __name__ == "__main__":
    checker = SHAChecker(API_KEY)
    file_path = input("Analiz edilecek dosya yolu: ")
    sha256 = checker.calculate_sha256(file_path)
    
    if sha256:
        console.print(f"[green]SHA256:[/green] {sha256}")
        vt_result = checker.query_virustotal(sha256)
        if vt_result:
            console.print_json(data=vt_result)
