import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import argparse
from core.hash_calculator import HashCalculator
from core.virustotal_checker import VirusTotalChecker
from core.language_detector import LanguageDetector
from core.encryption_detector import EncryptionDetector
from core.report_generator import ReportGenerator
from core.html_report_generator import HTMLReportGenerator
from rich.console import Console
from rich.panel import Panel
from datetime import datetime

console = Console()

def analyze_file(file_path, vt_checker, language_detector, encryption_detector):
    report_data = {}

    console.print(f"\n{'─'*30} Analiz Başladı: {file_path} {'─'*30}\n", style="bold blue")

    # SHA256 Hesaplama
    sha256 = HashCalculator.calculate_sha256(file_path)
    report_data["sha256"] = sha256
    console.print(Panel(f"[yellow]✓ Dosyanın SHA256 Hash'i hesaplandı[/yellow]", border_style="yellow"))
    console.print(Panel(f"[cyan]SHA256:\n{sha256}[/cyan]", border_style="cyan"))

    # VirusTotal Sorgulama
    console.print("\n    [bold green]VirusTotal Analiz[/bold green]")
    vt_result = vt_checker.check_file(sha256)
    report_data["virustotal"] = vt_result

    stats = vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    timeout = stats.get('timeout', 0)

    console.print(f"    Zararlı: [red]{malicious}[/red] | Şüpheli: [yellow]{suspicious}[/yellow] | Temiz: [green]{harmless}[/green] | Tespit Edilmedi: {undetected} | Timeout: {timeout}")

    reputation = vt_result.get('data', {}).get('attributes', {}).get('reputation', 0)
    console.print(Panel(f"[magenta]Reputation Skoru: {reputation}[/magenta]", border_style="magenta"))

    # Programlama Dili Algılama
    language = language_detector.detect_language(file_path)
    report_data["language_detection"] = language

    console.print(Panel(f"[cyan]Dosya Türü ve Olası Dil:\n{language}[/cyan]", border_style="cyan"))

    # Şifreleme / Packing Analizi
    enc_result = encryption_detector.analyze_file(file_path)
    report_data["encryption_detection"] = enc_result

    if enc_result:
        console.print(Panel(f"[blue]Ortalama Entropi: {enc_result.get('average_entropy', 0):.2f}[/blue]", border_style="blue"))
        if enc_result.get("packed_suspected", False):
            console.print("[bold red]⚠️ Dosya şifrelenmiş veya packed olabilir![/bold red]")
        else:
            console.print("[bold green]✓ Dosya şifrelenmemiş gibi görünüyor.[/bold green]")

    return report_data

def main():
    parser = argparse.ArgumentParser(description="CodeIntelX Yazılım Analiz Aracı")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Analiz edilecek dosya yolu")
    group.add_argument("-d", "--directory", help="Analiz edilecek klasör yolu")
    args = parser.parse_args()

    vt_checker = VirusTotalChecker()
    language_detector = LanguageDetector()
    encryption_detector = EncryptionDetector()
    reporter = ReportGenerator()
    html_generator = HTMLReportGenerator()

    if args.file:
        files = [args.file]
    elif args.directory:
        files = []
        for root, _, filenames in os.walk(args.directory):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                files.append(file_path)

    for file_path in files:
        if not os.path.isfile(file_path):
            console.print(f"[red]Dosya bulunamadı:[/red] {file_path}")
            continue

        try:
            report_data = analyze_file(file_path, vt_checker, language_detector, encryption_detector)

            filename_base = os.path.basename(file_path).split('.')[0]

            # JSON raporu kaydet
            report_path = reporter.save_report(report_data, filename_base)
            console.print(Panel(f"[green]✓ JSON raporu oluşturuldu: {report_path}[/green]", border_style="green"))

            # HTML raporu kaydet
            html_report_path = html_generator.save_html_report(report_data, filename_base)
            console.print(Panel(f"[cyan]✓ HTML raporu oluşturuldu: {html_report_path}[/cyan]", border_style="blue"))

        except Exception as e:
            console.print(Panel(f"[red]Analiz sırasında hata oluştu: {e}[/red]", border_style="red"))

    console.print(f"\n{'─'*30} Tüm Analizler Tamamlandı {'─'*30}\n", style="bold green")

if __name__ == "__main__":
    main()
