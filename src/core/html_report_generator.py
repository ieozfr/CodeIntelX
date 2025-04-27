import os
from datetime import datetime
import json

class HTMLReportGenerator:
    def save_html_report(self, data, filename_base):
        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)

        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(reports_dir, f"{filename_base}_{now}.html")

        # Blacklist AV motorları
        blacklist_av = [
            "Bkav", "Cyren", "VBA32", "Antiy-AVL", "Jiangmin", "Rising",
            "Trustlook", "Trapmine", "Zillya", "Fortinet"
        ]

        vt_data = data.get('virustotal', {}).get('data', {}).get('attributes', {})
        last_analysis_results = vt_data.get('last_analysis_results', {})

        filtered_results = {
            engine: result
            for engine, result in last_analysis_results.items()
            if engine not in blacklist_av
        }

        blacklist_detections = {
            engine: result
            for engine, result in last_analysis_results.items()
            if engine in blacklist_av and result['category'] in ['malicious', 'suspicious']
        }

        # Normal motorlardan risk hesapla
        malicious_count = sum(1 for r in filtered_results.values() if r['category'] == 'malicious')
        suspicious_count = sum(1 for r in filtered_results.values() if r['category'] == 'suspicious')
        harmless_count = sum(1 for r in filtered_results.values() if r['category'] == 'harmless')
        undetected_count = sum(1 for r in filtered_results.values() if r['category'] == 'undetected')

        total_scans = malicious_count + suspicious_count + harmless_count + undetected_count
        total_risk = malicious_count + suspicious_count

        risk_ratio = (total_risk / total_scans) * 100 if total_scans > 0 else 0

        # Packing detection
        encryption_detection = data.get('encryption_detection', {})
        packed_suspected = encryption_detection.get('packed_suspected', False)

        html_content = f"""
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>CodeIntelX Analiz Raporu</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #121212;
                    color: #e0e0e0;
                    margin: 0;
                    padding: 0;
                }}
                .header {{
                    background-color: #1f1f1f;
                    color: #ffffff;
                    padding: 20px;
                    text-align: center;
                }}
                .container {{
                    padding: 20px;
                    max-width: 1200px;
                    margin: auto;
                }}
                .card {{
                    background: #1e1e1e;
                    padding: 20px;
                    margin-bottom: 20px;
                    border-radius: 10px;
                    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.5);
                }}
                .alert-red {{
                    background-color: #f44336;
                    color: white;
                    padding: 15px;
                    margin-bottom: 15px;
                    border-radius: 10px;
                    font-weight: bold;
                }}
                .alert-yellow {{
                    background-color: #ff9800;
                    color: black;
                    padding: 15px;
                    margin-bottom: 15px;
                    border-radius: 10px;
                    font-weight: bold;
                }}
                pre {{
                    background-color: #2c2c2c;
                    padding: 10px;
                    border-radius: 5px;
                    overflow-x: auto;
                }}
                canvas {{
                    max-width: 400px;
                    margin: auto;
                    display: block;
                }}
                @media (max-width: 600px) {{
                    .container {{
                        padding: 10px;
                    }}
                    canvas {{
                        max-width: 300px;
                    }}
                }}
            </style>
        </head>
        <body>

            <div class="header">
                <h1>CodeIntelX Analiz Raporu</h1>
                <p>{now}</p>
            </div>

            <div class="container">
        """

        # Eğer dosya packed şüphesi varsa alert gösterelim
        if packed_suspected:
            html_content += """
                <div class="alert-red">
                    ⚠️ Şifrelenmiş veya Packed dosya tespit edildi!
                </div>
            """

        html_content += f"""
                <div class="card">
                    <h2>SHA-256</h2>
                    <pre>{data.get('sha256', 'Yok')}</pre>
                </div>

                <div class="card">
                    <h2>VirusTotal Sonuçları (Blacklist Filtresi Uygulandı)</h2>
        """

        # Risk yüzdesine göre karar verelim
        if risk_ratio >= 10:
            html_content += f"""
                <div class="alert-red">
                    ⚠️ Yüksek Risk: Zararlı/Şüpheli oranı %{risk_ratio:.2f}
                </div>
            """
        elif 0 < risk_ratio < 10:
            html_content += f"""
                <div class="alert-yellow">
                    ⚠️ Düşük Risk: Zararlı/Şüpheli oranı %{risk_ratio:.2f}
                </div>
            """

        html_content += f"""
                    <canvas id="vtChart"></canvas>
                    <script>
                        const ctx = document.getElementById('vtChart').getContext('2d');
                        const vtChart = new Chart(ctx, {{
                            type: 'pie',
                            data: {{
                                labels: ['Zararlı', 'Şüpheli', 'Temiz', 'Tespit Edilmedi'],
                                datasets: [{{
                                    data: [{malicious_count}, {suspicious_count}, {harmless_count}, {undetected_count}],
                                    backgroundColor: [
                                        'rgba(244, 67, 54, 0.7)',
                                        'rgba(255, 193, 7, 0.7)',
                                        'rgba(76, 175, 80, 0.7)',
                                        'rgba(158, 158, 158, 0.7)'
                                    ],
                                    borderColor: [
                                        'rgba(244, 67, 54, 1)',
                                        'rgba(255, 193, 7, 1)',
                                        'rgba(76, 175, 80, 1)',
                                        'rgba(158, 158, 158, 1)'
                                    ],
                                    borderWidth: 1
                                }}]
                            }},
                            options: {{
                                responsive: true,
                                animation: {{
                                    animateScale: true
                                }},
                                plugins: {{
                                    legend: {{
                                        labels: {{
                                            color: '#e0e0e0'
                                        }}
                                    }}
                                }}
                            }}
                        }});
                    </script>
                </div>
        """

        # Eğer Blacklist AV motorları bir şey yakaladıysa gösterelim
        if blacklist_detections:
            html_content += """
                <div class="card">
                    <h2>⚠️ Blacklist AV Motorlarının Tespitleri</h2>
                    <pre>
            """
            for engine, result in blacklist_detections.items():
                html_content += f"{engine}: {result['result']}\n"

            html_content += """
                    </pre>
                </div>
            """

        html_content += f"""
                <div class="card">
                    <h2>Programlama Dili ve Dosya Türü</h2>
                    <pre>{data.get('language_detection', 'Bilinmiyor')}</pre>
                </div>

                <div class="card">
                    <h2>Şifreleme / Packing Analizi</h2>
                    <pre>{json.dumps(data.get('encryption_detection', {}), indent=4, ensure_ascii=False)}</pre>
                </div>
            </div>

        </body>
        </html>
        """

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return report_path
