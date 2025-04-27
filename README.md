# CodeIntelX

🚀 CodeIntelX is an open-source professional tool to perform static analysis on executable files.

It provides:
- VirusTotal threat checking with smart risk evaluation
- Blacklist antivirus filtering (no false positives)
- Programming language detection
- Packing/encryption detection
- JSON and HTML report generation
- Dark Mode and responsive stylish HTML reports

---

## 🌍 Multi-language README (EN / TR)

---

## 📖 Project Description (EN)

CodeIntelX analyzes executable files by calculating SHA256, querying VirusTotal with smart risk evaluation, detecting programming language based on file signature, and checking if the file is packed/encrypted.  
It produces detailed reports in JSON and stylish HTML format.

---

## 📖 Proje Tanımı (TR)

CodeIntelX, yürütülebilir dosyaları analiz ederek SHA256 hesaplar, akıllı risk değerlendirmesi ile VirusTotal sorgulaması yapar, dosya imzasına göre programlama dili tespit eder ve dosya şifreli mi değil mi kontrol eder.  
Sonuçları JSON ve şık HTML rapor formatında sunar.

---

## 🚀 Features / Özellikler

- 🔍 VirusTotal risk checking with threshold logic (%10 rule)
- ❌ Ignoring false positives from specific AV engines
- 📦 Packing/Encryption detection via entropy analysis
- 💻 Programming language detection from binary type
- 📝 Stylish, dark mode, animated HTML reporting
- 🗃️ JSON report export
- 🌐 English + Turkish bilingual support (README)

---

## ⚙️ Installation / Kurulum

```bash
git clone https://github.com/yourusername/CodeIntelX.git
cd CodeIntelX
pip install -r requirements.txt
