# 🎣 RedPhish

![Python](https://img.shields.io/badge/Python-3.7+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**Advanced Phishing Detection & URL Analyzer** — Detect phishing URLs, suspicious emails, and credential harvesting attempts using multi-layered heuristic analysis.

## 🔥 Features

- 🔗 **URL Analysis** — Extract 25+ features from any URL including entropy, homoglyphs, punycode, brand impersonation
- 📧 **Email Header Analysis** — SPF/DKIM/DMARC verification, sender mismatch detection, urgency keyword flagging
- 🎯 **Brand Impersonation Detection** — Identifies spoofed domains targeting 20+ major brands
- 🌐 **Homoglyph Detection** — Catches visual lookalike characters used in domain spoofing
- 📊 **Risk Scoring** — 0-100 risk score with color-coded terminal output
- 📦 **Batch Processing** — Analyze hundreds of URLs from a file with CSV/JSON export
- 🖥️ **Beautiful CLI** — Rich colored output with ASCII art banner

## 📸 Preview

```
    ██████╗ ███████╗██████╗ ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗
    ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║  ██║██║██╔════╝██║  ██║
    ██████╔╝█████╗  ██║  ██║██████╔╝███████║██║███████╗███████║
    ██╔══██╗██╔══╝  ██║  ██║██╔═══╝ ██╔══██║██║╚════██║██╔══██║
    ██║  ██║███████╗██████╔╝██║     ██║  ██║██║███████║██║  ██║
    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝

  Target:  http://paypa1-secure.login-verify.tk/account/signin
  Risk Level:  HIGH RISK
  Score:      ██████████████████████████████░░ 90/100

  ⚠  No HTTPS — connection is not encrypted
  ⚠  Possible impersonation of 'paypal'
  ⚠  Suspicious TLD commonly used in phishing campaigns
  ⚠  URL path contains login/authentication keywords
```

## 🚀 Installation

```bash
git clone https://github.com/redX000/RedPhish.git
cd RedPhish
pip install -e .
```

Or run directly:
```bash
python -m redphish
```

## 📖 Usage

### Analyze a URL
```bash
redphish url "http://paypa1-secure.login-verify.tk/signin"
redphish url "https://google.com" -v          # verbose mode
redphish url "http://192.168.1.1/login" --json # JSON output
```

### Batch Analysis
```bash
# Create a file with URLs (one per line)
redphish batch urls.txt
redphish batch urls.txt -o results.csv
redphish batch urls.txt -o results.json
```

### Email Header Analysis
```bash
redphish email suspicious_email.eml
redphish email phishing.eml --json
```

## 🧠 Detection Methods

| Method | Description |
|--------|-------------|
| URL Entropy | Shannon entropy to detect randomly generated domains |
| Homoglyph Detection | Unicode lookalike characters (а vs a, 0 vs o) |
| Punycode Analysis | Internationalized domain name abuse |
| Brand Impersonation | Domain matching against 20+ targeted brands |
| TLD Reputation | Flags TLDs commonly abused in phishing (.tk, .ml, etc.) |
| Path Analysis | Login/verification keyword detection in URL paths |
| IP-based URLs | Direct IP address usage instead of domain names |
| SPF/DKIM/DMARC | Email authentication protocol verification |
| Sender Mismatch | From vs Return-Path domain comparison |
| Urgency Keywords | Fear/urgency language in email subjects |

## 📋 Risk Score Breakdown

| Score | Level | Description |
|-------|-------|-------------|
| 0-19 | ✅ SAFE | No significant phishing indicators |
| 20-39 | 🟡 LOW RISK | Minor suspicious elements detected |
| 40-69 | 🟠 MEDIUM RISK | Multiple phishing indicators present |
| 70-100 | 🔴 HIGH RISK | Strong phishing indicators — likely malicious |

## ⚠️ Disclaimer

This tool is designed for **educational purposes and legitimate security research only**. Use responsibly and in compliance with applicable laws. The author is not responsible for any misuse of this tool.

## 📄 License

MIT License — see [LICENSE](LICENSE)

## 👤 Author

**Yassine Lasraoui** — [@redX000](https://github.com/redX000)
