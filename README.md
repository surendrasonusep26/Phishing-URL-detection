# 🛡️ Phishing URL Detection System

An **AI-powered phishing detection tool** that combines **machine learning**, **web analysis**, and **vision-based AI** to identify and evaluate potentially malicious websites.

---

## 🔍 Overview

This system analyzes URLs through multiple layers of intelligence:

* **URL Structure Analysis** – Detects suspicious patterns and domains.
* **SSL Inspection** – Validates encryption and checks certificate age.
* **HTML Content Analysis** – Scans for phishing keywords, forms, and hidden elements.
* **Machine Learning (ML)** – Predicts phishing likelihood from URL features.
* **Visual AI (Ollama Llava)** – Examines screenshots for fake layouts or logos.
* **Web Reputation Check** – Provides domain safety recommendations.

---

## ⚙️ Features

* 🧠 AI & ML-based phishing detection
* 🔒 SSL verification and domain inspection
* 🌐 Automatic HTML scanning
* 📸 Screenshot capture with visual AI analysis
* 🧶 JSON report generation
* ⚡ Runs locally with optional GPU acceleration

---

## 🧮 Installation

### 1️⃣ Install dependencies:

```bash
pip install requests beautifulsoup4 selenium scikit-learn pillow numpy pandas ollama webdriver-manager
```

### 2️⃣ Install Ollama:

* Download from [https://ollama.ai](https://ollama.ai)
* Pull the Llava model:

```bash
ollama pull llava:7b
```

### 3️⃣ Make sure Ollama is running before starting the script.

---

## 🚀 Usage

Run the main script:

```bash
python phishing_detector.py
```

Enter any URL when prompted:

```
🔗 Enter URL to analyze: https://example.com
```

The tool performs all checks, displays a risk report, and offers to save the analysis as a `.json` file.

---

## 📊 Output Example

```
🔴 PHISHING DETECTED
⚠️ Risk Score: 82/100

Findings:
- 🚨 IP address used instead of domain
- ⚠️ Suspicious keywords: verify, login, account
- 🤖 ML Model: High phishing probability (94%)
- 🚨 No HTTPS encryption
```

---

## 🤩 Tech Stack

* **Python 3.9+**
* **Libraries:** Requests, BeautifulSoup4, Selenium, Scikit-learn, Pillow, Numpy
* **AI Model:** Ollama Llava
* **Browser Driver:** Chrome WebDriver (via webdriver-manager)

---

## 🧑‍💻 Author

**AI Security Tool**
Built for cybersecurity learning and awareness.

---

## ⚠️ Disclaimer

This project is for **educational and research purposes only**.
Do not use it for unauthorized scanning or malicious activities.

---
