# -*- coding: utf-8 -*-
"""
===========================================
PHISHING URL DETECTION SYSTEM
===========================================
A comprehensive AI-powered phishing detection tool using:
- Ollama (Llava model) for intelligent visual and text analysis
- Machine Learning for URL pattern detection
- Web search for reputation checking
- Screenshot analysis for visual phishing detection

Author: AI Security Tool
Requirements: See installation instructions below
===========================================
"""

# ============================================
# INSTALLATION INSTRUCTIONS
# ============================================
"""
1. Install Python packages:
   pip install requests beautifulsoup4 selenium scikit-learn pillow numpy pandas ollama webdriver-manager

2. Install Ollama:
   - Download from: https://ollama.ai
   - Pull Llava model: ollama pull llava:7b
   (You can change model name in OLLAMA_MODEL variable below)

3. Make sure Ollama is running before executing this script
"""

# ============================================
# IMPORTS
# ============================================
import requests
from bs4 import BeautifulSoup
import re
import ssl
import socket
from urllib.parse import urlparse, urljoin
import json
import time
from datetime import datetime
import base64
from io import BytesIO

# Selenium for screenshots
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# Machine Learning
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np
import pickle
import os

# Image processing
from PIL import Image

# Ollama for AI analysis
import ollama

# ============================================
# CONFIGURATION - EDIT THESE SETTINGS
# ============================================
OLLAMA_MODEL = "llava:7b"  # Change this to your preferred Llava model
                            # Options: llava:7b, llava:13b, llava:34b, llava:latest
USE_GPU = True              # Set to False if you want CPU only
SCREENSHOT_WIDTH = 1920     # Screenshot resolution
SCREENSHOT_HEIGHT = 1080
TIMEOUT = 10                # Request timeout in seconds

# ============================================
# SUSPICIOUS KEYWORDS DATABASE
# ============================================
SUSPICIOUS_KEYWORDS = [
    'verify', 'account', 'suspended', 'locked', 'urgent', 'immediate',
    'confirm', 'update', 'click here', 'act now', 'limited time',
    'security alert', 'unusual activity', 'verify identity', 'claim',
    'prize', 'winner', 'congratulations', 'reset password', 'billing',
    'payment method', 'expired', 'suspended account', 're-activate'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
    '.click', '.link', '.racing', '.party'
]

# ============================================
# PHISHING DETECTOR CLASS
# ============================================
class PhishingDetector:
    def __init__(self):
        """Initialize the phishing detector with all necessary components"""
        print("🔧 Initializing Phishing Detection System...")
        self.ml_model = None
        self.scaler = None
        self.driver = None
        self.initialize_ml_model()
        print("✅ System initialized successfully!\n")
    
    def initialize_ml_model(self):
        """
        Initialize or load the ML model for URL pattern analysis
        If no pre-trained model exists, creates a basic one
        """
        model_path = 'phishing_model.pkl'
        scaler_path = 'scaler.pkl'
        
        # Try to load existing model
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                with open(model_path, 'rb') as f:
                    self.ml_model = pickle.load(f)
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                print("📦 Loaded existing ML model")
                return
            except:
                print("⚠️  Could not load existing model, creating new one...")
        
        # Create a basic trained model with sample data
        print("🤖 Creating new ML model...")
        X_train = np.array([
            # Legitimate URLs (features: length, dots, hyphens, digits, special_chars)
            [25, 2, 0, 0, 0], [30, 2, 1, 2, 0], [20, 1, 0, 0, 0],
            [28, 2, 0, 1, 0], [22, 1, 1, 0, 0], [35, 3, 1, 3, 0],
            # Phishing URLs
            [80, 5, 8, 15, 5], [120, 7, 10, 20, 8], [95, 6, 12, 18, 6],
            [110, 8, 9, 22, 7], [150, 10, 15, 25, 10], [88, 5, 7, 16, 4]
        ])
        y_train = np.array([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1])  # 0=safe, 1=phishing
        
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_train)
        
        self.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.ml_model.fit(X_scaled, y_train)
        
        # Save the model
        with open(model_path, 'wb') as f:
            pickle.dump(self.ml_model, f)
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        print("✅ ML model created and saved")
    
    def extract_url_features(self, url):
        """
        Extract numerical features from URL for ML analysis
        Returns: [length, num_dots, num_hyphens, num_digits, num_special_chars]
        """
        length = len(url)
        num_dots = url.count('.')
        num_hyphens = url.count('-')
        num_digits = sum(c.isdigit() for c in url)
        num_special = sum(not c.isalnum() and c not in ['.', '-', ':', '/'] for c in url)
        
        return [length, num_dots, num_hyphens, num_digits, num_special]
    
    def analyze_url_structure(self, url):
        """
        Analyze URL structure for suspicious patterns
        Returns: dict with findings and risk score
        """
        findings = []
        risk_score = 0
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Check URL length
        if len(url) > 75:
            findings.append("⚠️ Very long URL (suspicious)")
            risk_score += 15
        
        # Check for IP address instead of domain
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, domain):
            findings.append("🚨 IP address used instead of domain name")
            risk_score += 25
        
        # Check for suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if url.endswith(tld):
                findings.append(f"⚠️ Suspicious TLD: {tld}")
                risk_score += 20
        
        # Check for @ symbol (can hide real domain)
        if '@' in url:
            findings.append("🚨 '@' symbol in URL (domain hiding technique)")
            risk_score += 30
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 3:
            findings.append(f"⚠️ Too many subdomains ({subdomain_count})")
            risk_score += 15
        
        # Check for suspicious characters
        if url.count('-') > 4:
            findings.append("⚠️ Excessive hyphens in URL")
            risk_score += 10
        
        # Use ML model for prediction
        try:
            features = self.extract_url_features(url)
            features_scaled = self.scaler.transform([features])
            ml_prediction = self.ml_model.predict(features_scaled)[0]
            ml_probability = self.ml_model.predict_proba(features_scaled)[0]
            
            if ml_prediction == 1:  # Phishing
                findings.append(f"🤖 ML Model: High phishing probability ({ml_probability[1]*100:.1f}%)")
                risk_score += int(ml_probability[1] * 30)
            else:
                findings.append(f"✅ ML Model: Low phishing probability ({ml_probability[1]*100:.1f}%)")
        except Exception as e:
            findings.append(f"⚠️ ML analysis error: {str(e)}")
        
        return {
            'findings': findings if findings else ["✅ No suspicious URL patterns detected"],
            'risk_score': risk_score
        }
    
    def check_ssl_certificate(self, url):
        """
        Check SSL certificate validity and age
        Returns: dict with findings and risk score
        """
        findings = []
        risk_score = 0
        
        parsed = urlparse(url)
        
        # Check if HTTPS
        if parsed.scheme != 'https':
            findings.append("🚨 No HTTPS encryption (HTTP only)")
            risk_score += 30
            return {'findings': findings, 'risk_score': risk_score}
        
        try:
            hostname = parsed.netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    findings.append("✅ Valid SSL certificate")
                    
                    # Check certificate age (new certs can be suspicious)
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    age_days = (datetime.now() - not_before).days
                    
                    if age_days < 30:
                        findings.append(f"⚠️ Very new SSL certificate ({age_days} days old)")
                        risk_score += 15
                    else:
                        findings.append(f"✅ SSL certificate age: {age_days} days")
        
        except Exception as e:
            findings.append(f"⚠️ SSL check failed: {str(e)}")
            risk_score += 20
        
        return {'findings': findings, 'risk_score': risk_score}
    
    def fetch_and_analyze_html(self, url):
        """
        Fetch HTML content and analyze for phishing indicators
        Returns: dict with HTML content, findings, and risk score
        """
        findings = []
        risk_score = 0
        html_content = ""
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=TIMEOUT, verify=True)
            html_content = response.text
            
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Check for suspicious keywords
            text_content = soup.get_text().lower()
            found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_content]
            if found_keywords:
                findings.append(f"⚠️ Suspicious keywords found: {', '.join(found_keywords[:5])}")
                risk_score += min(len(found_keywords) * 5, 25)
            
            # Check for login/password forms
            forms = soup.find_all('form')
            for form in forms:
                form_text = str(form).lower()
                if 'password' in form_text or 'login' in form_text or 'email' in form_text:
                    findings.append("🚨 Login/credential form detected")
                    risk_score += 20
                    break
            
            # Check for hidden iframes
            iframes = soup.find_all('iframe')
            hidden_iframes = [iframe for iframe in iframes if 'hidden' in str(iframe).lower()]
            if hidden_iframes:
                findings.append(f"⚠️ Hidden iframes detected ({len(hidden_iframes)})")
                risk_score += 15
            
            # Check for external links (many external links is suspicious)
            all_links = soup.find_all('a', href=True)
            external_links = [link for link in all_links 
                            if link['href'].startswith('http') 
                            and urlparse(url).netloc not in link['href']]
            
            if len(all_links) > 0:
                external_ratio = len(external_links) / len(all_links)
                if external_ratio > 0.5:
                    findings.append(f"⚠️ High external link ratio ({external_ratio*100:.0f}%)")
                    risk_score += 10
            
            # Check for missing contact information
            if not any(term in text_content for term in ['contact', 'about', 'email', 'phone']):
                findings.append("⚠️ No contact information found")
                risk_score += 10
            
            if not findings:
                findings.append("✅ No major HTML red flags detected")
        
        except requests.exceptions.SSLError:
            findings.append("🚨 SSL Certificate Error - Possible Man-in-the-Middle attack")
            risk_score += 40
        except requests.exceptions.Timeout:
            findings.append("⚠️ Request timeout")
            risk_score += 5
        except Exception as e:
            findings.append(f"⚠️ HTML fetch error: {str(e)}")
            risk_score += 10
        
        return {
            'html_content': html_content,
            'findings': findings,
            'risk_score': risk_score
        }
    
    def take_screenshot(self, url):
        """
        Take a screenshot of the webpage for visual analysis
        Returns: PIL Image object or None
        """
        try:
            print("📸 Taking screenshot...")
            
            # Setup Chrome options
            chrome_options = Options()
            chrome_options.add_argument('--headless')  # Run in background
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument(f'--window-size={SCREENSHOT_WIDTH},{SCREENSHOT_HEIGHT}')
            chrome_options.add_argument('--disable-gpu')
            
            # Initialize driver
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Navigate and capture
            self.driver.get(url)
            time.sleep(3)  # Wait for page to load
            
            # Take screenshot
            screenshot = self.driver.get_screenshot_as_png()
            image = Image.open(BytesIO(screenshot))
            
            self.driver.quit()
            print("✅ Screenshot captured")
            
            return image
        
        except Exception as e:
            print(f"⚠️ Screenshot failed: {str(e)}")
            if self.driver:
                self.driver.quit()
            return None
    
    def web_search_reputation(self, url):
        """
        Search the web for reputation information about the URL/domain
        Returns: dict with findings and risk score
        """
        findings = []
        risk_score = 0
        
        try:
            domain = urlparse(url).netloc
            
            # Simulate web search for reputation (In production, use actual search APIs)
            # For now, we'll check against common patterns
            
            findings.append("ℹ️ Web search: No automated API configured")
            findings.append("💡 Tip: Manually search for: 'is " + domain + " safe' or 'is " + domain + " phishing'")
            
            # In a production version, you would integrate:
            # - Google Safe Browsing API
            # - PhishTank API
            # - VirusTotal API
            # - WHOIS lookups
            
        except Exception as e:
            findings.append(f"⚠️ Web search error: {str(e)}")
        
        return {'findings': findings, 'risk_score': risk_score}
    
    def analyze_with_llava(self, url, screenshot, html_content, all_findings):
        """
        Use Ollama's Llava model to analyze screenshot and all collected data
        Returns: AI-generated analysis and verdict
        """
        try:
            print("🤖 Analyzing with Llava AI model...")
            
            # Prepare the prompt with all gathered information
            prompt = f"""You are a cybersecurity expert analyzing a potentially phishing website.

URL: {url}

AUTOMATED ANALYSIS FINDINGS:
{chr(10).join(all_findings)}

TASK: Based on the screenshot and the automated findings above, provide:
1. Your verdict: SAFE, SUSPICIOUS, or PHISHING
2. Risk score out of 100
3. Top 3 specific reasons for your verdict
4. Visual observations from the screenshot (logo, design, layout)
5. Final recommendation for the user

Be concise but thorough. Focus on what you SEE in the screenshot and how it relates to the findings."""

            # Convert image to base64 for Llava
            if screenshot:
                buffered = BytesIO()
                screenshot.save(buffered, format="PNG")
                img_base64 = base64.b64encode(buffered.getvalue()).decode()
                
                # Call Ollama with Llava
                response = ollama.chat(
                    model=OLLAMA_MODEL,
                    messages=[{
                        'role': 'user',
                        'content': prompt,
                        'images': [img_base64]
                    }]
                )
                
                ai_analysis = response['message']['content']
                print("✅ AI analysis complete")
                return ai_analysis
            else:
                # Fallback: text-only analysis if screenshot failed
                response = ollama.chat(
                    model=OLLAMA_MODEL,
                    messages=[{
                        'role': 'user',
                        'content': prompt + "\n\nNote: Screenshot unavailable, analyze based on findings only."
                    }]
                )
                ai_analysis = response['message']['content']
                return ai_analysis
        
        except Exception as e:
            return f"⚠️ AI analysis unavailable: {str(e)}\n\nPlease ensure Ollama is running and {OLLAMA_MODEL} model is installed.\nRun: ollama pull {OLLAMA_MODEL}"
    
    def calculate_final_risk_score(self, url_score, ssl_score, html_score, search_score):
        """
        Calculate weighted final risk score
        Returns: int (0-100)
        """
        weights = {
            'url': 0.25,
            'ssl': 0.20,
            'html': 0.35,
            'search': 0.20
        }
        
        total_score = (
            url_score * weights['url'] +
            ssl_score * weights['ssl'] +
            html_score * weights['html'] +
            search_score * weights['search']
        )
        
        return min(int(total_score), 100)
    
    def get_verdict(self, risk_score):
        """
        Convert risk score to verdict
        Returns: tuple (verdict_text, emoji)
        """
        if risk_score >= 70:
            return ("🔴 PHISHING DETECTED", "🔴")
        elif risk_score >= 40:
            return ("🟡 SUSPICIOUS", "🟡")
        else:
            return ("🟢 LIKELY SAFE", "🟢")
    
    def detect(self, url):
        """
        Main detection function - orchestrates all analysis steps
        Returns: Complete analysis report
        """
        print("=" * 70)
        print("🔍 PHISHING DETECTION ANALYSIS STARTED")
        print("=" * 70)
        print(f"🌐 Target URL: {url}\n")
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        all_findings = []
        
        # Step 1: Analyze URL Structure
        print("📊 Step 1/5: Analyzing URL structure...")
        url_analysis = self.analyze_url_structure(url)
        all_findings.extend(url_analysis['findings'])
        
        # Step 2: Check SSL Certificate
        print("🔒 Step 2/5: Checking SSL certificate...")
        ssl_analysis = self.check_ssl_certificate(url)
        all_findings.extend(ssl_analysis['findings'])
        
        # Step 3: Fetch and Analyze HTML
        print("📄 Step 3/5: Fetching and analyzing HTML content...")
        html_analysis = self.fetch_and_analyze_html(url)
        all_findings.extend(html_analysis['findings'])
        
        # Step 4: Web Reputation Search
        print("🌍 Step 4/5: Checking web reputation...")
        search_analysis = self.web_search_reputation(url)
        all_findings.extend(search_analysis['findings'])
        
        # Step 5: Screenshot and AI Analysis
        print("📸 Step 5/5: Taking screenshot and running AI analysis...")
        screenshot = self.take_screenshot(url)
        
        # Calculate preliminary risk score
        prelim_risk_score = self.calculate_final_risk_score(
            url_analysis['risk_score'],
            ssl_analysis['risk_score'],
            html_analysis['risk_score'],
            search_analysis['risk_score']
        )
        
        # Get AI analysis
        ai_analysis = self.analyze_with_llava(url, screenshot, html_analysis['html_content'], all_findings)
        
        # Generate final report
        verdict, emoji = self.get_verdict(prelim_risk_score)
        
        # Print results
        print("\n" + "=" * 70)
        print("📋 ANALYSIS COMPLETE - SECURITY REPORT")
        print("=" * 70)
        print(f"\n{verdict}")
        print(f"⚠️  Risk Score: {prelim_risk_score}/100")
        print(f"🕐 Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        print("─" * 70)
        print("📌 QUICK SUMMARY")
        print("─" * 70)
        print(f"URL: {url}")
        print(f"Verdict: {verdict}")
        print(f"Risk Level: {'HIGH' if prelim_risk_score >= 70 else 'MEDIUM' if prelim_risk_score >= 40 else 'LOW'}")
        
        print("\n" + "─" * 70)
        print("🔍 DETAILED FINDINGS")
        print("─" * 70)
        
        print("\n📊 URL Analysis:")
        for finding in url_analysis['findings']:
            print(f"  {finding}")
        
        print("\n🔒 SSL Certificate:")
        for finding in ssl_analysis['findings']:
            print(f"  {finding}")
        
        print("\n📄 HTML Content:")
        for finding in html_analysis['findings']:
            print(f"  {finding}")
        
        print("\n🌍 Web Reputation:")
        for finding in search_analysis['findings']:
            print(f"  {finding}")
        
        print("\n" + "─" * 70)
        print("🤖 AI ANALYSIS (Llava Vision Model)")
        print("─" * 70)
        print(ai_analysis)
        
        print("\n" + "=" * 70)
        print("✅ ANALYSIS COMPLETE")
        print("=" * 70)
        
        return {
            'url': url,
            'verdict': verdict,
            'risk_score': prelim_risk_score,
            'url_analysis': url_analysis,
            'ssl_analysis': ssl_analysis,
            'html_analysis': html_analysis,
            'search_analysis': search_analysis,
            'ai_analysis': ai_analysis,
            'timestamp': datetime.now().isoformat()
        }


# ============================================
# MAIN EXECUTION
# ============================================
def main():
    """Main function to run the phishing detector"""
    print("\n" + "=" * 70)
    print("🛡️  PHISHING URL DETECTION SYSTEM")
    print("=" * 70)
    print("Powered by Ollama Llava + Machine Learning + Web Analysis")
    print("=" * 70 + "\n")
    
    # Check if Ollama is running
    try:
        ollama.list()
        print("✅ Ollama connection successful")
    except:
        print("❌ ERROR: Cannot connect to Ollama!")
        print("Please make sure:")
        print("  1. Ollama is installed (https://ollama.ai)")
        print(f"  2. Ollama is running")
        print(f"  3. Model is installed: ollama pull {OLLAMA_MODEL}")
        return
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Get URL from user
    print("\n" + "─" * 70)
    url = input("🔗 Enter URL to analyze: ").strip()
    
    if not url:
        print("❌ No URL provided!")
        return
    
    # Run detection
    try:
        result = detector.detect(url)
        
        # Optional: Save report to file
        save_report = input("\n💾 Save detailed report to file? (y/n): ").strip().lower()
        if save_report == 'y':
            filename = f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"✅ Report saved to: {filename}")
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during analysis: {str(e)}")
        import traceback
        traceback.print_exc()


# ============================================
# RUN THE PROGRAM
# ============================================
if __name__ == "__main__":
    main()