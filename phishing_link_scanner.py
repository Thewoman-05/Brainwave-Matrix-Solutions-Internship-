import re
import requests
from urllib.parse import urlparse

def is_suspicious_url(url):
    """Check if a URL contains suspicious patterns"""
    suspicious_patterns = [
        r'paypal|bank|login|verify|account|secure',  # Common phishing terms
        r'[^\w.-]',  # Special characters in domain
        r'\.ru|\.cn|\.tk',  # Suspicious top-level domains (TLDs)
        r'\d{5,}',  # Long numerical subdomains
        r'@',  # Presence of '@' in URL
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

def check_url_blacklist(url):
    """Check if a URL is blacklisted using an external service"""
    blacklist_api = f"https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": "YOUR_VIRUSTOTAL_API_KEY"}  # Replace with a valid API key
    
    try:
        response = requests.post(blacklist_api, headers=headers, data={"url": url})
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0
    except requests.RequestException:
        pass  # Handle connection issues
    return False

def analyze_url(url):
    """Analyze a URL for phishing characteristics"""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    print(f"Analyzing: {url}")
    
    if is_suspicious_url(domain):
        print("⚠️ Warning: URL contains suspicious patterns!")
    
    if check_url_blacklist(url):
        print("❌ URL is blacklisted!")
    else:
        print("✅ URL appears safe.")

if __name__ == "__main__":
    test_url = input("Enter a URL to check: ")
    analyze_url(test_url)
