"""
Experiment 6: Phishing URL Detector
Inspects URLs for suspicious indicators (IP-based domain, suspicious keywords, excessive subdomains).
"""
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "update", "banking", "signin", "paypal", "free"]

def detect_phishing_url(url):
    reasons = []
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.hostname or ""

    # Check 1: IP address used directly as hostname
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        reasons.append("IP address used as hostname")

    # Check 2: Excessive subdomains (more than 3 dots)
    if hostname.count(".") > 3:
        reasons.append("Excessive subdomains")

    # Check 3: Suspicious keywords in URL path or subdomain
    url_lower = url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found_keywords:
        reasons.append(f"Suspicious keywords detected: {found_keywords}")

    # Check 4: Hyphens in domain (common homograph / typosquat technique)
    if "-" in hostname:
        reasons.append("Hyphenated domain name")

    is_phishing = len(reasons) >= 2
    return {"url": url, "is_phishing": is_phishing, "risk_score": len(reasons), "reasons": reasons}

# Test Cases
def test_exp6():
    u1 = "http://192.168.1.100/secure-login/update/account"
    res1 = detect_phishing_url(u1)
    assert res1["is_phishing"] is True

    u2 = "https://legitimate-bank.com.verify.user.auth.evil.com/signin"
    res2 = detect_phishing_url(u2)
    assert res2["is_phishing"] is True

    u3 = "https://www.google.com/search?q=cybersecurity"
    res3 = detect_phishing_url(u3)
    assert res3["is_phishing"] is False
    print("Experiment 6: All test cases passed.")

if __name__ == "__main__":
    test_url = "http://185.220.101.5/bank-login-verify"
    print("Result:", detect_phishing_url(test_url))
    test_exp6()
