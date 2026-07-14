import re


def check_url(url):
    reasons = []
    if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        reasons.append("Uses raw IP address instead of domain name")
    if "@" in url:
        reasons.append("Contains '@' symbol (can hide real destination)")
    if url.count("-") > 3:
        reasons.append("Too many hyphens in domain (common phishing trick)")
    if any(k in url.lower() for k in ["login", "verify", "update", "secure"]) and "https" not in url:
        reasons.append("Suspicious keyword without HTTPS")
    return reasons


urls = [
    "https://www.google.com",
    "http://192.168.10.5/login",
    "http://paypal-verify-account.com@evil.com",
]

for u in urls:
    issues = check_url(u)
    verdict = "SUSPICIOUS" if issues else "Looks OK"
    print(f"\nURL: {u}\nVerdict: {verdict}")
    for r in issues:
        print(" -", r)
