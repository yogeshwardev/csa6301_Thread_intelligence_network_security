"""
Experiment 15: Incident Case Study Root-Cause Classifier
"""

ROOT_CAUSE_RULES = [
    ("Phishing / Social Engineering", ["phishing", "fake login", "tricked into giving password", "social engineering", "credential harvest"]),
    ("Unpatched Vulnerability", ["unpatched", "cve-", "known vulnerability", "outdated software", "missing security update"]),
    ("Misconfiguration", ["misconfigured", "publicly accessible", "default password", "open permissions", "storage bucket was left"]),
    ("Insider Threat", ["disgruntled employee", "unauthorized insider", "former employee access", "stolen data by staff"]),
    ("Supply-Chain Compromise", ["vendor software update", "third-party supplier", "compromised library", "supply chain partner"]),
]

def classify_root_cause(narrative, rules=ROOT_CAUSE_RULES):
    text = narrative.lower()
    for cause, keywords in rules:
        if any(kw in text for kw in keywords):
            return cause
    return "Undetermined"

# Test Cases
def test_exp15():
    assert classify_root_cause("Staff clicked phishing link and entered corporate credentials.") == "Phishing / Social Engineering"
    assert classify_root_cause("Attackers exploited a known unpatched vulnerability in the Apache server.") == "Unpatched Vulnerability"
    assert classify_root_cause("A cloud storage bucket was left publicly accessible by mistake.") == "Misconfiguration"
    assert classify_root_cause("A compromised third-party supplier update allowed backdoor access.") == "Supply-Chain Compromise"
    print("Experiment 15: All test cases passed.")

if __name__ == "__main__":
    print("Root Cause:", classify_root_cause("Disgruntled employee exfiltrated internal design docs."))
    test_exp15()
