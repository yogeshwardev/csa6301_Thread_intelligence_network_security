"""
Experiment 5: Threat Intelligence Report Audience Classifier
Classifies threat reports as Strategic, Tactical, or Operational.
"""

AUDIENCE_RULES = [
    ("Strategic", ["board", "executive", "ciso", "risk profile", "geopolitical", "budget allocation", "long-term threat trend"]),
    ("Tactical", ["soc analyst", "ttp", "mitre att&ck", "incident response team", "detection engineer", "defense bypass", "attack pattern"]),
    ("Operational", ["threat hunter", "forensic", "ioc list", "file hash", "ip address", "c2 domain", "signature match", "specific campaign"]),
]

def classify_threat_report(report_summary, audience_desc="", rules=AUDIENCE_RULES):
    full_text = f"{report_summary} {audience_desc}".lower()
    for category, keywords in rules:
        if any(kw in full_text for kw in keywords):
            return category
    return "General Intelligence"

# Test Cases
def test_exp5():
    r1 = "Quarterly briefing for the CISO and Board on emerging geopolitical cyber risks and budget impact."
    assert classify_threat_report(r1) == "Strategic"

    r2 = "Analysis of attacker TTPs and MITRE ATT&CK techniques observed in recent ransomware operations for SOC analysts."
    assert classify_threat_report(r2) == "Tactical"

    r3 = "List of confirmed C2 IP addresses and file hash indicators associated with active malware campaign."
    assert classify_threat_report(r3) == "Operational"

    print("Experiment 5: All test cases passed.")

if __name__ == "__main__":
    desc = "Detailed list of C2 domain IOCs and file hash values for threat hunter team."
    print("Report Category:", classify_threat_report(desc))
    test_exp5()
