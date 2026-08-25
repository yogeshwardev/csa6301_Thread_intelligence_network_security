"""
Experiment 12: SOC Alert Triage Prioritizer
Assigns P1-P4 priority levels based on alert indicators.
"""

PRIORITY_RULES = [
    ("P1 - Critical", ["ransomware", "active data exfiltration", "domain admin compromised", "critical infrastructure attacked"]),
    ("P2 - High", ["malware detected", "c2 beaconing", "multiple failed admin logins", "unauthorized privilege escalation"]),
    ("P3 - Medium", ["port scan detected", "unusual login location", "policy violation", "suspicious powershell execution"]),
]

def triage_soc_alert(alert_text, rules=PRIORITY_RULES):
    text = alert_text.lower()
    for priority, keywords in rules:
        if any(kw in text for kw in keywords):
            return priority
    return "P4 - Low"

# Test Cases
def test_exp12():
    a1 = "Active data exfiltration detected from the primary database cluster."
    assert triage_soc_alert(a1) == "P1 - Critical"

    a2 = "Endpoint agent alerts on C2 beaconing to a foreign IP."
    assert triage_soc_alert(a2) == "P2 - High"

    a3 = "Port scan detected targeting internal web server."
    assert triage_soc_alert(a3) == "P3 - Medium"

    a4 = "Scheduled backup job completed successfully."
    assert triage_soc_alert(a4) == "P4 - Low"
    print("Experiment 12: All test cases passed.")

if __name__ == "__main__":
    print("Priority:", triage_soc_alert("Ransomware payload executing on server"))
    test_exp12()
