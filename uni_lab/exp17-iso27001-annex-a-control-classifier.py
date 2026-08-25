"""
Experiment 17: ISO/IEC 27001 Annex A Control Domain Classifier
"""

ISO_RULES = [
    ("A.5 Information Security Policies", ["security policy", "policy statement", "management review of policies"]),
    ("A.6 Organization of Security", ["segregation of duties", "roles and responsibilities", "security organization"]),
    ("A.8 Asset Management", ["asset inventory", "asset classification", "media handling", "device tracking"]),
    ("A.9 Access Control", ["user access review", "least privilege", "password policy", "role-based access"]),
    ("A.12 Operations Security", ["malware protection", "backup management", "logging and monitoring", "vulnerability management"]),
    ("A.16 Incident Management", ["incident response procedure", "reporting security incidents", "incident evidence"]),
    ("A.17 Business Continuity", ["disaster recovery", "business continuity plan", "bcp testing"]),
]

def classify_iso_control(control_desc, rules=ISO_RULES):
    text = control_desc.lower()
    for domain, keywords in rules:
        if any(kw in text for kw in keywords):
            return domain
    return "Unmapped Control"

# Test Cases
def test_exp17():
    assert classify_iso_control("Perform periodic user access review under least privilege.") == "A.9 Access Control"
    assert classify_iso_control("Maintain an accurate asset inventory of all hardware devices.") == "A.8 Asset Management"
    assert classify_iso_control("Annual disaster recovery plan drill and testing.") == "A.17 Business Continuity"
    print("Experiment 17: All test cases passed.")

if __name__ == "__main__":
    print("Domain:", classify_iso_control("Deploy anti-malware protection and maintain daily backup management."))
    test_exp17()
