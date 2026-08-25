"""
Experiment 36: Compliance Framework Mapper (PCI-DSS, HIPAA, GDPR, SOX)
"""

FRAMEWORK_RULES = [
    ("PCI-DSS", ["credit card", "cardholder data", "primary account number", "cardholder pan", "cvv", "payment card transaction"]),
    ("HIPAA", ["protected health information", "phi", "patient record", "electronic health record", "ehr"]),
    ("GDPR", ["eu resident personal data", "right to be forgotten", "data subject access request", "gdpr"]),
    ("SOX", ["financial reporting controls", "public company accounting", "quarterly earnings audit"]),
]

def map_compliance(system_desc, rules=FRAMEWORK_RULES):
    text = system_desc.lower()
    for framework, keywords in rules:
        if any(kw in text for kw in keywords):
            return framework
    return "General Baseline Compliance"

# Test Cases
def test_exp36():
    assert map_compliance("System stores cardholder data and credit card transactions.") == "PCI-DSS"
    assert map_compliance("Database holds patient record and electronic health record data.") == "HIPAA"
    assert map_compliance("App handles EU resident personal data and right to be forgotten requests.") == "GDPR"
    assert map_compliance("Audit covers public company accounting and financial reporting controls.") == "SOX"
    print("Experiment 36: All test cases passed.")

if __name__ == "__main__":
    print("Compliance Standard:", map_compliance("Processing customer credit card payments online."))
    test_exp36()
