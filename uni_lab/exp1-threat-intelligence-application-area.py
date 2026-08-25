"""
Experiment 1: Threat Intelligence Application Area Identifier
Identifies relevant TI application area for a given business scenario.
"""

INDUSTRY_TI_RULES = [
    ("Banking Fraud Prevention", ["bank", "atm", "credit card", "wire transfer", "financial", "account takeover"]),
    ("Healthcare Data Protection", ["hospital", "patient", "medical", "ehr", "hipaa", "health record", "clinical"]),
    ("E-commerce Fraud Prevention", ["online store", "shopping cart", "payment gateway", "checkout", "e-commerce", "retailer"]),
    ("Critical Infrastructure Defense", ["power grid", "scada", "water treatment", "utility", "ics", "nuclear"]),
    ("Telecommunications Security", ["telecom", "cellular", "5g", "sim swap", "voip", "isp", "network carrier"]),
]

def identify_ti_application(scenario_text, rules=INDUSTRY_TI_RULES):
    text = scenario_text.lower()
    for area, keywords in rules:
        if any(kw in text for kw in keywords):
            return area
    return "General Enterprise Threat Intelligence"

# Test Cases
def test_exp1():
    s1 = "A national retail bank is facing automated credential stuffing attacks against its mobile banking portal."
    assert identify_ti_application(s1) == "Banking Fraud Prevention"

    s2 = "A hospital network wants to protect electronic patient records from targeted ransomware."
    assert identify_ti_application(s2) == "Healthcare Data Protection"

    s3 = "An online shopping store wants to detect fraudulent payment gateway checkouts using stolen cards."
    assert identify_ti_application(s3) == "E-commerce Fraud Prevention"

    print("Experiment 1: All test cases passed.")

if __name__ == "__main__":
    scenario = "Regional hospital needs intelligence on threats targeting clinical EHR systems."
    print(f"Scenario: {scenario}")
    print(f"Recommended TI Area: {identify_ti_application(scenario)}")
    test_exp1()
