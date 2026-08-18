def map_compliance_framework(description, rules):
    text = description.lower()
    for framework, keywords in rules:
        for kw in keywords:
            if kw in text:
                return framework
    return "No Specific Framework Identified"


COMPLIANCE_RULES = [
    (
        "PCI-DSS",
        [
            "cardholder data",
            "credit card number",
            "payment card transaction",
        ],
    ),
    (
        "HIPAA",
        [
            "patient medical record",
            "protected health information",
            "electronic health record",
        ],
    ),
    (
        "GDPR",
        [
            "personal data of eu residents",
            "right to be forgotten request",
            "data subject access request",
        ],
    ),
    (
        "SOX",
        [
            "financial reporting controls",
            "public company accounting",
            "quarterly earnings statement",
        ],
    ),
]


# Test Cases
def test_experiment39():
    d1 = "The system stores cardholder data for online transactions."
    assert map_compliance_framework(d1, COMPLIANCE_RULES) == "PCI-DSS"
    d2 = "The application manages electronic health record access for a clinic."
    assert map_compliance_framework(d2, COMPLIANCE_RULES) == "HIPAA"
    d3 = (
        "The company received a right to be forgotten request from a customer."
    )
    assert map_compliance_framework(d3, COMPLIANCE_RULES) == "GDPR"
    d4 = "The audit reviewed financial reporting controls for the fiscal year."
    assert map_compliance_framework(d4, COMPLIANCE_RULES) == "SOX"
    d5 = "The app tracks internal employee lunch preferences."
    assert (
        map_compliance_framework(d5, COMPLIANCE_RULES)
        == "No Specific Framework Identified"
    )
    print("Experiment 39: All test cases passed.")


test_experiment39()
