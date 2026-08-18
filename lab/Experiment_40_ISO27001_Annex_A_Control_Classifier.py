def classify_iso27001_control(description, rules):
    text = description.lower()
    for domain, keywords in rules:
        for kw in keywords:
            if kw in text:
                return domain
    return "Unmapped Control"


ISO27001_RULES = [
    (
        "A.5 Information Security Policies",
        [
            "security policy document was approved by management",
            "information security policy statement",
        ],
    ),
    (
        "A.6 Organization of Information Security",
        [
            "segregation of duties between roles",
            "defined security roles and responsibilities",
        ],
    ),
    (
        "A.8 Asset Management",
        [
            "asset inventory is maintained",
            "classification of information assets",
        ],
    ),
    (
        "A.9 Access Control",
        [
            "least privilege access",
            "periodic user access review",
            "role-based access control policy",
        ],
    ),
    (
        "A.12 Operations Security",
        [
            "malware protection software is deployed",
            "regular backup procedure is followed",
            "logging and monitoring of system events",
        ],
    ),
    (
        "A.16 Information Security Incident Management",
        [
            "documented incident response procedure",
            "process for reporting security incidents",
        ],
    ),
    (
        "A.17 Business Continuity Management",
        [
            "business continuity plan is tested annually",
            "disaster recovery plan",
        ],
    ),
]


# Test Cases
def test_experiment40():
    d1 = (
        "The organization maintains a documented incident response procedure."
    )
    assert classify_iso27001_control(d1, ISO27001_RULES) == (
        "A.16 Information Security Incident Management"
    )
    d2 = "Access is governed by a role-based access control policy."
    assert classify_iso27001_control(d2, ISO27001_RULES) == "A.9 Access Control"
    d3 = "A disaster recovery plan is reviewed every year."
    assert classify_iso27001_control(d3, ISO27001_RULES) == (
        "A.17 Business Continuity Management"
    )
    d4 = "An asset inventory is maintained for all company laptops."
    assert classify_iso27001_control(d4, ISO27001_RULES) == "A.8 Asset Management"
    d5 = "The company installed new office furniture."
    assert classify_iso27001_control(d5, ISO27001_RULES) == "Unmapped Control"
    print("Experiment 40: All test cases passed.")


test_experiment40()
