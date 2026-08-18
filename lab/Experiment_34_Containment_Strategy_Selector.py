def recommend_containment(incident_description, rules):
    text = incident_description.lower()
    for strategy, keywords in rules:
        for kw in keywords:
            if kw in text:
                return strategy
    return "Escalate to Senior Analyst for Manual Review"


CONTAINMENT_RULES = [
    (
        "Isolate Host from Network",
        [
            "ransomware encrypting files",
            "worm actively spreading",
            "active malware execution detected",
        ],
    ),
    (
        "Block Malicious IP/Domain at Firewall",
        [
            "command-and-control communication observed",
            "large outbound data transfer to external server",
            "beaconing to a known malicious domain",
        ],
    ),
    (
        "Disable Compromised User Account",
        [
            "compromised credentials used to log in",
            "account takeover suspected",
            "unauthorized login from a foreign country",
        ],
    ),
    (
        "Segment Network / Restrict VLAN Access",
        [
            "lateral movement between internal hosts",
            "internal network scanning detected",
        ],
    ),
    (
        "Revoke Access Tokens / API Keys",
        [
            "leaked api key found in a public repository",
            "exposed access token discovered",
        ],
    ),
]


# Test Cases
def test_experiment34():
    d1 = "Ransomware encrypting files was found on three workstations."
    assert recommend_containment(d1, CONTAINMENT_RULES) == "Isolate Host from Network"
    d2 = "The SOC observed beaconing to a known malicious domain every 60 seconds."
    assert recommend_containment(d2, CONTAINMENT_RULES) == "Block Malicious IP/Domain at Firewall"
    d3 = "Logs show an unauthorized login from a foreign country using valid credentials."
    assert recommend_containment(d3, CONTAINMENT_RULES) == "Disable Compromised User Account"
    d4 = "Internal network scanning detected originating from a marketing workstation."
    assert recommend_containment(d4, CONTAINMENT_RULES) == "Segment Network / Restrict VLAN Access"
    d5 = "An exposed access token discovered in a public GitHub commit."
    assert recommend_containment(d5, CONTAINMENT_RULES) == "Revoke Access Tokens / API Keys"
    d6 = "A user reported a slow laptop."
    assert recommend_containment(d6, CONTAINMENT_RULES) == "Escalate to Senior Analyst for Manual Review"
    print("Experiment 34: All test cases passed.")


test_experiment34()
