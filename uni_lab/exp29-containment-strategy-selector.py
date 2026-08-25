"""
Experiment 29: Incident Containment Strategy Selector
"""

CONTAINMENT_RULES = [
    ("Host Network Isolation", ["ransomware encrypting", "worm spreading", "active payload execution"]),
    ("Firewall Perimeter Block", ["c2 beaconing observed", "exfiltration to foreign ip", "malicious domain connection"]),
    ("Account Disablement & Password Reset", ["compromised credentials", "account takeover", "unauthorized foreign login"]),
    ("VLAN / Network Subnet Isolation", ["lateral movement detected", "internal port scanning"]),
    ("API Key / Token Revocation", ["leaked api key", "exposed access token", "github secret leak"]),
]

def select_containment_action(incident_description, rules=CONTAINMENT_RULES):
    text = incident_description.lower()
    for action, keywords in rules:
        if any(kw in text for kw in keywords):
            return action
    return "Escalate for Manual Incident Review"

# Test Cases
def test_exp29():
    assert select_containment_action("Active ransomware encrypting files on accounting workstation.") == "Host Network Isolation"
    assert select_containment_action("SOC observed C2 beaconing observed to external threat actor IP.") == "Firewall Perimeter Block"
    assert select_containment_action("Discovered exposed access token in public repository.") == "API Key / Token Revocation"
    print("Experiment 29: All test cases passed.")

if __name__ == "__main__":
    print("Strategy:", select_containment_action("Lateral movement detected across internal subnets."))
    test_exp29()
