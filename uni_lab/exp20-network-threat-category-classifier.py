"""
Experiment 20: Plain-Language Network Threat Category Classifier
Classifies descriptions into Phishing, DoS/DDoS, Malware, or Man-in-the-Middle.
"""

NETWORK_THREAT_RULES = [
    ("Phishing", ["fake email", "credential harvesting page", "impersonating bank", "malicious link in email"]),
    ("DoS/DDoS", ["flood of syn packets", "traffic saturation", "server overwhelmed", "distributed denial of service", "high volumetric request"]),
    ("Malware", ["ransomware encryption", "keylogger installed", "trojan horse backdoor", "worm spreading"]),
    ("Man-in-the-Middle", ["arp poisoning", "ssl stripping", "intercepting unencrypted traffic", "eavesdropping on session"]),
]

def classify_network_threat(description, rules=NETWORK_THREAT_RULES):
    text = description.lower()
    for cat, keywords in rules:
        if any(kw in text for kw in keywords):
            return cat
    return "Unknown Threat"

# Test Cases
def test_exp20():
    assert classify_network_threat("Attackers launched a flood of SYN packets causing server overwhelmed condition.") == "DoS/DDoS"
    assert classify_network_threat("User clicked fake email leading to credential harvesting page.") == "Phishing"
    assert classify_network_threat("Attacker performed ARP poisoning to perform eavesdropping on session data.") == "Man-in-the-Middle"
    assert classify_network_threat("System infected with keylogger installed via macro attachment.") == "Malware"
    print("Experiment 20: All test cases passed.")

if __name__ == "__main__":
    print("Threat Category:", classify_network_threat("High volumetric request traffic saturation detected."))
    test_exp20()
