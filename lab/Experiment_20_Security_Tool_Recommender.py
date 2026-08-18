tool_catalog = {
    "Wireshark": {
        "purpose": "packet analysis",
        "keywords": ["packet analysis", "packet capture", "network traffic"],
    },
    "Nmap": {
        "purpose": "network scanning",
        "keywords": ["network scanning", "open ports", "port scan"],
    },
    "Nessus": {
        "purpose": "vulnerability assessment",
        "keywords": ["vulnerability assessment", "known vulnerabilities"],
    },
    "Burp Suite": {
        "purpose": "web application testing",
        "keywords": ["web application testing", "http proxy"],
    },
    "Metasploit": {
        "purpose": "penetration testing",
        "keywords": ["penetration testing", "exploit code"],
    },
    "Splunk": {
        "purpose": "log management and SIEM",
        "keywords": ["log search", "siem dashboard"],
    },
    "ELK Stack": {
        "purpose": "log collection and visualization",
        "keywords": ["log visualization", "elasticsearch"],
    },
    "Snort": {
        "purpose": "intrusion detection",
        "keywords": ["intrusion detection"],
    },
    "VirusTotal": {
        "purpose": "malware scanning",
        "keywords": ["malware scanning", "file hash reputation"],
    },
    "MISP": {
        "purpose": "threat intelligence sharing",
        "keywords": ["threat intelligence sharing", "indicators of compromise"],
    },
}


def recommend_tool(task_description):
    task_lower = task_description.lower()
    scores = {
        tool: sum(1 for kw in info["keywords"] if kw in task_lower)
        for tool, info in tool_catalog.items()
    }
    scores = {t: s for t, s in scores.items() if s > 0}
    return max(scores, key=scores.get) if scores else None


test_tasks = [
    "We need to perform network scanning to find open ports on the target.",
    "The analyst wants to inspect packet capture data during the incident.",
    "Check the file hash reputation to see if it's known malware.",
    "Our team wants to enable threat intelligence sharing of indicators of compromise with partners.",
]

recommendations = [recommend_tool(t) for t in test_tasks]
print(list(zip(test_tasks, recommendations)))


# Test Cases
def test_experiment20():
    assert recommendations[0] == "Nmap"
    assert recommendations[1] == "Wireshark"
    assert recommendations[2] == "VirusTotal"
    assert recommendations[3] == "MISP"
    assert recommend_tool("completely unrelated text about cooking pasta") is None
    print("Experiment 20: All test cases passed.")


test_experiment20()
