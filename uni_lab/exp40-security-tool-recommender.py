"""
Experiment 40: IT Industry Security Tool Recommender
Matches task descriptions to standard cybersecurity tools.
"""

TOOL_CATALOG = {
    "Wireshark": ["packet capture", "packet analysis", "network traffic inspection", "pcap"],
    "Nmap": ["port scan", "network scanning", "service discovery", "open ports"],
    "Nessus": ["vulnerability scan", "cve assessment", "vulnerability management"],
    "Burp Suite": ["web application testing", "http proxy", "sql injection test", "xss intercept"],
    "Metasploit": ["penetration testing", "exploit execution", "payload generation"],
    "Splunk": ["siem log aggregation", "spl query", "log search", "soc dashboard"],
    "Snort": ["network intrusion detection", "ids signatures", "inline ips rules"],
    "VirusTotal": ["malware hash reputation", "file scanning", "multi-engine antivirus check"],
    "MISP": ["threat intelligence sharing", "ioc platform", "threat sharing community"],
}

def recommend_security_tool(task_description, catalog=TOOL_CATALOG):
    text = task_description.lower()
    scores = {}
    for tool, keywords in catalog.items():
        match_count = sum(1 for kw in keywords if kw in text)
        if match_count > 0:
            scores[tool] = match_count
    return max(scores, key=scores.get) if scores else "No Specific Tool Recommendation"

# Test Cases
def test_exp40():
    assert recommend_security_tool("Need to perform network scanning to find open ports.") == "Nmap"
    assert recommend_security_tool("Analyze packet capture pcap files from network traffic.") == "Wireshark"
    assert recommend_security_tool("Perform web application testing with an HTTP proxy.") == "Burp Suite"
    assert recommend_security_tool("Query SIEM log aggregation on the SOC dashboard.") == "Splunk"
    print("Experiment 40: All test cases passed.")

if __name__ == "__main__":
    print("Recommended Tool:", recommend_security_tool("Check file malware hash reputation."))
    test_exp40()
