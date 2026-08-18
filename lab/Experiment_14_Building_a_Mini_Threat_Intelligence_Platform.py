def normalize_ioc(raw):
    return {
        "type": raw.get("type", "").lower(),
        "value": raw.get("value", "").strip().lower(),
        "source": raw.get("source", "unknown"),
        "severity": raw.get("severity", "medium").lower(),
    }


raw_feed = [
    {"type": "IP", "value": " 45.33.32.156 ", "source": "MISP", "severity": "High"},
    {"type": "Domain", "value": "Malicious-Site.COM", "source": "VirusTotal", "severity": "critical"},
    {"type": "Hash", "value": "5d41402abc4b2a76b9719d911017c592", "source": "AlienVault OTX", "severity": "Medium"},
]

tip_database = [normalize_ioc(r) for r in raw_feed]

internal_firewall_logs = [
    {"src_ip": "45.33.32.156", "dest": "internal-server-1", "action": "connection attempt"},
    {"src_ip": "10.0.0.5", "dest": "internal-server-2", "action": "connection attempt"},
]


def correlate_with_tip(logs, tip_db):
    ioc_ips = {i["value"] for i in tip_db if i["type"] == "ip"}
    return [
        {"alert": "Known malicious IP contacted internal system", "log": log}
        for log in logs
        if log["src_ip"] in ioc_ips
    ]


alerts = correlate_with_tip(internal_firewall_logs, tip_database)

print(f"Normalized {len(tip_database)} IOCs:")
for ioc in tip_database:
    print(" ", ioc)
print(f"Generated {len(alerts)} alert(s):", alerts)


# Test Cases
def test_experiment14():
    assert tip_database[0]["value"] == "45.33.32.156", "IOC values should be trimmed and lowercased"
    assert tip_database[1]["value"] == "malicious-site.com"
    assert tip_database[0]["type"] == "ip"
    assert len(alerts) == 1, "Exactly one firewall log should match a known malicious IP"
    assert alerts[0]["log"]["src_ip"] == "45.33.32.156"
    print("Experiment 14: All test cases passed.")


test_experiment14()
