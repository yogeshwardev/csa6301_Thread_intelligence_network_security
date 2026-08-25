"""
Experiment 39: Mini Threat Intelligence Platform (IOC Normalization & Correlation Engine)
"""

def normalize_raw_ioc(raw):
    return {
        "type": raw.get("type", "").strip().lower(),
        "value": raw.get("value", "").strip().lower(),
        "source": raw.get("source", "unknown"),
        "severity": raw.get("severity", "medium").lower()
    }

def correlate_tip_with_logs(tip_db, internal_logs):
    ioc_ips = {i["value"] for i in tip_db if i["type"] == "ip"}
    ioc_domains = {i["value"] for i in tip_db if i["type"] == "domain"}

    alerts = []
    for log in internal_logs:
        src = log.get("src_ip", "").lower()
        dst = log.get("dst_domain", "").lower()
        if src in ioc_ips or dst in ioc_domains:
            alerts.append({"alert": "Threat Feed Match", "log": log})
    return alerts

# Test Cases
def test_exp39():
    feed = [
        {"type": "IP", "value": " 45.33.32.156 ", "source": "MISP", "severity": "High"},
        {"type": "Domain", "value": "MALICIOUS-SITE.COM", "source": "VirusTotal", "severity": "Critical"},
    ]
    tip_db = [normalize_raw_ioc(r) for r in feed]
    assert tip_db[0]["value"] == "45.33.32.156"
    assert tip_db[1]["value"] == "malicious-site.com"

    logs = [
        {"src_ip": "45.33.32.156", "action": "outbound_connect"},
        {"src_ip": "10.0.0.1", "action": "outbound_connect"},
    ]
    alerts = correlate_tip_with_logs(tip_db, logs)
    assert len(alerts) == 1
    assert alerts[0]["log"]["src_ip"] == "45.33.32.156"
    print("Experiment 39: All test cases passed.")

if __name__ == "__main__":
    feed = [{"type": "ip", "value": "198.51.100.1"}]
    tip = [normalize_raw_ioc(f) for f in feed]
    print("Correlation Alert:", correlate_tip_with_logs(tip, [{"src_ip": "198.51.100.1"}]))
    test_exp39()
