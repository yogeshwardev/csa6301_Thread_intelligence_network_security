"""
Experiment 14: SIEM Architecture Pipeline (Collect -> Normalize -> Correlate -> Alert)
"""

def collect_events(raw_sources):
    return raw_sources

def normalize_event(e):
    return {
        "source": e.get("src", "unknown"),
        "event_type": e.get("type", "generic").lower(),
        "severity": "high" if e.get("type") in ("malware_detected", "blocked_firewall") else "low",
        "raw": e
    }

def correlate_events(normalized_list):
    return [e for e in normalized_list if e["severity"] == "high"]

def raise_alerts(correlated_list):
    return [f"ALERT: {e['source']} raised high-severity event '{e['event_type']}'" for e in correlated_list]

# Test Cases
def test_exp14():
    raw_data = [
        {"src": "FW-01", "type": "blocked_firewall", "ip": "45.33.32.156"},
        {"src": "EDR-02", "type": "malware_detected", "file": "payload.exe"},
        {"src": "AUTH-01", "type": "login_success", "user": "admin"},
    ]
    norm = [normalize_event(e) for e in collect_events(raw_data)]
    corr = correlate_events(norm)
    alerts = raise_alerts(corr)

    assert len(norm) == 3
    assert len(corr) == 2
    assert len(alerts) == 2
    print("Experiment 14: All test cases passed.")

if __name__ == "__main__":
    raw = [{"src": "AV", "type": "malware_detected"}]
    print("Alerts:", raise_alerts(correlate_events([normalize_event(e) for e in raw])))
    test_exp14()
