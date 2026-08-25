"""
Experiment 30: Multi-Source SIEM Log Correlation for Brute-Force Detection
Combines Firewall, Windows Auth, and VPN logs to detect distributed brute-force.
"""

def correlate_multi_source_logs(firewall_log, windows_log, vpn_log):
    indicators = 0
    evidence = []

    if firewall_log.get("event") == "inbound_connection_rejected":
        indicators += 1
        evidence.append("Firewall rejected suspicious inbound traffic")

    if windows_log.get("event") == "account_lockout":
        indicators += 1
        evidence.append("Windows account locked after repeated auth failures")

    if vpn_log.get("failed_login_count", 0) >= 3:
        indicators += 1
        evidence.append("VPN gateway registered multiple failed logins")

    is_attack = indicators >= 2
    return {
        "brute_force_detected": is_attack,
        "indicators_count": indicators,
        "evidence": evidence
    }

# Test Cases
def test_exp30():
    fw = {"event": "inbound_connection_rejected"}
    win = {"event": "account_lockout"}
    vpn = {"failed_login_count": 5}
    res = correlate_multi_source_logs(fw, win, vpn)
    assert res["brute_force_detected"] is True
    assert res["indicators_count"] == 3

    normal = correlate_multi_source_logs({}, {}, {"failed_login_count": 0})
    assert normal["brute_force_detected"] is False
    print("Experiment 30: All test cases passed.")

if __name__ == "__main__":
    print("Correlation:", correlate_multi_source_logs({"event": "inbound_connection_rejected"}, {"event": "account_lockout"}, {}))
    test_exp30()
