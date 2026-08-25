"""
Experiment 28: Denial-of-Service (DoS) Detection from Web Server Logs
Identifies IP addresses generating abnormally high request frequencies.
"""

def detect_dos_attack(web_logs, threshold_requests_per_ip=50):
    ip_counts = {}
    for log in web_logs:
        # log: {"ip": "...", "timestamp": "...", "endpoint": "..."}
        ip = log.get("ip")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    flagged_ips = {ip: count for ip, count in ip_counts.items() if count >= threshold_requests_per_ip}
    return {
        "dos_detected": len(flagged_ips) > 0,
        "flagged_attackers": flagged_ips
    }

# Test Cases
def test_exp28():
    logs = [{"ip": "192.168.1.10"}] * 10 + [{"ip": "203.0.113.88"}] * 60
    res = detect_dos_attack(logs, threshold_requests_per_ip=50)
    assert res["dos_detected"] is True
    assert "203.0.113.88" in res["flagged_attackers"]
    assert res["flagged_attackers"]["203.0.113.88"] == 60
    print("Experiment 28: All test cases passed.")

if __name__ == "__main__":
    test_logs = [{"ip": "10.0.0.5"}] * 100
    print("DoS Scan Result:", detect_dos_attack(test_logs))
    test_exp28()
