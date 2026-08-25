"""
Experiment 27: Minimal Signature-Based Intrusion Detection System (IDS)
Fires alerts only when protocol, port context, and content signature match.
"""

IDS_RULES = [
    {"sid": 3001, "msg": "SQL Injection in HTTP Request", "proto": "tcp", "dst_port": 80, "content": "union select"},
    {"sid": 3002, "msg": "Path Traversal Attack", "proto": "tcp", "dst_port": 80, "content": "../../../etc/passwd"},
    {"sid": 3003, "msg": "RDP Brute Force Signature", "proto": "tcp", "dst_port": 3389, "content": "rdp_login_attempt"},
]

def scan_network_packet(packet, rules=IDS_RULES):
    alerts = []
    payload = packet.get("payload", "").lower()
    for rule in rules:
        if packet.get("proto") == rule["proto"] and packet.get("dst_port") == rule["dst_port"]:
            if rule["content"] in payload:
                alerts.append(rule["msg"])
    return alerts

# Test Cases
def test_exp27():
    http_sqli = {"proto": "tcp", "dst_port": 80, "payload": "GET /item?id=1 UNION SELECT name, pass FROM users"}
    assert "SQL Injection in HTTP Request" in scan_network_packet(http_sqli)

    # Same content sent on SSH port 22 must NOT trigger web rule
    ssh_packet = {"proto": "tcp", "dst_port": 22, "payload": "GET /item?id=1 UNION SELECT name, pass FROM users"}
    assert scan_network_packet(ssh_packet) == []
    print("Experiment 27: All test cases passed.")

if __name__ == "__main__":
    test_pkt = {"proto": "tcp", "dst_port": 80, "payload": "GET /files?path=../../../etc/passwd"}
    print("IDS Alerts:", scan_network_packet(test_pkt))
    test_exp27()
