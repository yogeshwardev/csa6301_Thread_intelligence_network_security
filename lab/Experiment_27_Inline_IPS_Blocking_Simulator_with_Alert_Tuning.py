IDS_RULES = [
    {
        "sid": 2000001,
        "msg": "Possible SQL Injection",
        "proto": "tcp",
        "dst_port": 80,
        "content": "union select",
    },
    {
        "sid": 2000002,
        "msg": "Directory Traversal Attempt",
        "proto": "tcp",
        "dst_port": 80,
        "content": "../../../etc/passwd",
    },
    {
        "sid": 2000003,
        "msg": "Suspicious RDP Brute Force Pattern",
        "proto": "tcp",
        "dst_port": 3389,
        "content": "login_attempt",
    },
]


def scan_packet(packet, rules=IDS_RULES):
    alerts = []
    payload_lower = packet["payload"].lower()
    for rule in rules:
        if (
            packet["proto"] == rule["proto"]
            and packet["dst_port"] == rule["dst_port"]
        ):
            if rule["content"] in payload_lower:
                alerts.append(rule["msg"])
    return alerts


def ips_process(packet, rules, whitelist=None):
    """Decides whether to BLOCK (untrusted source) or ALLOW-WITH-LOG (source on tuning whitelist)."""
    whitelist = whitelist or set()
    alerts = scan_packet(packet, rules)
    if not alerts:
        return {"action": "allow", "alerts": []}
    if packet.get("src_ip") in whitelist:
        return {
            "action": "allow",
            "alerts": alerts,
            "note": "source whitelisted, alert suppressed from blocking",
        }
    return {"action": "block", "alerts": alerts}


# Test Cases
def test_experiment27():
    attack_packet = {
        "proto": "tcp",
        "dst_port": 80,
        "payload": "union select username,password from users",
        "src_ip": "203.0.113.50",
    }
    result = ips_process(attack_packet, IDS_RULES)
    assert result["action"] == "block"

    partner_packet = dict(attack_packet, src_ip="198.51.100.10")
    result2 = ips_process(partner_packet, IDS_RULES, whitelist={"198.51.100.10"})
    assert result2["action"] == "allow"
    assert "note" in result2
    print("Experiment 27: All test cases passed.")


test_experiment27()
