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
    """packet: {"proto","dst_port","payload"}. A rule fires only if BOTH
    the protocol/port match AND the content pattern is found (case-insensitive)."""
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


# Test Cases
def test_experiment26():
    sqli_packet = {
        "proto": "tcp",
        "dst_port": 80,
        "payload": "id=1' UNION SELECT user,pass FROM accounts--",
    }
    assert "Possible SQL Injection" in scan_packet(sqli_packet)
    traversal_packet = {
        "proto": "tcp",
        "dst_port": 80,
        "payload": "GET /files?path=../../../etc/passwd",
    }
    assert "Directory Traversal Attempt" in scan_packet(traversal_packet)

    wrong_context = {
        "proto": "tcp",
        "dst_port": 22,
        "payload": "id=1' UNION SELECT user,pass FROM accounts--",
    }
    assert scan_packet(wrong_context) == []
    print("Experiment 26: All test cases passed.")


test_experiment26()
