rules = [
    {"action": "ALLOW", "ip": "10.0.0.5", "port": 443},
    {"action": "ALLOW", "ip": "10.0.0.5", "port": 80},
    {"action": "DENY", "ip": "203.0.113.99", "port": None},  # block this IP entirely
    {"action": "DENY", "ip": None, "port": 23},  # block telnet from anyone
]


def check_packet(ip, port):
    for rule in rules:
        ip_match = rule["ip"] in (None, ip)
        port_match = rule["port"] in (None, port)
        if ip_match and port_match:
            return rule["action"]
    return "DENY"  # default: deny anything not explicitly allowed


packets = [
    ("10.0.0.5", 443),
    ("203.0.113.99", 80),
    ("10.0.0.9", 23),
    ("10.0.0.9", 8080),
]

for ip, port in packets:
    decision = check_packet(ip, port)
    print(f"Packet from {ip}:{port} -> {decision}")
