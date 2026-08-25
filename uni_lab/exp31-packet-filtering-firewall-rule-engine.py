"""
Experiment 31: Packet-Filtering Firewall Rule Engine
Demonstrates default-deny and top-down rule ordering sensitivity.
"""

def packet_matches_rule(packet, rule):
    def check_field(val, rule_val):
        return rule_val == "any" or val == rule_val
    return (
        check_field(packet.get("src"), rule.get("src")) and
        check_field(packet.get("dst"), rule.get("dst")) and
        check_field(packet.get("port"), rule.get("port")) and
        check_field(packet.get("proto"), rule.get("proto"))
    )

def evaluate_firewall(packet, rules):
    for rule in rules:
        if packet_matches_rule(packet, rule):
            return rule["action"]
    return "deny"  # Default-deny principle

# Test Cases
def test_exp31():
    # Misordered: broad allow placed first hides specific deny
    bad_rules = [
        {"action": "allow", "src": "any", "dst": "any", "port": "any", "proto": "any"},
        {"action": "deny", "src": "10.0.0.99", "dst": "any", "port": "any", "proto": "any"},
    ]
    pkt = {"src": "10.0.0.99", "dst": "8.8.8.8", "port": 443, "proto": "tcp"}
    assert evaluate_firewall(pkt, bad_rules) == "allow"

    # Correct order: specific deny placed first
    good_rules = [
        {"action": "deny", "src": "10.0.0.99", "dst": "any", "port": "any", "proto": "any"},
        {"action": "allow", "src": "any", "dst": "any", "port": "any", "proto": "any"},
    ]
    assert evaluate_firewall(pkt, good_rules) == "deny"

    # Default deny for empty rules
    assert evaluate_firewall(pkt, []) == "deny"
    print("Experiment 31: All test cases passed.")

if __name__ == "__main__":
    rules = [{"action": "allow", "src": "10.0.0.1", "dst": "any", "port": 80, "proto": "tcp"}]
    print("Eval 10.0.0.1:", evaluate_firewall({"src": "10.0.0.1", "dst": "1.1.1.1", "port": 80, "proto": "tcp"}, rules))
    print("Eval 10.0.0.2:", evaluate_firewall({"src": "10.0.0.2", "dst": "1.1.1.1", "port": 80, "proto": "tcp"}, rules))
    test_exp31()
