def rule_matches(packet, rule):
    def field_ok(value, rule_value):
        return rule_value == "any" or value == rule_value

    return (
        field_ok(packet["src"], rule["src"])
        and field_ok(packet["dst"], rule["dst"])
        and field_ok(packet["port"], rule["port"])
        and field_ok(packet["proto"], rule["proto"])
    )


def evaluate_packet(packet, rules):
    """Return the action of the first matching rule (top-down), or 'deny' if no rule matches (default-deny)."""
    for rule in rules:
        if rule_matches(packet, rule):
            return rule["action"]
    return "deny"


# Test Cases
def test_experiment24():
    misordered_rules = [
        {"action": "allow", "src": "any", "dst": "any", "port": "any", "proto": "any"},
        {"action": "deny", "src": "10.0.0.5", "dst": "any", "port": "any", "proto": "any"},
    ]
    packet = {"src": "10.0.0.5", "dst": "8.8.8.8", "port": 443, "proto": "tcp"}
    assert evaluate_packet(packet, misordered_rules) == "allow"

    fixed_rules = [
        {"action": "deny", "src": "10.0.0.5", "dst": "any", "port": "any", "proto": "any"},
        {"action": "allow", "src": "any", "dst": "any", "port": "any", "proto": "any"},
    ]
    assert evaluate_packet(packet, fixed_rules) == "deny"

    other_packet = {"src": "192.168.1.9", "dst": "1.1.1.1", "port": 53, "proto": "udp"}
    assert evaluate_packet(other_packet, []) == "deny"
    print("Experiment 24: All test cases passed.")


test_experiment24()
