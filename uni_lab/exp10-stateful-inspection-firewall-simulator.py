"""
Experiment 10: Stateful Inspection Firewall Connection Tracker
Tracks outbound TCP flows and allows return packets while blocking unsolicited inbound traffic.
"""

class StatefulFirewall:
    def __init__(self, allowed_outbound_ports):
        self.allowed_outbound_ports = allowed_outbound_ports
        self.state_table = {}

    def handle_outbound(self, packet):
        # packet: {"src", "sport", "dst", "dport"}
        if packet["dport"] in self.allowed_outbound_ports:
            flow_key = (packet["src"], packet["sport"], packet["dst"], packet["dport"])
            self.state_table[flow_key] = "ESTABLISHED"
            return "allow"
        return "deny"

    def handle_inbound(self, packet):
        # packet: {"src", "sport", "dst", "dport"}
        reverse_key = (packet["dst"], packet["dport"], packet["src"], packet["sport"])
        if reverse_key in self.state_table:
            return "allow"
        return "deny"

# Test Cases
def test_exp10():
    fw = StatefulFirewall(allowed_outbound_ports={80, 443})
    outbound = {"src": "10.0.0.5", "sport": 49152, "dst": "93.184.216.34", "dport": 443}
    assert fw.handle_outbound(outbound) == "allow"

    # Legitimate response matches reversed state
    response = {"src": "93.184.216.34", "sport": 443, "dst": "10.0.0.5", "dport": 49152}
    assert fw.handle_inbound(response) == "allow"

    # Unsolicited inbound packet denied
    unsolicited = {"src": "198.51.100.2", "sport": 4444, "dst": "10.0.0.5", "dport": 80}
    assert fw.handle_inbound(unsolicited) == "deny"
    print("Experiment 10: All test cases passed.")

if __name__ == "__main__":
    fw = StatefulFirewall(allowed_outbound_ports={443})
    print("Outbound connection:", fw.handle_outbound({"src": "10.0.0.1", "sport": 50000, "dst": "1.1.1.1", "dport": 443}))
    test_exp10()
