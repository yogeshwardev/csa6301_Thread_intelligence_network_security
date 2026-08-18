def handle_outbound_syn(packet, state_table, allow_rules):
    """packet: {"src","sport","dst","dport"} outbound SYN.
    If (dst, dport) is permitted by allow_rules, record state so the
    matching return traffic will be permitted automatically."""
    key = (packet["dst"], packet["dport"])
    if key in allow_rules:
        state_table[(packet["src"], packet["sport"], packet["dst"], packet["dport"])] = "ESTABLISHED"
        return "allow"
    return "deny"


def handle_inbound_packet(packet, state_table):
    """packet: {"src","sport","dst","dport"} inbound packet claiming to be
    a response. Only allowed if it matches an existing state-table entry
    for the original outbound connection (reversed direction)."""
    key = (packet["dst"], packet["dport"], packet["src"], packet["sport"])
    if key in state_table:
        return "allow"
    return "deny"


# Test Cases
def test_experiment25():
    state_table = {}
    allow_rules = {("93.184.216.34", 443)}
    outbound = {"src": "10.0.0.20", "sport": 51000, "dst": "93.184.216.34", "dport": 443}
    assert handle_outbound_syn(outbound, state_table, allow_rules) == "allow"
    assert (outbound["src"], outbound["sport"], outbound["dst"], outbound["dport"]) in state_table

    response = {"src": "93.184.216.34", "sport": 443, "dst": "10.0.0.20", "dport": 51000}
    assert handle_inbound_packet(response, state_table) == "allow"

    unsolicited = {"src": "203.0.113.9", "sport": 4444, "dst": "10.0.0.20", "dport": 51000}
    assert handle_inbound_packet(unsolicited, state_table) == "deny"
    print("Experiment 25: All test cases passed.")


test_experiment25()
