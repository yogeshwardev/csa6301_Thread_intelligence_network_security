"""
Experiment 23: Inline IPS with False-Positive Tuning Whitelist
"""

SIGNATURES = [
    {"sid": 1001, "pattern": "union select", "action": "block"},
    {"sid": 1002, "pattern": "../../../etc/passwd", "action": "block"},
]

def ips_filter_packet(packet, signatures=SIGNATURES, whitelist=None):
    # packet: {"src_ip": "...", "payload": "..."}
    whitelist = whitelist or set()
    payload = packet.get("payload", "").lower()
    matched = [s for s in signatures if s["pattern"] in payload]

    if not matched:
        return {"action": "allow", "reason": "clean payload"}

    if packet.get("src_ip") in whitelist:
        return {"action": "allow_with_log", "reason": "trusted source whitelisted", "matched_sids": [s["sid"] for s in matched]}

    return {"action": "block", "reason": "malicious signature matched", "matched_sids": [s["sid"] for s in matched]}

# Test Cases
def test_exp23():
    bad_packet = {"src_ip": "203.0.113.10", "payload": "id=1' UNION SELECT user, password FROM users--"}
    assert ips_filter_packet(bad_packet)["action"] == "block"

    partner_packet = {"src_ip": "198.51.100.25", "payload": "id=1' UNION SELECT user, password FROM users--"}
    assert ips_filter_packet(partner_packet, whitelist={"198.51.100.25"})["action"] == "allow_with_log"
    print("Experiment 23: All test cases passed.")

if __name__ == "__main__":
    pkt = {"src_ip": "10.0.0.1", "payload": "Normal request"}
    print("IPS Decision:", ips_filter_packet(pkt))
    test_exp23()
