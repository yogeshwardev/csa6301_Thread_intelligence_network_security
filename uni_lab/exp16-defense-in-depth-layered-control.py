"""
Experiment 16: Defense-in-Depth Layered Control Simulator
Evaluates an attack against ordered security layers.
"""

def spam_filter(attack): return attack.get("phishing_link_present", False)
def endpoint_av(attack): return attack.get("malicious_attachment_hash", False)
def segmentation(attack): return attack.get("attempts_lateral_movement", False) and not attack.get("bypasses_vlan", False)
def siem_monitor(attack): return attack.get("generates_anomaly_logs", False)

LAYERS = [
    ("Email Spam Filter", spam_filter),
    ("Endpoint Antivirus", endpoint_av),
    ("Network Segmentation", segmentation),
    ("SIEM Monitoring", siem_monitor),
]

def simulate_defense(attack, layers=LAYERS):
    for name, layer_fn in layers:
        if layer_fn(attack):
            return {"status": "BLOCKED", "blocked_by": name}
    return {"status": "BREACH", "blocked_by": None}

# Test Cases
def test_exp16():
    att1 = {"phishing_link_present": True}
    assert simulate_defense(att1)["blocked_by"] == "Email Spam Filter"

    att2 = {"phishing_link_present": False, "malicious_attachment_hash": True}
    assert simulate_defense(att2)["blocked_by"] == "Endpoint Antivirus"

    att3 = {"attempts_lateral_movement": True, "bypasses_vlan": False}
    assert simulate_defense(att3)["blocked_by"] == "Network Segmentation"

    att_breach = {}
    assert simulate_defense(att_breach)["status"] == "BREACH"
    print("Experiment 16: All test cases passed.")

if __name__ == "__main__":
    print("Defense Simulation:", simulate_defense({"generates_anomaly_logs": True}))
    test_exp16()
