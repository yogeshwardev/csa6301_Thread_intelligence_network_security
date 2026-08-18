def simulate_defense(attack, layers):
    """layers: ordered list of (layer_name, catch_function).
    Returns the name of the first layer that catches the attack, or 'BREACH' if it passes undetected."""
    for layer_name, catch_fn in layers:
        if catch_fn(attack):
            return layer_name
    return "BREACH"


def spam_filter_catches(attack):
    return attack.get("known_phishing_domain", False)


def endpoint_av_catches(attack):
    return attack.get("known_malware_hash", False)


def segmentation_catches(attack):
    return attack.get("attempts_lateral_movement", False) and not attack.get(
        "segmentation_bypassed", False
    )


def siem_monitoring_catches(attack):
    return attack.get("generates_anomalous_traffic", False)


# Test Cases
def test_experiment32():
    layers = [
        ("Email Spam Filter", spam_filter_catches),
        ("Endpoint Antivirus", endpoint_av_catches),
        ("Network Segmentation", segmentation_catches),
        ("SIEM Monitoring", siem_monitoring_catches),
    ]

    # Phishing email evades spam filter (unknown domain), but AV catches the attachment
    attack1 = {"known_phishing_domain": False, "known_malware_hash": True}
    assert simulate_defense(attack1, layers) == "Endpoint Antivirus"

    # Evades spam filter and AV, but is caught while attempting lateral movement
    attack2 = {
        "known_phishing_domain": False,
        "known_malware_hash": False,
        "attempts_lateral_movement": True,
        "segmentation_bypassed": False,
    }
    assert simulate_defense(attack2, layers) == "Network Segmentation"

    # Evades every layer entirely
    attack3 = {
        "known_phishing_domain": False,
        "known_malware_hash": False,
        "attempts_lateral_movement": False,
        "generates_anomalous_traffic": False,
    }
    assert simulate_defense(attack3, layers) == "BREACH"
    print("Experiment 32: All test cases passed.")


test_experiment32()
