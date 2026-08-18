def triage_alert(alert_description, rules):
    text = alert_description.lower()
    for priority, keywords in rules:
        for kw in keywords:
            if kw in text:
                return priority
    return "P4 - Low"


SOC_TRIAGE_RULES = [
    (
        "P1 - Critical",
        [
            "ransomware detonation confirmed",
            "domain admin account compromised",
            "active data exfiltration in progress",
        ],
    ),
    (
        "P2 - High",
        [
            "malware detected on endpoint",
            "multiple failed administrator logins",
            "command-and-control beacon detected",
        ],
    ),
    (
        "P3 - Medium",
        [
            "acceptable use policy violation",
            "login from an unusual location",
            "port scan detected against a server",
        ],
    ),
]


# Test Cases
def test_experiment41():
    d1 = (
        "SIEM confirms active data exfiltration in progress from the finance"
        " share."
    )
    assert triage_alert(d1, SOC_TRIAGE_RULES) == "P1 - Critical"
    d2 = "Endpoint agent reports malware detected on endpoint WKS-204."
    assert triage_alert(d2, SOC_TRIAGE_RULES) == "P2 - High"
    d3 = "A login from an unusual location was flagged for a sales account."
    assert triage_alert(d3, SOC_TRIAGE_RULES) == "P3 - Medium"
    d4 = "Scheduled maintenance window notification received."
    assert triage_alert(d4, SOC_TRIAGE_RULES) == "P4 - Low"
    print("Experiment 41: All test cases passed.")


test_experiment41()
