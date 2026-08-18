def classify_ir_phase(description, rules):
    text = description.lower()
    for phase, keywords in rules:
        for kw in keywords:
            if kw in text:
                return phase
    return "Unclassified"


IR_PHASE_RULES = [
    (
        "Preparation",
        [
            "tabletop exercise",
            "incident response playbook",
            "conduct staff training",
            "runbook",
        ],
    ),
    (
        "Identification",
        [
            "alert was triggered",
            "suspicious activity was detected",
            "anomaly detected by the ids",
            "reported the issue to the helpdesk",
        ],
    ),
    (
        "Containment",
        [
            "isolate the affected host",
            "disconnect the machine from the network",
            "block the ip at the firewall",
            "disable the compromised account",
        ],
    ),
    (
        "Eradication",
        [
            "remove the malware from the system",
            "patch the vulnerable software",
            "delete the malicious scheduled task",
            "rebuild the infected server",
        ],
    ),
    (
        "Recovery",
        [
            "restore the system from a clean backup",
            "bring the server back into production",
            "monitor the system for signs of reinfection",
        ],
    ),
    (
        "Lessons Learned",
        [
            "post-incident review meeting",
            "perform a root cause analysis session",
            "update the playbook based on the incident",
        ],
    ),
]


# Test Cases
def test_experiment33():
    d1 = "The team ran a tabletop exercise to test the incident response playbook."
    assert classify_ir_phase(d1, IR_PHASE_RULES) == "Preparation"
    d2 = "An anomaly detected by the IDS triggered an alert overnight."
    assert classify_ir_phase(d2, IR_PHASE_RULES) == "Identification"
    d3 = "Analysts decided to isolate the affected host immediately."
    assert classify_ir_phase(d3, IR_PHASE_RULES) == "Containment"
    d4 = "The engineer had to patch the vulnerable software on all servers."
    assert classify_ir_phase(d4, IR_PHASE_RULES) == "Eradication"
    d5 = "Admins worked to restore the system from a clean backup overnight."
    assert classify_ir_phase(d5, IR_PHASE_RULES) == "Recovery"
    d6 = "The team held a post-incident review meeting the following week."
    assert classify_ir_phase(d6, IR_PHASE_RULES) == "Lessons Learned"
    print("Experiment 33: All test cases passed.")


test_experiment33()
