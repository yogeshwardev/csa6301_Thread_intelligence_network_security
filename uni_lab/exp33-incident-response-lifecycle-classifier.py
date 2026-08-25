"""
Experiment 33: Incident Response Lifecycle Phase Classifier
Classifies actions into Preparation, Identification, Containment, Eradication, Recovery, or Lessons Learned.
"""

IR_RULES = [
    ("Preparation", ["tabletop drill", "playbook creation", "staff training", "ir plan update"]),
    ("Identification", ["ids alert triggered", "anomaly detected", "helpdesk report of breach", "suspicious activity detected"]),
    ("Containment", ["isolate host", "disconnect network cable", "block ip on firewall", "disable account"]),
    ("Eradication", ["remove malware", "delete scheduled task", "patch vulnerability", "clean registry keys"]),
    ("Recovery", ["restore from clean backup", "rebuild server", "bring server back to production", "monitor reinfection"]),
    ("Lessons Learned", ["post-incident review", "root cause analysis meeting", "document lessons learned", "update playbook"]),
]

def classify_ir_action(description, rules=IR_RULES):
    text = description.lower()
    for phase, keywords in rules:
        if any(kw in text for kw in keywords):
            return phase
    return "Unclassified"

# Test Cases
def test_exp33():
    assert classify_ir_action("Admins ran a tabletop drill to test playbook creation.") == "Preparation"
    assert classify_ir_action("IDS alert triggered on database segment.") == "Identification"
    assert classify_ir_action("Isolate host from the internal network immediately.") == "Containment"
    assert classify_ir_action("Patch vulnerability and delete scheduled task.") == "Eradication"
    assert classify_ir_action("Restore from clean backup and bring server back to production.") == "Recovery"
    assert classify_ir_action("Hold a post-incident review meeting with stakeholders.") == "Lessons Learned"
    print("Experiment 33: All test cases passed.")

if __name__ == "__main__":
    print("Phase:", classify_ir_action("Analysts decided to block IP on firewall."))
    test_exp33()
