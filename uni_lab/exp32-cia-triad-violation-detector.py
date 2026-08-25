"""
Experiment 32: CIA Triad Principle Violation Detector
Identifies which CIA principles (Confidentiality, Integrity, Availability) are violated.
"""

def detect_cia_violations(security_properties):
    # security_properties: [{"property": "...", "cia_pillar": "Confidentiality", "status_ok": bool}]
    violations = set()
    for prop in security_properties:
        pillar = prop.get("cia_pillar")
        status = prop.get("status_ok", True)
        if not status and pillar in ("Confidentiality", "Integrity", "Availability"):
            violations.add(pillar)

    return {
        "has_violations": len(violations) > 0,
        "violated_pillars": sorted(list(violations))
    }

# Test Cases
def test_exp32():
    props = [
        {"property": "Database encryption at rest", "cia_pillar": "Confidentiality", "status_ok": False},
        {"property": "File checksum hashing intact", "cia_pillar": "Integrity", "status_ok": True},
        {"property": "Server cluster online and accessible", "cia_pillar": "Availability", "status_ok": False},
    ]
    res = detect_cia_violations(props)
    assert res["has_violations"] is True
    assert res["violated_pillars"] == ["Availability", "Confidentiality"]
    print("Experiment 32: All test cases passed.")

if __name__ == "__main__":
    sample = [{"property": "Cleartext password leak", "cia_pillar": "Confidentiality", "status_ok": False}]
    print("Violations:", detect_cia_violations(sample))
    test_exp32()
