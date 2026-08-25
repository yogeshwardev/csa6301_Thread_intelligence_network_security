"""
Experiment 13: Threat Intelligence vs Raw Data Qualifier
Evaluates context, confidence score, and actionability to qualify intelligence.
"""

def qualify_threat_intelligence(item):
    # item: {"data": "...", "has_context": bool, "confidence_score": float (0-1), "actionable_mitigation": bool}
    has_ctx = item.get("has_context", False)
    conf = item.get("confidence_score", 0.0)
    actionable = item.get("actionable_mitigation", False)

    if has_ctx and conf >= 0.7 and actionable:
        return {"status": "Actionable Threat Intelligence", "qualified": True}
    elif has_ctx and conf >= 0.5:
        return {"status": "Enriched Data (Requires Analysis)", "qualified": False}
    else:
        return {"status": "Unprocessed Raw Data", "qualified": False}

# Test Cases
def test_exp13():
    raw = {"data": "198.51.100.5", "has_context": False, "confidence_score": 0.2, "actionable_mitigation": False}
    assert qualify_threat_intelligence(raw)["status"] == "Unprocessed Raw Data"

    intel = {
        "data": "IP 198.51.100.5 associated with LockBit C2 infrastructure targeting finance sector",
        "has_context": True,
        "confidence_score": 0.9,
        "actionable_mitigation": True
    }
    assert qualify_threat_intelligence(intel)["status"] == "Actionable Threat Intelligence"
    print("Experiment 13: All test cases passed.")

if __name__ == "__main__":
    item = {"data": "File hash abc123", "has_context": True, "confidence_score": 0.85, "actionable_mitigation": True}
    print("Qualification:", qualify_threat_intelligence(item))
    test_exp13()
