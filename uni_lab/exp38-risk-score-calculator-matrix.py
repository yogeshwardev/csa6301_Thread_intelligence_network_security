"""
Experiment 38: Qualitative Risk Score Calculator (Likelihood x Impact Matrix)
"""

def calculate_qualitative_risk(likelihood, impact):
    if not (1 <= likelihood <= 5) or not (1 <= impact <= 5):
        raise ValueError("Likelihood and impact must both be integers between 1 and 5.")

    score = likelihood * impact
    if score <= 5:
        level = "Low"
    elif score <= 12:
        level = "Medium"
    elif score <= 19:
        level = "High"
    else:
        level = "Critical"

    return {"likelihood": likelihood, "impact": impact, "score": score, "risk_level": level}

# Test Cases
def test_exp38():
    assert calculate_qualitative_risk(1, 2)["risk_level"] == "Low"
    assert calculate_qualitative_risk(3, 4)["risk_level"] == "Medium"
    assert calculate_qualitative_risk(4, 4)["risk_level"] == "High"
    assert calculate_qualitative_risk(5, 5)["risk_level"] == "Critical"

    try:
        calculate_qualitative_risk(0, 5)
        assert False, "Should raise ValueError"
    except ValueError:
        pass
    print("Experiment 38: All test cases passed.")

if __name__ == "__main__":
    print("Risk Assessment:", calculate_qualitative_risk(4, 5))
    test_exp38()
