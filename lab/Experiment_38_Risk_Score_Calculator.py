def calculate_risk(likelihood, impact):
    if not (1 <= likelihood <= 5) or not (1 <= impact <= 5):
        raise ValueError("Likelihood and impact must each be between 1 and 5.")
    score = likelihood * impact
    if score <= 5:
        level = "Low"
    elif score <= 12:
        level = "Medium"
    elif score <= 19:
        level = "High"
    else:
        level = "Critical"
    return {"score": score, "level": level}


# Test Cases
def test_experiment38():
    assert calculate_risk(1, 2) == {"score": 2, "level": "Low"}
    assert calculate_risk(3, 4) == {"score": 12, "level": "Medium"}
    assert calculate_risk(4, 4) == {"score": 16, "level": "High"}
    assert calculate_risk(5, 5) == {"score": 25, "level": "Critical"}
    assert calculate_risk(5, 4) == {"score": 20, "level": "Critical"}
    try:
        calculate_risk(6, 1)
        assert False, "Expected ValueError for out-of-range likelihood"
    except ValueError:
        pass
    print("Experiment 38: All test cases passed.")


test_experiment38()
