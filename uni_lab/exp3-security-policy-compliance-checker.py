"""
Experiment 3: Security Policy Governance Compliance Checker
Checks policy documents for mandatory governance sections.
"""

REQUIRED_ELEMENTS = [
    ("Scope", "scope"),
    ("Roles and Responsibilities", "responsibilities"),
    ("Enforcement", "enforcement"),
    ("Review Cycle", "review"),
    ("Approval Authority", "approved by"),
]

def check_policy_governance(policy_text, required_elements=REQUIRED_ELEMENTS):
    text = policy_text.lower()
    missing = [elem for elem, kw in required_elements if kw not in text]
    present = [elem for elem, kw in required_elements if kw in text]
    return {
        "is_compliant": len(missing) == 0,
        "present_elements": present,
        "missing_elements": missing
    }

# Test Cases
def test_exp3():
    complete_policy = """
    Scope: Applies to all employees and cloud infrastructure.
    Roles and Responsibilities: CISO enforces compliance; IT team implements controls.
    Enforcement: Disciplinary action for non-compliance.
    Review: Reviewed annually by the security steering committee.
    Approved by: Chief Information Security Officer.
    """
    res = check_policy_governance(complete_policy)
    assert res["is_compliant"] is True
    assert res["missing_elements"] == []

    incomplete = "Scope: Applies to engineering only. Responsibilities are assigned."
    res2 = check_policy_governance(incomplete)
    assert res2["is_compliant"] is False
    assert "Enforcement" in res2["missing_elements"]
    print("Experiment 3: All test cases passed.")

if __name__ == "__main__":
    sample_text = "Scope: Enterprise-wide. Approved by: CISO. Reviewed quarterly."
    print("Policy Check:", check_policy_governance(sample_text))
    test_exp3()
