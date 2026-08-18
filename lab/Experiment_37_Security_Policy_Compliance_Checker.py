def check_policy_compliance(policy_text, required_elements):
    text = policy_text.lower()
    missing = [
        element for element, keyword in required_elements if keyword not in text
    ]
    return missing


REQUIRED_POLICY_ELEMENTS = [
    ("Scope", "scope"),
    ("Roles and Responsibilities", "responsibilities"),
    ("Enforcement/Consequences", "enforcement"),
    ("Review Cycle", "review"),
    ("Approval Authority", "approved by"),
]


# Test Cases
def test_experiment37():
    complete_policy = """
Scope: This policy applies to all employees and contractors.
Roles and Responsibilities: The IT department is responsible for enforcement.
Enforcement: Violations may result in disciplinary action.
This policy will undergo an annual review.
Approved by the Chief Information Security Officer.
"""
    assert check_policy_compliance(complete_policy, REQUIRED_POLICY_ELEMENTS) == []

    incomplete_policy = """
Scope: This policy applies to all employees.
The IT department manages this document.
"""
    missing = check_policy_compliance(incomplete_policy, REQUIRED_POLICY_ELEMENTS)
    assert set(missing) == {
        "Roles and Responsibilities",
        "Enforcement/Consequences",
        "Review Cycle",
        "Approval Authority",
    }
    print("Experiment 37: All test cases passed.")


test_experiment37()
