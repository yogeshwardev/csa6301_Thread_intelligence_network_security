ROLE_REQUIREMENTS = {
    "intern": {"read_reports"},
    "analyst": {"read_reports", "write_reports"},
    "admin": {"read_reports", "write_reports", "manage_users", "manage_servers"},
}


def find_over_privileged_users(users, role_requirements=ROLE_REQUIREMENTS):
    """users: {username: {"role": str, "granted_permissions": set}}.
    Returns {username: excess_permissions} for anyone holding more access
    than their role requires — a least-privilege violation."""
    violations = {}
    for username, info in users.items():
        required = role_requirements.get(info["role"], set())
        excess = info["granted_permissions"] - required
        if excess:
            violations[username] = excess
    return violations


# Test Cases
def test_experiment30():
    users = {
        "jdoe": {"role": "intern", "granted_permissions": {"read_reports"}},
        "asmith": {
            "role": "analyst",
            "granted_permissions": {"read_reports", "write_reports"},
        },
        "kintern": {
            "role": "intern",
            "granted_permissions": {
                "read_reports",
                "manage_users",
                "manage_servers",
            },
        },
    }
    violations = find_over_privileged_users(users)
    assert "jdoe" not in violations
    assert "asmith" not in violations
    assert "kintern" in violations
    assert violations["kintern"] == {"manage_users", "manage_servers"}
    print("Experiment 30: All test cases passed.")


test_experiment30()
