"""
Experiment 35: Least-Privilege Access Control Matrix Validator
Audits user permissions against role baselines to flag excess privileges.
"""

ROLE_PERMISSIONS = {
    "intern": {"read_reports"},
    "analyst": {"read_reports", "create_tickets", "view_logs"},
    "admin": {"read_reports", "create_tickets", "view_logs", "manage_users", "delete_records"},
}

def audit_least_privilege(users, role_defs=ROLE_PERMISSIONS):
    # users: {"username": {"role": "...", "granted": set(...)}}
    violations = {}
    for username, data in users.items():
        role = data.get("role")
        granted = data.get("granted", set())
        allowed = role_defs.get(role, set())
        excess = granted - allowed
        if excess:
            violations[username] = {"role": role, "excess_permissions": sorted(list(excess))}
    return violations

# Test Cases
def test_exp35():
    users = {
        "alice": {"role": "intern", "granted": {"read_reports"}},
        "bob": {"role": "intern", "granted": {"read_reports", "manage_users"}},
        "charlie": {"role": "analyst", "granted": {"read_reports", "create_tickets", "view_logs"}},
    }
    viol = audit_least_privilege(users)
    assert "alice" not in viol
    assert "charlie" not in viol
    assert "bob" in viol
    assert "manage_users" in viol["bob"]["excess_permissions"]
    print("Experiment 35: All test cases passed.")

if __name__ == "__main__":
    u = {"test_user": {"role": "intern", "granted": {"delete_records"}}}
    print("Violations:", audit_least_privilege(u))
    test_exp35()
