"""
Experiment 24: Security Baseline Compliance Checker
Audits an organization's current configurations against mandatory baseline standards.
"""

BASELINE_REQUIREMENTS = {
    "mfa_enforced": True,
    "min_password_length": 14,
    "disk_encryption_enabled": True,
    "automatic_patching": True,
    "inbound_firewall_default_deny": True,
}

def audit_baseline_compliance(current_config, baseline=BASELINE_REQUIREMENTS):
    non_compliant = []
    for control, req_val in baseline.items():
        curr_val = current_config.get(control)
        if isinstance(req_val, bool):
            if curr_val is not req_val:
                non_compliant.append({"control": control, "required": req_val, "found": curr_val})
        elif isinstance(req_val, (int, float)):
            if curr_val is None or curr_val < req_val:
                non_compliant.append({"control": control, "required": req_val, "found": curr_val})

    return {"compliant": len(non_compliant) == 0, "failed_controls": non_compliant}

# Test Cases
def test_exp24():
    good_cfg = {
        "mfa_enforced": True,
        "min_password_length": 16,
        "disk_encryption_enabled": True,
        "automatic_patching": True,
        "inbound_firewall_default_deny": True,
    }
    assert audit_baseline_compliance(good_cfg)["compliant"] is True

    bad_cfg = {
        "mfa_enforced": False,
        "min_password_length": 8,
        "disk_encryption_enabled": True,
        "automatic_patching": False,
        "inbound_firewall_default_deny": True,
    }
    audit = audit_baseline_compliance(bad_cfg)
    assert audit["compliant"] is False
    assert len(audit["failed_controls"]) == 3
    print("Experiment 24: All test cases passed.")

if __name__ == "__main__":
    print("Audit:", audit_baseline_compliance({"mfa_enforced": True, "min_password_length": 10}))
    test_exp24()
