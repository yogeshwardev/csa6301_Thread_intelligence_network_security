def zero_trust_authorize(request, resource_policy):
    """request: {"user","mfa_passed","device_posture":{"antivirus_enabled","os_patched"},"resource"}
    resource_policy: {resource: set(allowed_users)}
    Access requires: user authorized for resource AND mfa_passed AND healthy device posture."""
    reasons = []
    allowed_users = resource_policy.get(request["resource"], set())

    if request["user"] not in allowed_users:
        reasons.append("user not authorized for this resource")
    if not request["mfa_passed"]:
        reasons.append("MFA not completed")
    if not request["device_posture"]["antivirus_enabled"]:
        reasons.append("antivirus disabled")
    if not request["device_posture"]["os_patched"]:
        reasons.append("OS not fully patched")

    return {"granted": len(reasons) == 0, "reasons": reasons}


# Test Cases
def test_experiment31():
    policy = {"finance_db": {"csmith", "afinance"}}
    healthy_request = {
        "user": "csmith",
        "mfa_passed": True,
        "device_posture": {"antivirus_enabled": True, "os_patched": True},
        "resource": "finance_db",
    }
    assert zero_trust_authorize(healthy_request, policy)["granted"] is True

    # Same user, correct password/MFA, but antivirus disabled -> still denied
    unhealthy_request = dict(
        healthy_request,
        device_posture={"antivirus_enabled": False, "os_patched": True},
    )
    result2 = zero_trust_authorize(unhealthy_request, policy)
    assert result2["granted"] is False
    assert "antivirus disabled" in result2["reasons"]

    # A stolen credential for a user never authorized for this resource
    unauthorized_request = dict(healthy_request, user="attacker99")
    assert zero_trust_authorize(unauthorized_request, policy)["granted"] is False
    print("Experiment 31: All test cases passed.")


test_experiment31()
