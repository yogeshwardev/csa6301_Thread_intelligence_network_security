"""
Experiment 22: Authentication Log Brute-Force Pattern Detector
Detects repeated failed logins followed by a successful login for a given user.
"""

def detect_brute_force_success(auth_logs, target_user, fail_threshold=3):
    failed_streak = 0
    for entry in auth_logs:
        # entry: {"time": "...", "user": "...", "status": "failed"/"success"}
        if entry.get("user") == target_user:
            if entry.get("status") == "failed":
                failed_streak += 1
            elif entry.get("status") == "success":
                if failed_streak >= fail_threshold:
                    return {"detected": True, "failed_attempts_before_success": failed_streak}
                failed_streak = 0
    return {"detected": False, "failed_attempts_before_success": failed_streak}

# Test Cases
def test_exp22():
    logs = [
        {"time": "09:00", "user": "admin", "status": "failed"},
        {"time": "09:01", "user": "admin", "status": "failed"},
        {"time": "09:02", "user": "admin", "status": "failed"},
        {"time": "09:03", "user": "admin", "status": "success"},
    ]
    res = detect_brute_force_success(logs, "admin", fail_threshold=3)
    assert res["detected"] is True
    assert res["failed_attempts_before_success"] == 3

    logs_normal = [
        {"time": "09:00", "user": "admin", "status": "failed"},
        {"time": "09:01", "user": "admin", "status": "success"},
    ]
    assert detect_brute_force_success(logs_normal, "admin", fail_threshold=3)["detected"] is False
    print("Experiment 22: All test cases passed.")

if __name__ == "__main__":
    sample_logs = [{"user": "jdoe", "status": "failed"}] * 4 + [{"user": "jdoe", "status": "success"}]
    print("Result:", detect_brute_force_success(sample_logs, "jdoe"))
    test_exp22()
