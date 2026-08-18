auth_log = [
    ("09:15", "login_success"),
    ("09:17", "failed_login"),
    ("09:18", "failed_login"),
    ("09:19", "failed_login"),
    ("09:20", "account_locked"),
]


def detect_bruteforce(log, fail_threshold=3):
    consecutive_fails = 0
    for _, event in log:
        if event == "failed_login":
            consecutive_fails += 1
        elif event == "account_locked" and consecutive_fails >= fail_threshold:
            return True, consecutive_fails
        else:
            consecutive_fails = 0
    return False, consecutive_fails


def classify_log_line(line):
    keywords = {
        "firewall": ["blocked", "dropped", "denied"],
        "security": ["login", "locked", "authentication"],
        "web_server": ["get", "post", "http"],
    }
    line_lower = line.lower()
    for category, words in keywords.items():
        if any(w in line_lower for w in words):
            return category
    return "unknown"


detected, fails = detect_bruteforce(auth_log)
sample_classification = classify_log_line("User login failed - authentication error")

print("Brute-force detected:", detected, "| consecutive fails before lockout:", fails)
print("Log line classified as:", sample_classification)


# Test Cases
def test_experiment18():
    assert detected is True
    assert fails == 3
    normal_log = [("10:00", "login_success"), ("10:05", "login_success")]
    assert detect_bruteforce(normal_log)[0] is False
    assert sample_classification == "security"
    assert classify_log_line("Connection blocked by firewall rule 12") == "firewall"
    print("Experiment 18: All test cases passed.")


test_experiment18()
