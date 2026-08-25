"""
Experiment 37: Continuous Security Monitoring Loop with Anomaly Flagging
"""
import random

def monitor_login_stream(event_stream):
    flags = []
    for event in event_stream:
        # event: {"user": "...", "hour": 0-23, "failed_logins": int}
        reasons = []
        hour = event.get("hour", 12)
        fails = event.get("failed_logins", 0)

        if hour < 6 or hour > 22:
            reasons.append("off-hours login attempt")
        if fails >= 5:
            reasons.append(f"excessive failed logins ({fails})")

        if reasons:
            flags.append({"event": event, "reasons": reasons})
    return flags

# Test Cases
def test_exp37():
    stream = [
        {"user": "alice", "hour": 10, "failed_logins": 0},
        {"user": "bob", "hour": 3, "failed_logins": 1},      # off-hours
        {"user": "charlie", "hour": 14, "failed_logins": 7}, # excessive fails
    ]
    flags = monitor_login_stream(stream)
    assert len(flags) == 2
    assert "off-hours login attempt" in flags[0]["reasons"]
    assert "excessive failed logins (7)" in flags[1]["reasons"]
    print("Experiment 37: All test cases passed.")

if __name__ == "__main__":
    events = [{"user": "hacker", "hour": 2, "failed_logins": 10}]
    print("Flags:", monitor_login_stream(events))
    test_exp37()
