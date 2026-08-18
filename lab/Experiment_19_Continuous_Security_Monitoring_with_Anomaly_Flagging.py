import random

random.seed(42)


def generate_event_stream(n=20):
    stream = []
    for _ in range(n):
        stream.append({
            "hour": random.choice([9, 10, 11, 14, 15, 16]),  # normal business hours
            "failed_logins": random.choice([0, 0, 0, 1]),
        })
    # inject 2 known anomalies
    stream.append({"hour": 3, "failed_logins": 0})
    stream.append({"hour": 10, "failed_logins": 9})
    return stream


def monitor_stream(stream):
    flags = []
    for event in stream:
        reasons = []
        if event["hour"] < 6 or event["hour"] > 22:
            reasons.append("off-hours activity")
        if event["failed_logins"] >= 5:
            reasons.append("excessive failed logins")
        if reasons:
            flags.append({"event": event, "reasons": reasons})
    return flags


event_stream = generate_event_stream()
flags = monitor_stream(event_stream)

print(f"Stream length: {len(event_stream)} | Flags raised: {len(flags)}")
for f in flags:
    print(f)


# Test Cases
def test_experiment19():
    assert len(flags) == 2, "Exactly the 2 injected anomalies should be flagged"
    assert any("off-hours activity" in f["reasons"] for f in flags)
    assert any("excessive failed logins" in f["reasons"] for f in flags)
    print("Experiment 19: All test cases passed.")


test_experiment19()
